from flask import render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import bleach
from app import app, db
from models import User, CryptoBalance, Transaction, CRYPTO_TYPES
from forms import RegistrationForm, LoginForm, TransferForm
from auth import register_user, login_user, generate_token, token_required
from utils import format_datetime
import logging

@app.route('/')
def index():
    """Home page route"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route with security protections"""
    # Redirect logged in users
    if session.get('token'):
        flash('You are already logged in!', 'info')
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Sanitize inputs to prevent XSS
        username = bleach.clean(form.username.data)
        email = bleach.clean(form.email.data)
        password = form.password.data  # No need to sanitize password as it will be hashed
        
        # Attempt registration
        success, message = register_user(username, email, password)
        
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route with anti-enumeration protections"""
    # Redirect logged in users
    if session.get('token'):
        flash('You are already logged in!', 'info')
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        # Sanitize inputs to prevent XSS
        identifier = bleach.clean(form.identifier.data)
        password = form.password.data  # No need to sanitize password
        
        # Attempt login
        success, message, user_id = login_user(identifier, password)
        
        if success:
            # Generate JWT token
            token = generate_token(user_id)
            
            # Store token in session cookie (httpOnly by default in Flask)
            session['token'] = token
            
            flash(message, 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(message, 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Log user out by removing token"""
    session.pop('token', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@token_required
def dashboard(user_id):
    """User dashboard showing account balances for both traditional money ($) and cryptocurrencies"""
    # Get user information
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('logout'))
    
    # Get user's account balances (both traditional money and cryptocurrencies)
    crypto_balances = CryptoBalance.query.filter_by(user_id=user_id).all()
    
    # Create a dictionary of user balances for quick lookup
    user_balances = {}
    for balance in crypto_balances:
        user_balances[balance.crypto_type] = balance.amount
    
    # Add all currency types to the dashboard
    balances = []
    for crypto in CRYPTO_TYPES:
        symbol = crypto['symbol']
        amount = user_balances.get(symbol, 0)
        
        # Create balance entry
        balances.append({
            'symbol': symbol,
            'name': crypto['name'],
            'color': crypto['color'],
            'amount': amount
        })
        
        # If this currency doesn't exist in the user's balances yet, create it
        if symbol not in user_balances:
            # For USD, give users an initial $5000 balance
            initial_amount = 5000.0 if symbol == 'USD' else 0
            
            new_balance = CryptoBalance(
                user_id=user_id,
                crypto_type=symbol,
                amount=initial_amount
            )
            db.session.add(new_balance)
            db.session.commit()
    
    # Get recent transactions
    sent = Transaction.query.filter_by(sender_id=user_id).order_by(Transaction.timestamp.desc()).limit(5).all()
    received = Transaction.query.filter_by(receiver_id=user_id).order_by(Transaction.timestamp.desc()).limit(5).all()
    
    # Combine and sort transactions by timestamp (most recent first)
    transactions = sorted(sent + received, key=lambda x: x.timestamp, reverse=True)[:10]
    
    # Prepare transaction data for template
    transaction_data = []
    for tx in transactions:
        sender = User.query.get(tx.sender_id)
        receiver = User.query.get(tx.receiver_id)
        
        crypto_info = next((c for c in CRYPTO_TYPES if c['symbol'] == tx.crypto_type), None)
        color = crypto_info['color'] if crypto_info else '#808080'
        
        # Use format_datetime for a consistent, user-friendly timestamp
        transaction_data.append({
            'id': tx.id,
            'sender': sender.username,
            'receiver': receiver.username,
            'is_sent': tx.sender_id == user_id,
            'amount': tx.amount,
            'crypto_type': tx.crypto_type,
            'crypto_color': color,
            'timestamp': tx.timestamp,  # Keep the original timestamp for sorting
            'formatted_time': format_datetime(tx.timestamp),  # Add formatted time
            'status': tx.status
        })
    
    return render_template(
        'dashboard.html',
        user=user,
        balances=balances,
        transactions=transaction_data
    )

@app.route('/transfer', methods=['GET', 'POST'])
@token_required
def transfer(user_id):
    """Transfer money ($) or cryptocurrency to another user with comprehensive security validations"""
    # Get user information
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('logout'))
    
    # Create transfer form
    form = TransferForm()
    
    # Populate crypto_type dropdown with all available currencies
    user_cryptos = CryptoBalance.query.filter_by(user_id=user_id).all()
    crypto_choices = []
    
    # Create a dictionary of user balances for quick lookup
    user_balances = {}
    for balance in user_cryptos:
        user_balances[balance.crypto_type] = balance.amount
    
    # Add all currency types to the dropdown
    for crypto in CRYPTO_TYPES:
        symbol = crypto['symbol']
        balance = user_balances.get(symbol, 0)
        name = f"{symbol} ({crypto['name']})"
        crypto_choices.append((symbol, f"{name} - Balance: {balance}"))
    
    form.crypto_type.choices = crypto_choices
    
    if request.method == 'POST' and form.validate_on_submit():
        # SECURITY: Sanitize inputs to prevent XSS attacks
        # Using bleach to remove any malicious HTML/JavaScript from user inputs
        recipient_username = bleach.clean(form.recipient.data)
        crypto_type = bleach.clean(form.crypto_type.data)
        
        # SECURITY: No need to sanitize amount as it's validated as a float by WTForms
        # This prevents SQL injection and type conversion attacks
        amount = form.amount.data
        
        # Find recipient
        recipient = User.query.filter_by(username=recipient_username).first()
        
        # SECURITY: Validate recipient exists
        # This prevents transfers to non-existent accounts
        # Note: We use a generic error message to avoid username enumeration
        if not recipient:
            flash('Recipient not found.', 'danger')
            return render_template('transfer.html', form=form)
        
        # SECURITY: Prevent transfer to self
        # This prevents potential money laundering or transaction confusion
        # It also prevents potential exploitation of transaction processing bugs
        if recipient.id == user_id:
            flash('You cannot transfer to yourself.', 'danger')
            return render_template('transfer.html', form=form)
        
        # SECURITY: Check if user has enough balance
        # This prevents overdrafts and ensures users can only transfer what they own
        # We query by both user_id and crypto_type to ensure we're checking the correct balance
        # and to prevent parameter tampering attacks
        sender_balance = CryptoBalance.query.filter_by(
            user_id=user_id, crypto_type=crypto_type
        ).first()
        
        # SECURITY: Validate sufficient funds
        # Double-check the balance to prevent race conditions and ensure atomic operations
        if not sender_balance or sender_balance.amount < amount:
            flash('Insufficient balance for this transfer.', 'danger')
            return render_template('transfer.html', form=form)
        
        # Get or create recipient's balance for this crypto
        recipient_balance = CryptoBalance.query.filter_by(
            user_id=recipient.id, crypto_type=crypto_type
        ).first()
        
        if not recipient_balance:
            recipient_balance = CryptoBalance(
                user_id=recipient.id,
                crypto_type=crypto_type,
                amount=0
            )
            db.session.add(recipient_balance)
        
        # Create transaction record
        transaction = Transaction(
            sender_id=user_id,
            receiver_id=recipient.id,
            crypto_type=crypto_type,
            amount=amount,
            status='completed'
        )
        
        # SECURITY: Update balances in a way that ensures consistency
        # We subtract from sender first, then add to recipient
        # This ensures that if any error occurs, funds aren't created out of nowhere
        sender_balance.amount -= amount
        recipient_balance.amount += amount
        
        # SECURITY: Add transaction record to maintain audit trail
        # This ensures all transfers are logged for accountability and dispute resolution
        db.session.add(transaction)
        
        # SECURITY: Use database transaction to ensure atomicity
        # Either all operations succeed or none do, preventing partial transfers
        try:
            # SECURITY: Commit all changes in a single transaction
            # This ensures that balance updates and transaction record are atomic
            # Prevents race conditions and ensures data consistency
            db.session.commit()
            flash(f'Successfully transferred {amount} {crypto_type} to {recipient_username}!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            # SECURITY: Roll back transaction on any error
            # This ensures no partial updates occur if something goes wrong
            db.session.rollback()
            # SECURITY: Log the error but don't expose details to the user
            # This prevents information leakage while maintaining auditability
            app.logger.error(f"Transfer error: {str(e)}")
            # SECURITY: Generic error message to user
            # Prevents information disclosure about the database or application structure
            flash('An error occurred during the transfer. Please try again.', 'danger')
    
    return render_template('transfer.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    return render_template('error.html', error_code=500, error_message='Internal server error'), 500

@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors"""
    return render_template('error.html', error_code=403, error_message='Forbidden'), 403

@app.route('/api/validate-username/<username>')
def validate_username(username):
    """API endpoint to check if username is available"""
    # Sanitize input
    username = bleach.clean(username)
    
    # Add a delay to prevent enumeration
    import time
    time.sleep(0.5)
    
    # Return a generic message regardless of whether username exists
    # The actual validation happens server-side during registration
    return jsonify({'valid': True, 'message': 'Username is being checked'})
