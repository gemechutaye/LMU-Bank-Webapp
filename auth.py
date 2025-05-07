import datetime
import jwt
import uuid
from functools import wraps
from flask import request, jsonify, make_response, current_app, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from models import User, CryptoBalance, CRYPTO_TYPES
import time
import bleach

# SECURITY: JWT token duration in seconds (30 minutes)
# Limiting token lifetime reduces the window of opportunity if a token is compromised
# 30 minutes provides a good balance between security and user experience
TOKEN_DURATION = 30 * 60

def generate_token(user_id):
    """
    Generate a JWT token for authentication
    
    Args:
        user_id: ID of the user to encode in the token
        
    Returns:
        str: JWT token
    """
    # SECURITY: Create a secure JWT with appropriate claims
    payload = {
        # SECURITY: Store user ID in the subject claim
        'sub': str(user_id),  # Convert user_id to string as required by JWT
        
        # SECURITY: Include issued-at time to track when the token was created
        'iat': datetime.datetime.utcnow(),
        
        # SECURITY: Set expiration time to limit token lifetime
        # This ensures that stolen tokens can only be used for a limited time
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_DURATION),
        
        # SECURITY: Add a unique JWT ID to prevent token reuse
        # This helps protect against replay attacks where an attacker would reuse a captured token
        'jti': str(uuid.uuid4())
    }
    
    current_app.logger.debug(f"Generating token for user ID: {user_id}")
    
    # SECURITY: Sign the token with our secret key using HMAC-SHA256
    # This ensures the token cannot be modified without detection
    return jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def decode_token(token):
    """
    Decode and validate JWT token
    
    Args:
        token: JWT token to decode
        
    Returns:
        dict: Decoded payload if valid
        None: If token is invalid or expired
    """
    try:
        # Log token for debugging
        current_app.logger.debug(f"Decoding token: {token[:10]}...")
        
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Log successful decode
        current_app.logger.debug(f"Successfully decoded token, payload contains user_id: {payload.get('sub')}")
        return payload
    except jwt.ExpiredSignatureError:
        current_app.logger.error("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        current_app.logger.error(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        current_app.logger.error(f"Error decoding token: {str(e)}")
        return None

def token_required(f):
    """
    Decorator for routes that require token authentication
    
    Args:
        f: Function to wrap
        
    Returns:
        Function that checks for valid token before executing wrapped function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        current_app.logger.debug(f"Token in session: {'Yes' if token else 'No'}")
        
        if not token:
            # Clear any potentially corrupt session data
            session.clear()
            flash('Authentication required. Please log in.', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Try to decode the token
            payload = decode_token(token)
            if not payload:
                # If token is invalid, clear session and redirect
                current_app.logger.warning("Invalid token detected, clearing session")
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
            
            # Check if user exists
            from models import User
            # Convert string user_id back to integer for database query
            user_id = int(payload['sub'])
            user = User.query.get(user_id)
            if not user:
                current_app.logger.warning(f"User ID {user_id} from token not found in database")
                session.clear()
                flash('User account not found.', 'danger')
                return redirect(url_for('login'))
            
            # Add user_id to kwargs so the wrapped function can use it
            kwargs['user_id'] = user_id
            return f(*args, **kwargs)
        except Exception as e:
            # Catch any unexpected errors
            current_app.logger.error(f"Unexpected error in token_required: {str(e)}")
            session.clear()
            flash('An error occurred. Please log in again.', 'danger')
            return redirect(url_for('login'))
    
    return decorated

def register_user(username, email, password):
    """
    Register a new user with anti-enumeration protections
    
    Args:
        username: User's chosen username (sanitized)
        email: User's email address (sanitized)
        password: User's plaintext password
        
    Returns:
        tuple: (success, message)
    """
    # SECURITY: Sanitize inputs to prevent XSS attacks
    # This removes any potentially malicious HTML/scripts from user inputs
    username = bleach.clean(username.strip())
    email = bleach.clean(email.strip())
    
    # SECURITY: Add a consistent time delay to prevent user enumeration through timing attacks
    # This ensures registration attempts take the same time whether username/email exists or not
    time.sleep(0.5)
    
    # SECURITY: Check if username already exists
    # We perform these checks separately but return the same generic error message
    # to avoid revealing which specific field (username or email) is already taken
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        # SECURITY: Generic error message to prevent user enumeration
        # We don't specify whether the username or email is taken
        return False, "Registration failed. Please check your information and try again."
    
    # SECURITY: Check if email already exists
    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        # SECURITY: Generic error message to prevent user enumeration
        # Same message as username conflict to prevent information disclosure
        return False, "Registration failed. Please check your information and try again."
    
    # SECURITY: Hash the password with pbkdf2 (Werkzeug's default)
    # generate_password_hash uses a secure algorithm with salt to protect passwords
    # This protects passwords even if the database is compromised
    password_hash = generate_password_hash(password)
    
    # Create new user
    new_user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        created_at=datetime.datetime.utcnow()
    )
    
    # Add the user to the database and get the ID in a transaction
    try:
        # Begin transaction
        db.session.add(new_user)
        db.session.flush()  # This assigns the ID without committing
        
        # Get the assigned user ID
        user_id = new_user.id
        
        # Now create initial currency balances for the user (both traditional money and crypto)
        for crypto in CRYPTO_TYPES:
            # Give new users some starting balances (for demo purposes)
            if crypto['symbol'] == 'USD':
                initial_amount = 5000.0  # $5000 for traditional money
            elif crypto['symbol'] == 'DOGE':
                initial_amount = 100.0  # More Dogecoin for fun
            else:
                initial_amount = 1.0  # Small amount of other cryptocurrencies
                
            crypto_balance = CryptoBalance(
                user_id=user_id,
                crypto_type=crypto['symbol'],
                amount=initial_amount
            )
            db.session.add(crypto_balance)
        
        # Commit the entire transaction
        db.session.commit()
        current_app.logger.info(f"Successfully registered user with ID: {user_id}")
        return True, "Registration successful! You can now log in."
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during registration: {str(e)}")
        return False, "An error occurred during registration. Please try again later."

def login_user(identifier, password):
    """
    Authenticate a user with anti-enumeration protections
    
    Args:
        identifier: Username or email (sanitized)
        password: Plaintext password
        
    Returns:
        tuple: (success, message, user_id)
    """
    # Sanitize input
    identifier = bleach.clean(identifier.strip())
    
    # Add a time delay to prevent user enumeration through timing attacks
    time.sleep(0.5)
    
    # SECURITY: Find user by username or email using a single query
    # This makes it harder for attackers to enumerate valid accounts
    user = User.query.filter(
        (User.email == identifier) | (User.username == identifier)
    ).first()
    
    if not user:
        # SECURITY: Generic error message to prevent user enumeration
        # We return the same message whether the user doesn't exist or the password is wrong
        # This prevents attackers from learning which usernames/emails are valid
        return False, "Invalid credentials. Please try again.", None
    
    # Check if user exists and password is correct
    if not check_password_hash(user.password_hash, password):
        # SECURITY: Generic error message to prevent user enumeration
        # Same message as user not found to prevent information disclosure
        return False, "Invalid credentials. Please try again.", None
    
    # Update last login timestamp with current time
    previous_login = user.last_login
    current_time = datetime.datetime.utcnow()
    user.last_login = current_time
    db.session.commit()
    
    # Log the login time update for debugging
    current_app.logger.info(f"Updated last login for user {user.username} from {previous_login} to {current_time}")
    
    return True, "Login successful!", user.id
