from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    """User model for authentication and profile data"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Store user's cryptocurrency balances
    cryptos = db.relationship('CryptoBalance', backref='owner', lazy='dynamic')
    
    # User's transaction history
    sent_transactions = db.relationship('Transaction', 
                                      foreign_keys='Transaction.sender_id',
                                      backref='sender', 
                                      lazy='dynamic')
    received_transactions = db.relationship('Transaction', 
                                          foreign_keys='Transaction.receiver_id',
                                          backref='receiver', 
                                          lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'


class CryptoBalance(db.Model):
    """Model to store user's cryptocurrency balances"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crypto_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'crypto_type', name='unique_user_crypto'),
    )
    
    def __repr__(self):
        return f'<CryptoBalance {self.crypto_type}: {self.amount}>'


class Transaction(db.Model):
    """Model to record cryptocurrency transfers between users"""
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crypto_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='completed')  # completed, pending, failed
    
    def __repr__(self):
        return f'<Transaction {self.sender_id} -> {self.receiver_id}: {self.amount} {self.crypto_type}>'


# Define available currency types for the application (both traditional money and crypto)
CRYPTO_TYPES = [
    {'symbol': 'USD', 'name': 'US Dollar', 'color': '#85bb65'},
    {'symbol': 'BTC', 'name': 'Bitcoin', 'color': '#f7931a'},
    {'symbol': 'ETH', 'name': 'Ethereum', 'color': '#627eea'},
    {'symbol': 'XRP', 'name': 'Ripple', 'color': '#0f0e0e'},
    {'symbol': 'LTC', 'name': 'Litecoin', 'color': '#d3d3d3'},
    {'symbol': 'DOGE', 'name': 'Dogecoin', 'color': '#c3a634'}
]
