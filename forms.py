from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError
import re
from models import CRYPTO_TYPES, User

class LoginForm(FlaskForm):
    """Form for user login with security measures"""
    # Using 'identifier' instead of username/email to prevent user enumeration
    identifier = StringField('Username or Email', validators=[
        DataRequired(),
        Length(min=3, max=120, message="Identifier must be between 3 and 120 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    submit = SubmitField('Login')
    
    # Client-side validation is minimal to prevent user enumeration
    # More complex validation is done server-side


class RegistrationForm(FlaskForm):
    """Form for user registration with strong validation"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64, message="Username must be between 3 and 64 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address"),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Register')
    
    # Custom validators
    def validate_username(self, username):
        """Validate username format and availability"""
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', username.data):
            raise ValidationError('Username can only contain letters, numbers, underscores, and hyphens')
        
        # Check if username is taken - will be done server-side to prevent enumeration

    def validate_password(self, password):
        """Ensure password meets complexity requirements"""
        pwd = password.data
        
        # Check for at least one uppercase, one lowercase, one number
        if not (re.search(r'[A-Z]', pwd) and re.search(r'[a-z]', pwd) and re.search(r'[0-9]', pwd)):
            raise ValidationError('Password must contain at least one uppercase letter, one lowercase letter, and one number')


class TransferForm(FlaskForm):
    """Form for transferring money ($) or cryptocurrency to other users"""
    recipient = StringField('Recipient Username', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    
    # Dynamic choices will be set in routes.py based on user's available currencies
    crypto_type = SelectField('Currency Type', choices=[], validators=[DataRequired()])
    
    amount = FloatField('Amount', validators=[
        DataRequired(message="Please enter a valid number")
    ])
    
    submit = SubmitField('Transfer')
    
    def validate_amount(self, amount):
        """Ensure amount is positive"""
        if amount.data <= 0:
            raise ValidationError('Amount must be greater than zero')
