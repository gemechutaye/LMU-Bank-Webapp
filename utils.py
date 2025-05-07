import re
import bleach
from datetime import datetime

def sanitize_input(text):
    """
    Sanitize user input to prevent XSS attacks
    
    Args:
        text: User input text to sanitize
        
    Returns:
        str: Sanitized text safe for rendering
    """
    if text is None:
        return ""
    
    # Strip any HTML tags and attributes that could be malicious
    # Only allow a very restrictive set of tags and attributes
    allowed_tags = ['b', 'i', 'em', 'strong']
    allowed_attrs = {}
    
    # First use bleach to sanitize HTML
    sanitized = bleach.clean(
        text,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
    
    return sanitized

def validate_password_strength(password):
    """
    Validate password strength
    
    Args:
        password: Password to validate
        
    Returns:
        tuple: (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    # Consider adding special character requirement
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    #     return False, "Password must contain at least one special character"
    
    return True, "Password meets strength requirements"

def format_datetime(dt):
    """
    Format datetime for user-friendly display
    
    Args:
        dt: Datetime to format
        
    Returns:
        str: Formatted datetime string in user-friendly format
    """
    if not dt:
        return "N/A"
    
    # Format: "May 7, 2025 at 05:44 PM"
    return dt.strftime("%B %d, %Y at %I:%M %p")

def is_valid_username(username):
    """
    Validate username format
    
    Args:
        username: Username to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Check length
    if len(username) < 3 or len(username) > 64:
        return False
    
    # Check allowed characters (letters, numbers, underscore, hyphen)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    
    # Check if starts with letter or number
    if not re.match(r'^[a-zA-Z0-9]', username):
        return False
    
    return True

def is_valid_email(email):
    """
    Validate email format
    
    Args:
        email: Email to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))
