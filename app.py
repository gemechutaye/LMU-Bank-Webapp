import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect

# Set up logging for easier debugging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# Create the Flask app
app = Flask(__name__)

# SECURITY: Set the secret key from environment variable
# This key is used for signing session cookies and CSRF tokens
# In production, this should be a long, random, and kept secret
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-replace-in-production")  # SECURITY: This default is only for development

# SECURITY: CSRF protection
# This initializes Flask-WTF's CSRF protection which defends against Cross-Site Request Forgery attacks
# It works by requiring a unique token with each POST/PUT/DELETE request that an attacker cannot forge
csrf = CSRFProtect(app)

# Fix for proper URL generation behind proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database connection
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cryptoapp.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SECURITY: Cookie and session security configurations
# These settings protect against various session-based attacks

# SECURITY: In development, allow cookies over HTTP. In production, this MUST be True
app.config["SESSION_COOKIE_SECURE"] = False  # SECURITY: Set to True in production to only send cookies over HTTPS

# SECURITY: HttpOnly flag prevents JavaScript from accessing cookies
# This protects against XSS attacks attempting to steal session cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True

# SECURITY: SameSite cookie attribute helps prevent CSRF attacks
# 'Lax' allows cookies to be sent with top-level navigations and GET requests from other sites
# This provides a balance between security and usability
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# SECURITY: Limit session lifetime to reduce risk if a session cookie is compromised
# 1 hour is a reasonable balance between security and user convenience
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # Session lifetime in seconds (1 hour)

# SECURITY: Content Security Policy (CSP) to prevent XSS attacks
# CSP is a powerful defense-in-depth mechanism against XSS
# It restricts the sources from which various resource types can be loaded
csp = {
    # SECURITY: By default, only allow resources from same origin
    'default-src': "'self'",
    
    # SECURITY: Only allow scripts from our server and trusted CDN
    # This prevents attackers from injecting malicious scripts
    'script-src': "'self' https://cdn.jsdelivr.net",
    
    # SECURITY: Only allow styles from our server and trusted CDNs
    'style-src': "'self' https://cdn.replit.com https://cdn.jsdelivr.net",
    
    # SECURITY: Only allow fonts from our server and trusted CDN
    'font-src': "'self' https://cdn.jsdelivr.net",
    
    # SECURITY: Allow images from our server and data URIs (for dynamically generated images)
    'img-src': "'self' data:",
    
    # SECURITY: Only allow AJAX/WebSocket/fetch to our own server
    'connect-src': "'self'"
}

@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    # SECURITY: Add Content Security Policy header to prevent XSS
    # This transforms our CSP dictionary into the proper header format
    csp_string = '; '.join([f"{k} {v}" for k, v in csp.items()])
    response.headers['Content-Security-Policy'] = csp_string
    
    # SECURITY: Add other security headers
    # X-Content-Type-Options prevents MIME type sniffing
    # This prevents browsers from interpreting files as a different MIME type
    # (e.g., treating a text file as JavaScript)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # SECURITY: X-Frame-Options prevents clickjacking attacks
    # SAMEORIGIN only allows our own site to frame this page
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # SECURITY: X-XSS-Protection enables browser's built-in XSS filters
    # This is a legacy header but still useful for older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Initialize the app with the SQLAlchemy extension
db.init_app(app)

with app.app_context():
    # Import models here to avoid circular imports
    import models  # noqa: F401
    
    # Create all database tables
    db.create_all()

    # Import routes after DB initialization to avoid circular imports
    import routes  # noqa: F401
