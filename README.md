# LMU Bank - Secure Digital Asset Trading Platform

LMU Bank is a secure web application that demonstrates comprehensive security features for handling digital asset transfers. This application implements robust security mechanisms to protect against common web vulnerabilities such as XSS, CSRF, SQL Injection, and user enumeration attacks.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Security Features Explained](#security-features-explained)
  - [XSS Prevention](#xss-prevention)
  - [CSRF Protection](#csrf-protection)
  - [SQL Injection Prevention](#sql-injection-prevention)
  - [User Enumeration Defense](#user-enumeration-defense)
  - [Authentication Security](#authentication-security)
  - [Secure Session Management](#secure-session-management)
  - [Secure Transfer Implementation](#secure-transfer-implementation)
  - [Content Security Policy](#content-security-policy)
- [Development Notes](#development-notes)

## Features

- **User Authentication**
  - Secure registration and login system
  - Password hashing with PBKDF2 (Werkzeug's implementation)
  - JWT-based authentication using secure cookies
  - Protection against user enumeration attacks
  - Consistent timing to prevent timing attacks

- **Cryptocurrency Management**
  - View your portfolio of digital assets with real-time balances
  - Transfer cryptocurrencies to other users securely
  - Track transaction history with comprehensive audit trail
  - Animated UI elements for a more engaging experience

- **Security Implementations**
  - Cross-Site Scripting (XSS) Prevention through multiple layers
  - Cross-Site Request Forgery (CSRF) Protection using Flask-WTF
  - SQL Injection Prevention using SQLAlchemy ORM
  - Input Validation and Sanitization with Bleach and WTForms
  - Content Security Policy headers
  - Secure HTTP Headers (X-Content-Type-Options, X-Frame-Options, etc.)
  - Transaction atomicity to prevent partial transfers

- **UI Features**
  - Responsive design that works on mobile and desktop
  - Animated cryptocurrency transfers and balance updates
  - Color-coded transaction history for easy identification
  - Clean, modern interface with intuitive navigation

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/gemechutaye/LMU-Bank-Webapp.git
   cd LMU-Bank-Webapp
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set environment variables (optional, defaults are provided for development):
   ```
   export SESSION_SECRET=your_secure_random_key
   export DATABASE_URL=sqlite:///cryptoapp.db  # Default is SQLite
   export FLASK_ENV=development  # Use 'production' in production
   ```

5. Run the application:
   ```
   python main.py
   ```

6. Access the application at `http://localhost:5000`

## Security Features Explained

### XSS Prevention

Cross-Site Scripting (XSS) attacks are prevented using multiple layers of defense:

1. **Input Sanitization**: All user inputs are sanitized using the `bleach` library before being stored or displayed:
   ```python
   # Sanitize inputs to prevent XSS attacks
   username = bleach.clean(form.username.data)
   email = bleach.clean(form.email.data)
   ```

2. **Content Security Policy (CSP)**: Strict CSP headers restrict the sources of executable scripts:
   ```python
   # Content Security Policy to prevent XSS
   csp = {
       'default-src': "'self'",
       'script-src': "'self' https://cdn.jsdelivr.net",
       # Additional directives...
   }
   ```

3. **Template Auto-Escaping**: All dynamic content in templates is automatically escaped by Jinja2, preventing script injection:
   ```html
   <!-- Safe display of user-provided content -->
   <span>{{ user.username }}</span>  <!-- Automatically escaped -->
   ```

4. **HTTPOnly Cookies**: Authentication tokens are stored in HTTPOnly cookies to prevent JavaScript access:
   ```python
   app.config["SESSION_COOKIE_HTTPONLY"] = True
   ```

### CSRF Protection

Cross-Site Request Forgery (CSRF) attacks are prevented using Flask-WTF's CSRF protection:

1. **CSRF Token Generation**: Every form includes a unique CSRF token:
   ```python
   # Initialize CSRF protection
   csrf = CSRFProtect(app)
   ```

2. **Token Validation**: All POST/PUT/DELETE requests require a valid CSRF token:
   ```html
   <!-- In forms -->
   <form method="post">
       {{ form.csrf_token }}
       <!-- Form fields -->
   </form>
   ```

3. **SameSite Cookie Attribute**: Cookies are set with SameSite=Lax to provide additional CSRF protection:
   ```python
   app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
   ```

### SQL Injection Prevention

SQL Injection attacks are prevented by using SQLAlchemy's ORM:

1. **Parameterized Queries**: All database queries use parameterized statements:
   ```python
   # Safe query using SQLAlchemy ORM
   user = User.query.filter_by(username=username).first()
   ```

2. **Input Validation**: Form inputs are validated before processing:
   ```python
   # Validate form data
   if form.validate_on_submit():
       # Process data
   ```

3. **Type Checking**: Data types are enforced through SQLAlchemy models:
   ```python
   # Model definition with type constraints
   class User(UserMixin, db.Model):
       id = db.Column(db.Integer, primary_key=True)
       username = db.Column(db.String(64), unique=True, nullable=False)
   ```

### User Enumeration Defense

Protection against user enumeration attacks:

1. **Consistent Error Messages**: Login and registration use generic error messages:
   ```python
   # Generic error message that doesn't reveal if username exists
   return False, "Registration failed. Please check your information and try again."
   ```

2. **Consistent Timing**: Time delays are added to prevent timing attacks:
   ```python
   # Add a time delay to prevent user enumeration through timing attacks
   time.sleep(0.5)
   ```

3. **Single Identifier Field**: Login form uses a single field for username/email to prevent enumeration:
   ```python
   # Using 'identifier' instead of username/email to prevent user enumeration
   identifier = StringField('Username or Email', validators=[...])
   ```

### Authentication Security

Secure authentication implementation:

1. **Password Hashing**: Passwords are hashed using PBKDF2 with salt:
   ```python
   # Hash password securely
   password_hash = generate_password_hash(password)
   ```

2. **JWT Tokens**: Authentication uses JWT tokens with expiration:
   ```python
   # Generate JWT with appropriate claims
   payload = {
       'sub': str(user_id),
       'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_DURATION),
       'jti': str(uuid.uuid4())  # Unique token ID
   }
   ```

3. **Password Complexity**: Password requirements are enforced:
   ```python
   # Validate password complexity
   if not (re.search(r'[A-Z]', pwd) and re.search(r'[a-z]', pwd) and re.search(r'[0-9]', pwd)):
       raise ValidationError('Password must contain uppercase, lowercase, and numbers')
   ```

### Secure Session Management

Secure session handling:

1. **Secure Cookie Settings**:
   ```python
   app.config["SESSION_COOKIE_SECURE"] = True  # In production
   app.config["SESSION_COOKIE_HTTPONLY"] = True
   app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
   ```

2. **Session Expiration**:
   ```python
   app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour
   ```

3. **Token Verification**: JWT tokens are verified on every request:
   ```python
   # Decode and validate JWT token
   payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
   ```

### Secure Transfer Implementation

The cryptocurrency transfer functionality includes multiple security measures:

1. **Input Validation**: All transfer parameters are validated:
   ```python
   # Validate amount is positive
   if amount <= 0:
       raise ValidationError('Amount must be greater than zero')
   ```

2. **Balance Verification**: Ensures users can only transfer what they own:
   ```python
   # Check if user has enough balance
   if not sender_balance or sender_balance.amount < amount:
       flash('Insufficient balance for this transfer.', 'danger')
   ```

3. **Transaction Atomicity**: Database transactions ensure all-or-nothing operations:
   ```python
   try:
       # Perform transfer operations
       db.session.commit()
   except Exception:
       db.session.rollback()
   ```

4. **Audit Trail**: All transfers are logged for accountability:
   ```python
   # Create transaction record
   transaction = Transaction(
       sender_id=user_id,
       receiver_id=recipient.id,
       crypto_type=crypto_type,
       amount=amount
   )
   ```

### Content Security Policy

Comprehensive Content Security Policy implementation:

```python
csp = {
    'default-src': "'self'",
    'script-src': "'self' https://cdn.jsdelivr.net",
    'style-src': "'self' https://cdn.replit.com https://cdn.jsdelivr.net",
    'font-src': "'self' https://cdn.jsdelivr.net",
    'img-src': "'self' data:",
    'connect-src': "'self'"
}
```

## About the Author

This project was developed by **Gemechu Taye** as part of the Secure Software Development course at Loyola Marymount University. The project demonstrates practical implementation of web security concepts and best practices in a real-world application.

## Project Background

LMU Bank was created to showcase how to build secure web applications that protect against common vulnerabilities while providing an engaging user experience. The application uses cryptocurrency as a fun alternative to traditional banking, with animated UI elements and color-coded transaction history.

This project implements the security concepts learned in the course, including:
- Protecting against XSS, CSRF, and SQL Injection attacks
- Implementing secure authentication and session management
- Preventing user enumeration and timing attacks
- Ensuring secure data handling and transfer operations

## Development Notes

This application was developed as part of a Secure Software Development course to demonstrate secure coding practices. While it implements many security features, in a production environment you would also want to consider:

1. Using HTTPS exclusively
2. Implementing rate limiting for login attempts
3. Adding multi-factor authentication
4. Regular security audits and penetration testing
5. Monitoring for suspicious activities

The code is extensively commented to explain security considerations and implementation details.
