import os
import hashlib
import secrets
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import uuid
import time
import re
from flask import Flask, request, Response, send_file, jsonify, redirect, render_template_string, send_from_directory
from twilio.twiml.voice_response import VoiceResponse
from openai import OpenAI
import threading
from pathlib import Path
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('voxcord.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Static file configuration
app.static_folder = 'static'
app.static_url_path = '/static'

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# JWT Secret
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(64))

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', '587')),
    'email': os.getenv('EMAIL_ADDRESS'),
    'password': os.getenv('EMAIL_PASSWORD'),
    'from_name': 'Voxcord Team'
}

# Plan configurations with limits
PLAN_LIMITS = {
    'free': {
        'max_assistants': 1,
        'max_calls_per_month': 100,
        'max_call_duration': 300,
        'features': ['basic_ai', 'email_support'],
        'price': 0,
        'trial_days': None
    },
    'professional': {
        'max_assistants': 5,
        'max_calls_per_month': -1,
        'max_call_duration': -1,
        'features': ['custom_training', 'crm_integration', 'analytics', 'priority_support'],
        'price': 99,
        'trial_days': 14
    },
    'enterprise': {
        'max_assistants': -1,
        'max_calls_per_month': -1,
        'max_call_duration': -1,
        'features': ['voice_cloning', 'api_access', 'custom_integration', 'dedicated_support', 'white_label'],
        'price': 299,
        'trial_days': 14
    }
}

# In-memory storage (use Redis/PostgreSQL in production)
users_db = {}
sessions_db = {}
failed_attempts = {}
user_phone_numbers = {}
user_usage = {}
call_sessions = {}
pending_verifications = {}

# Create directories
AUDIO_DIR = Path("audio_files")
AUDIO_DIR.mkdir(exist_ok=True)

STATIC_DIR = Path("static")
STATIC_DIR.mkdir(exist_ok=True)

TEMPLATES_DIR = Path("templates")
TEMPLATES_DIR.mkdir(exist_ok=True)

class SecurityManager:
    """Enhanced security management"""
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def hash_password(password):
        """Hash password with salt"""
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    @staticmethod
    def verify_password(password, stored_hash):
        """Verify password against stored hash"""
        try:
            salt, hash_value = stored_hash.split(':')
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return password_hash.hex() == hash_value
        except:
            return False

class EmailService:
    """Email service for notifications and verification"""
    
    @staticmethod
    def send_email(to_email, subject, html_body, text_body=None):
        """Send email using SMTP"""
        if not EMAIL_CONFIG['email'] or not EMAIL_CONFIG['password']:
            logger.warning("Email service not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{EMAIL_CONFIG['from_name']} <{EMAIL_CONFIG['email']}>"
            msg['To'] = to_email
            
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['email'], EMAIL_CONFIG['password'])
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    @staticmethod
    def send_verification_email(user_email, user_name, verification_token):
        """Send email verification"""
        verification_url = f"{request.host_url}verify-email?token={verification_token}"
        
        subject = "Welcome to Voxcord - Verify Your Email"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Email - Voxcord</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f8fafc; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
                .header {{ background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); color: white; padding: 2rem; text-align: center; }}
                .content {{ padding: 2rem; }}
                .button {{ display: inline-block; background: #1e40af; color: white; padding: 1rem 2rem; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 1rem 0; }}
                .footer {{ background: #f1f5f9; padding: 1rem; text-align: center; color: #64748b; font-size: 0.875rem; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📡 Welcome to Voxcord!</h1>
                    <p>Enterprise AI Voice Solutions</p>
                </div>
                <div class="content">
                    <h2>Hi {user_name},</h2>
                    <p>Thanks for signing up for Voxcord! To get started with your AI voice assistant, please verify your email address by clicking the button below:</p>
                    <div style="text-align: center; margin: 2rem 0;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </div>
                    <p>If you can't click the button, copy and paste this link into your browser:</p>
                    <p style="background: #f1f5f9; padding: 1rem; border-radius: 4px; word-break: break-all; font-family: monospace;">{verification_url}</p>
                    <p><strong>This link will expire in 24 hours for security reasons.</strong></p>
                    <p>If you didn't create a Voxcord account, you can safely ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 Voxcord. All rights reserved.</p>
                    <p>Enterprise AI Voice Solutions</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Welcome to Voxcord!
        
        Hi {user_name},
        
        Thanks for signing up for Voxcord! To verify your email address, please visit:
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, you can ignore this email.
        
        Best regards,
        The Voxcord Team
        """
        
        return EmailService.send_email(user_email, subject, html_body, text_body)

class CallSession:
    def __init__(self, call_sid):
        self.call_sid = call_sid
        self.conversation_history = []
        self.created_at = time.time()

def get_call_session(call_sid):
    if call_sid not in call_sessions:
        call_sessions[call_sid] = CallSession(call_sid)
    return call_sessions[call_sid]

def create_session_token(user):
    """Create JWT session token"""
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'plan': user['plan'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_session_token(token):
    """Verify JWT session token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def is_rate_limited(ip):
    """Check if IP is rate limited"""
    if ip not in failed_attempts:
        return False
    
    attempts = failed_attempts[ip]
    now = datetime.utcnow()
    
    # Remove old attempts (older than 15 minutes)
    attempts['timestamps'] = [
        ts for ts in attempts['timestamps'] 
        if now - ts < timedelta(minutes=15)
    ]
    
    return len(attempts['timestamps']) >= 5

def record_failed_attempt(ip):
    """Record a failed login attempt"""
    if ip not in failed_attempts:
        failed_attempts[ip] = {'timestamps': []}
    failed_attempts[ip]['timestamps'].append(datetime.utcnow())

def clear_failed_attempts(ip):
    """Clear failed attempts for IP"""
    if ip in failed_attempts:
        del failed_attempts[ip]

# Routes
@app.route('/')
def index():
    return redirect('/landing')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with proper MIME types"""
    try:
        return send_from_directory('static', filename)
    except Exception as e:
        logger.error(f"Error serving static file {filename}: {e}")
        return "File not found", 404

@app.route('/landing')
def landing_page():
    try:
        return send_file('landing.html')
    except Exception as e:
        logger.error(f"Error serving landing page: {e}")
        return "Landing page not found", 404

@app.route('/signup')
def signup_page():
    try:
        return send_file('signup.html')
    except Exception as e:
        logger.error(f"Error serving signup page: {e}")
        return "Signup page not found", 404

@app.route('/login')
def login_page():
    try:
        return send_file('login.html')
    except Exception as e:
        logger.error(f"Error serving login page: {e}")
        return "Login page not found", 404

@app.route('/dashboard')
def dashboard():
    try:
        return send_file('dashboard.html')
    except Exception as e:
        logger.error(f"Error serving dashboard: {e}")
        return "Dashboard not found", 404

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Enhanced signup with proper email verification"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'email', 'password', 'company', 'industry', 'phone', 'plan']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        # Validate email format
        email = data['email'].lower().strip()
        if not SecurityManager.validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Check if email already exists
        if any(user['email'] == email for user in users_db.values()):
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Validate password strength
        password = data['password']
        is_valid, message = SecurityManager.validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'message': message}), 400
        
        # Validate plan
        plan = data.get('plan', 'free')
        if plan not in PLAN_LIMITS:
            return jsonify({'success': False, 'message': 'Invalid plan selected'}), 400
        
        # Generate user ID and hash password
        user_id = str(uuid.uuid4())
        password_hash = SecurityManager.hash_password(password)
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Calculate trial end date for paid plans
        trial_end = None
        if PLAN_LIMITS[plan]['trial_days'] and plan != 'free':
            trial_end = (datetime.utcnow() + timedelta(days=PLAN_LIMITS[plan]['trial_days'])).isoformat()
        
        # Create user account
        users_db[user_id] = {
            'id': user_id,
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'email': email,
            'passwordHash': password_hash,
            'company': data['company'],
            'industry': data['industry'],
            'phone': data['phone'],
            'plan': plan,
            'planLimits': PLAN_LIMITS[plan],
            'trialEnd': trial_end,
            'subscriptionStatus': 'trial' if trial_end else ('pending' if plan != 'free' else 'active'),
            'verified': False,  # Always require email verification
            'verificationToken': verification_token,
            'verificationExpiry': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'createdAt': datetime.utcnow().isoformat(),
            'lastLogin': None,
            'mfaEnabled': False,
            'securityLog': []
        }
        
        # Store verification token separately
        pending_verifications[verification_token] = {
            'user_id': user_id,
            'expires': datetime.utcnow() + timedelta(hours=24)
        }
        
        # Send verification email
        email_sent = EmailService.send_verification_email(
            email,
            data['firstName'],
            verification_token
        )
        
        if not email_sent:
            logger.warning(f"Failed to send verification email to {email}")
        
        logger.info(f"New user registration: {data['company']} ({email}) - {plan} plan")
        
        return jsonify({
            'success': True,
            'userId': user_id,
            'plan': plan,
            'message': 'Account created successfully! Please check your email to verify your account before signing in.',
            'emailSent': email_sent
        })
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """Enhanced login with proper security"""
    try:
        data = request.json
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Check rate limiting
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            return jsonify({
                'success': False, 
                'message': 'Too many failed attempts. Please try again in 15 minutes.'
            }), 429
        
        # Find user by email
        user = None
        for user_data in users_db.values():
            if user_data['email'] == email:
                user = user_data
                break
        
        if not user:
            record_failed_attempt(client_ip)
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Verify password
        if not SecurityManager.verify_password(password, user['passwordHash']):
            record_failed_attempt(client_ip)
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Check if account is verified
        if not user['verified']:
            return jsonify({
                'success': False, 
                'message': 'Please verify your email address before signing in. Check your inbox for the verification link.'
            }), 401
        
        # Create session token
        session_token = create_session_token(user)
        
        # Clear failed attempts
        clear_failed_attempts(client_ip)
        
        # Update last login
        user['lastLogin'] = datetime.utcnow().isoformat()
        
        # Generate phone number if not exists
        if user['id'] not in user_phone_numbers:
            user_phone_numbers[user['id']] = generate_phone_number()
        
        logger.info(f"Successful login: {email}")
        
        return jsonify({
            'success': True,
            'sessionToken': session_token,
            'user': {
                'id': user['id'],
                'firstName': user['firstName'],
                'lastName': user['lastName'],
                'email': user['email'],
                'company': user['company'],
                'plan': user['plan'],
                'phoneNumber': user_phone_numbers.get(user['id'])
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/verify-email')
def verify_email():
    """Email verification endpoint"""
    token = request.args.get('token')
    
    if not token:
        return render_template_string(ERROR_PAGE_TEMPLATE, 
            title="Invalid Verification Link",
            message="The verification link is invalid or missing."
        )
    
    # Check if token exists and is valid
    if token not in pending_verifications:
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="Invalid Verification Token",
            message="This verification link is invalid or has already been used."
        )
    
    verification_data = pending_verifications[token]
    
    # Check if token has expired
    if datetime.utcnow() > verification_data['expires']:
        del pending_verifications[token]
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="Verification Link Expired",
            message="This verification link has expired. Please request a new one."
        )
    
    user_id = verification_data['user_id']
    
    if user_id not in users_db:
        return render_template_string(ERROR_PAGE_TEMPLATE,
            title="User Not Found",
            message="The user account associated with this verification link was not found."
        )
    
    user = users_db[user_id]
    
    # Mark user as verified
    user['verified'] = True
    user['verificationToken'] = None
    user['subscriptionStatus'] = 'active' if user['plan'] == 'free' else 'trial'
    
    # Generate phone number
    if user_id not in user_phone_numbers:
        user_phone_numbers[user_id] = generate_phone_number()
    
    # Initialize usage tracking
    if user_id not in user_usage:
        user_usage[user_id] = {
            'calls_this_month': 0,
            'total_call_duration': 0,
            'month_year': datetime.utcnow().strftime('%Y-%m'),
            'call_log': []
        }
    
    # Clean up verification token
    del pending_verifications[token]
    
    # Create session token for auto-login
    session_token = create_session_token(user)
    
    logger.info(f"Email verified for user: {user['email']}")
    
    return render_template_string(SUCCESS_PAGE_TEMPLATE,
        user_name=user['firstName'],
        plan=user['plan'],
        phone_number=user_phone_numbers.get(user_id),
        session_token=session_token,
        user_data={
            'id': user['id'],
            'email': user['email'],
            'plan': user['plan']
        }
    )

def generate_phone_number():
    """Generate a phone number"""
    import random
    area_codes = ['212', '310', '312', '404', '415', '469', '305', '206', '617', '702']
    area_code = random.choice(area_codes)
    number = random.randint(1000000, 9999999)
    return f"+1{area_code}{number}"

# Template constants
ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }} - Voxcord</title>
    <link rel="stylesheet" href="/static/styles.css">
    <style>
        body { background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 500px; text-align: center; }
        .error-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #e74c3c; margin-bottom: 1rem; }
        .btn { background: #1e40af; color: white; padding: 1rem 2rem; border: none; border-radius: 8px; text-decoration: none; display: inline-block; margin-top: 1rem; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>{{ title }}</h1>
        <p>{{ message }}</p>
        <a href="/login" class="btn">Back to Login</a>
        <a href="/signup" class="btn" style="background: #6b7280;">Sign Up</a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Verified - Voxcord</title>
    <link rel="stylesheet" href="/static/styles.css">
    <style>
        body { background: linear-gradient(135deg, #1e40af 0%, #3730a3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 500px; text-align: center; }
        .success-icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #10b981; margin-bottom: 1rem; }
        .btn { background: #1e40af; color: white; padding: 1rem 2rem; border: none; border-radius: 8px; text-decoration: none; display: inline-block; margin-top: 1rem; font-weight: 600; }
        .info-box { background: #f0f9ff; padding: 1rem; border-radius: 8px; margin: 1rem 0; border-left: 4px solid #0ea5e9; }
    </style>
    <script>
        setTimeout(() => {
            localStorage.setItem('sessionToken', '{{ session_token }}');
            localStorage.setItem('user', JSON.stringify({{ user_data | tojson }}));
            window.location.href = '/dashboard';
        }, 3000);
    </script>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Email Verified!</h1>
        <p>Welcome to Voxcord, {{ user_name }}!</p>
        
        <div class="info-box">
            <p><strong>Plan:</strong> {{ plan.title() }}</p>
            <p><strong>Phone Number:</strong> {{ phone_number }}</p>
        </div>
        
        <p>Your account has been successfully verified and is now active.</p>
        <p style="margin-top: 2rem;">Redirecting to your dashboard in 3 seconds...</p>
        <a href="/dashboard" class="btn">Go to Dashboard Now</a>
    </div>
</body>
</html>
"""

@app.route('/health')
def health_check():
    """System health check"""
    plan_distribution = {}
    for user in users_db.values():
        plan = user.get('plan', 'free')
        plan_distribution[plan] = plan_distribution.get(plan, 0) + 1
    
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "openai_configured": bool(os.getenv('OPENAI_API_KEY')),
        "email_configured": bool(EMAIL_CONFIG['email']),
        "total_users": len(users_db),
        "verified_users": len([u for u in users_db.values() if u.get('verified')]),
        "active_calls": len(call_sessions),
        "plan_distribution": plan_distribution
    })

if __name__ == '__main__':
    # Validate environment variables
    required_vars = ['OPENAI_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        exit(1)
    
    # Check email configuration
    if not EMAIL_CONFIG['email']:
        logger.warning("Email service not configured - verification emails will not be sent")
    
    logger.info("Starting Voxcord backend server...")
    logger.info(f"Email service: {'Configured' if EMAIL_CONFIG['email'] else 'Not configured'}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)