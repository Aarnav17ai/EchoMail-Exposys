import os
import re
import json
import base64
import pandas as pd
import logging
import requests
import json
import datetime
import hashlib
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from functools import wraps

# OAuth and Google Authentication
from authlib.integrations.flask_client import OAuth

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Configure Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
app.config['HISTORY_FILE'] = 'csv_history.json'
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours in seconds

# Load configuration from environment variables
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

# Verify required environment variables are set
missing_vars = []
if not GOOGLE_CLIENT_ID:
    missing_vars.append("GOOGLE_OAUTH_CLIENT_ID")
if not GOOGLE_CLIENT_SECRET:
    missing_vars.append("GOOGLE_OAUTH_CLIENT_SECRET")
if missing_vars:
    logger.warning(f"Missing required environment variables: {', '.join(missing_vars)}")

logger.info(f"BASE_URL: {BASE_URL}")
logger.info(f"GOOGLE_CLIENT_ID: {'Set' if GOOGLE_CLIENT_ID else 'Not set'}")
logger.info(f"GOOGLE_CLIENT_SECRET: {'Set' if GOOGLE_CLIENT_SECRET else 'Not set'}")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    logger.warning("Google OAuth credentials not found in environment variables. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET")

# Initialize OAuth
oauth = OAuth(app)

# Configure OAuth with Google
try:
    # Ensure BASE_URL ends with a slash
    base_url = BASE_URL.rstrip('/')
    redirect_uri = f"{base_url}/login/google/authorized"
    
    logger.info(f"Configuring OAuth with redirect_uri: {redirect_uri}")
    
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        client_kwargs={
            'scope': 'openid email profile',
            'prompt': 'select_account',  # Force account selection
        },
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
        access_token_url='https://oauth2.googleapis.com/token',
        client_kwargs_oauth2={'token_endpoint_auth_method': 'client_secret_basic'},
        redirect_uri=redirect_uri
    )
    
    logger.info("OAuth configuration successful")
except Exception as e:
    logger.error(f"Error configuring OAuth: {str(e)}")
    raise

USERS_FILE = 'users.json'

# User management functions (JSON file-based)
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            try:
                # Load users as a list of dictionaries
                users_data = json.load(f)
                if isinstance(users_data, dict):
                    # If it's an old format (dict keyed by email), convert to list
                    return list(users_data.values())
                return users_data
            except json.JSONDecodeError:
                logger.error("Error decoding users.json, returning empty list")
                return []
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def find_user_by_email(email):
    """Find a user by email address"""
    users = load_users()
    for user in users:
        if user.get('email') == email:
            return user
    return None

def find_user_by_google_id(google_id):
    """Find a user by Google ID"""
    if not google_id:
        return None
        
    users = load_users()
    for user in users:
        if user.get('google_id') == google_id:
            return user
    return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'email' in session: # If already logged in, redirect
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email') # Changed from username to email
        password = request.form.get('password')
        if not email or not password:
            flash('Email and password required', 'error')
            return render_template('signup.html')
        if find_user_by_email(email): # Changed from find_user to find_user_by_email
            flash('Email already registered', 'error')
            return render_template('signup.html')
        users = load_users()
        new_user = {
            'email': email, 
            'password': hash_password(password), 
            'created_at': datetime.datetime.now().isoformat()
        }
        users.append(new_user)
        save_users(users)
        # Store minimal session data
        session.permanent = True  # This enables the 24h expiration
        session['email'] = email
        flash('Registration successful! Welcome to EchoMail!', 'success')
        return redirect(url_for('index'))  # Redirect to dashboard
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'email' in session: # If already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email') # Changed from username to email
        password = request.form.get('password')
        user = find_user_by_email(email) # Changed from find_user to find_user_by_email
        if not user or user['password'] != hash_password(password):
            flash('Invalid email or password', 'error')
            return render_template('login.html')
        # Store minimal session data
        session.permanent = True  # This enables the 24h expiration
        session['email'] = email
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('email', None) # Pop email from session
    return redirect(url_for('login'))

# Google OAuth routes
@app.route('/login/google')
def google_login():
    """Initiate Google OAuth login/signup"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.error("Google OAuth not configured. Missing client ID or secret.")
        flash('Google login is not properly configured. Please contact support.', 'error')
        return redirect(url_for('login'))
    
    try:
        google = oauth.create_client('google')
        logger.debug(f"Initiating Google OAuth flow with redirect_uri: {google.redirect_uri}")
        
        # Store the referrer (login or signup) in the session
        if request.referrer and 'signup' in request.referrer:
            session['auth_referrer'] = 'signup'
        else:
            session['auth_referrer'] = 'login'
            
        # Start the OAuth flow
        return google.authorize_redirect(
            redirect_uri=google.redirect_uri,
            access_type='offline',  # Request refresh token
            prompt='select_account',  # Force account selection
            include_granted_scopes='true'  # For incremental auth
        )
        
    except Exception as e:
        logger.error(f"Error initializing Google OAuth: {str(e)}", exc_info=True)
        flash('Failed to initialize Google login. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/login/google/authorized')
def google_authorized():
    """Google OAuth callback for both login and signup"""
    try:
        if 'error' in request.args:
            error = request.args.get('error')
            error_desc = request.args.get('error_description', 'No description')
            logger.error(f"Google OAuth error: {error} - {error_desc}")
            flash(f'Google authentication failed: {error}. Please try again.', 'error')
            return redirect(url_for('login'))
            
        google = oauth.create_client('google')
        logger.debug("Processing Google OAuth callback")
        
        # Get tokens from Google
        token = google.authorize_access_token()
        logger.debug("Successfully obtained access token")
        
        # Get user info
        user_info = google.get('userinfo')
        user_info = user_info.json()
        logger.debug(f"User info: {user_info}")
        
        # Extract user data
        user_email = user_info.get('email')
        google_id = user_info.get('sub')
        user_name = user_info.get('name', '')
        
        if not user_email or not google_id:
            logger.error("Missing email or Google ID in user info")
            flash('Failed to get required information from Google. Please try again.', 'error')
            return redirect(url_for('login'))
            
        # Check if this is a signup or login flow
        is_signup = session.get('auth_referrer') == 'signup'
        
        # Find existing user by Google ID or email
        user = find_user_by_google_id(google_id) or find_user_by_email(user_email)
        
        if not user_info.get('email_verified', False):
            logger.error(f"Email not verified for user: {user_info.get('email')}")
            flash('Your Google email is not verified. Please verify your email with Google and try again.', 'error')
            return redirect(url_for('login'))
        
        user_email = user_info.get('email')
        if not user_email:
            logger.error("No email in Google user info")
            flash('Could not get email from your Google account. Please try another login method.', 'error')
            return redirect(url_for('login'))
        
        # Handle user creation or login
        users = load_users()
        user = find_user_by_google_id(google_id) or find_user_by_email(user_email)
        
        if not user and is_signup:
            # Create new user in signup flow
            logger.info(f"Creating new user account for: {user_email}")
            user = {
                'email': user_email,
                'name': user_info.get('name', user_email.split('@')[0]),
                'google_id': google_id,
                'profile_pic': user_info.get('picture', ''),
                'created_at': datetime.datetime.now().isoformat(),
                'email_verified': True,
                'is_active': True
            }
            # Save the new user
            users.append(user)
            save_users(users)
            logger.info(f"New user created via Google OAuth: {user_email}")
            flash('Account created and signed in with Google!', 'success')
        elif not user and not is_signup:
            # Block login attempt with non-existent account
            logger.warning(f"Login attempt with non-existent email: {user_email}")
            flash('No account found with this email. Please sign up first.', 'error')
            return redirect(url_for('signup'))
        else:
            # Update existing user with Google ID if not set
            if user and not user.get('google_id'):
                user['google_id'] = google_id
                users = [u for u in users if u['email'] != user_email]
                users.append(user)
                save_users(users)
                logger.info(f"Updated user with Google ID: {user_email}")
            
            logger.info(f"User logged in via Google: {user_email}")
            flash('Successfully signed in with Google!', 'success')
        
        # Store minimal session data
        session.permanent = True  # This enables the 24h expiration
        session['email'] = user_email
        session['google_oauth'] = True
        
        # Clear the auth_referrer from session
        session.pop('auth_referrer', None)
        
        next_url = session.pop('next', None)
        return redirect(next_url or url_for('index'))
        
    except Exception as e:
        logger.error(f"Error during Google OAuth callback: {str(e)}", exc_info=True)
        flash('An unexpected error occurred during login. Please try again.', 'error')
        return redirect(url_for('login'))

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Get SendGrid configuration from environment variables
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
FROM_EMAIL = os.environ.get('FROM_EMAIL')
SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"

# Validate required configuration
if not SENDGRID_API_KEY or not FROM_EMAIL:
    logger.error("Missing required environment variables: SENDGRID_API_KEY and/or FROM_EMAIL")
    raise ValueError("Missing required environment variables. Please check your .env file")

# Log configuration information (without exposing sensitive data)
logger.info("SendGrid configuration loaded")
logger.info(f"Sending emails from: {FROM_EMAIL}")

# CSV history functions
def get_csv_history():
    """Get the CSV upload history from JSON file"""
    if os.path.exists(app.config['HISTORY_FILE']):
        try:
            # Load users as a list of dictionaries
            history_data = json.load(f)
            if not isinstance(history_data, list):
                return []
            return history_data
        except json.JSONDecodeError:
            logger.error("Error decoding history file, returning empty history")
            return []
    else:
        return []

def save_csv_history(history):
    """Save the CSV upload history to JSON file"""
    with open(app.config['HISTORY_FILE'], 'w') as f:
        json.dump(history, f, indent=2)

def add_csv_to_history(filename, original_filename, valid_count, invalid_count, sender_email=None):
    """Add a CSV file to the upload history"""
    history = get_csv_history()
    
    # Create new history entry
    new_entry = {
        'id': len(history) + 1,
        'filename': filename,
        'original_filename': original_filename,
        'upload_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'valid_emails': valid_count,
        'invalid_emails': invalid_count,
        'total_emails': valid_count + invalid_count,
        'sent_from': sender_email if sender_email else FROM_EMAIL,
        'user_email': session.get('email') # Link history to logged-in user
    }
    
    # Add to history and save
    history.append(new_entry)
    save_csv_history(history)
    
    return new_entry

# Helper function to check if file extension is allowed
def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension
    
    Args:
        filename (str): The name of the uploaded file
        
    Returns:
        bool: True if the file extension is allowed, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Helper function to validate email
def is_valid_email(email):
    """
    Validate an email address using regex
    
    Args:
        email (str): The email address to validate
        
    Returns:
        bool: True if the email is valid, False otherwise
    """
    # Basic email validation regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Helper function to send email using SendGrid API
def send_email_with_sendgrid(to_email, subject, message_text, from_email=None, api_key=None, attachments=None):
    """
    Send an email using SendGrid API
    
    Args:
        to_email (str): Recipient email address
        subject (str): Email subject
        message_text (str): Email body text
        from_email (str, optional): Sender email address. Defaults to FROM_EMAIL.
        api_key (str, optional): SendGrid API key. Defaults to SENDGRID_API_KEY.
        attachments (list, optional): List of file attachments. Each attachment should be a dict with:
            - 'filename': Name of the file
            - 'content': Base64 encoded content
            - 'type': MIME type of the file
            - 'disposition': Either 'attachment' or 'inline'
            - 'content_id': Optional content ID for inline images
            
    Returns:
        tuple: (success, status_code, response_text)
    """
    # Use provided sender email or default
    sender_email = from_email if from_email else FROM_EMAIL
    
    # Use provided API key or default
    sender_api_key = api_key if api_key else SENDGRID_API_KEY
    
    # Create email data
    email_data = {
        "personalizations": [
            {
                "to": [
                    {
                        "email": to_email
                    }
                ],
                "subject": subject
            }
        ],
        "from": {
            "email": sender_email
        },
        "content": [
            {
                "type": "text/plain",
                "value": message_text
            }
        ]
    }
    
    # Add attachments if any
    if attachments:
        email_data['attachments'] = attachments
    
    # Set up headers
    headers = {
        "Authorization": f"Bearer {sender_api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        # Make the API request
        response = requests.post(
            SENDGRID_API_URL,
            headers=headers,
            data=json.dumps(email_data)
        )
        
        # Check if successful
        success = 200 <= response.status_code < 300
        return success, response.status_code, response.text
    
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False, 0, str(e)

# Routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    # If user is already logged in, go to dashboard, else go to login
    if 'email' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

@app.route('/upload-page')
@login_required
def upload_page():
    """Render the upload page"""
    return render_template('upload.html')

@app.route('/history-page')
@login_required
def history_page():
    """Render the history page"""
    return render_template('history.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """
    Handle file upload and email validation
    
    Returns:
        JSON response with validation results
    """
    try:
        # Clear any existing upload data from session and server-side state
        session.pop('current_upload', None)
        session.pop('valid_emails', None)
        session.pop('invalid_emails', None)
        session.modified = True  # Ensure session is marked as modified
        
        # Check if a file was uploaded
        if 'csvFile' not in request.files:
            logger.warning("No file part in the request")
            return jsonify({'success': False, 'message': 'No file part'})
        
        file = request.files['csvFile']
        
        # Check if file was selected
        if not file or file.filename == '':
            logger.warning("No file selected")
            return jsonify({'success': False, 'message': 'No file selected'})
        
        # Check if file has allowed extension
        if not allowed_file(file.filename):
            logger.warning(f"File type not allowed: {file.filename}")
            return jsonify({
                'success': False, 
                'message': 'File type not allowed. Please upload a CSV file.'
            })
        
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save the file with a timestamp to ensure uniqueness
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        original_filename = secure_filename(file.filename) if file.filename else 'uploaded_file.csv'
        filename = f"{timestamp}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        logger.info(f"File saved: {filepath}")
        
        # First try reading with headers
        try:
            df = pd.read_csv(filepath)
            logger.info(f"CSV file read with columns: {df.columns.tolist()}")
            
            # Check if the CSV has an email column
            email_columns = [col for col in df.columns if 'email' or 'email address' in str(col).lower()]
            
            # If no email column found and we have at least one column, assume first column is emails
            if not email_columns and len(df.columns) > 0:
                logger.info("No email column found, using first column as emails")
                email_column = df.columns[0]
            elif not email_columns:
                logger.warning("No columns found in CSV")
                return jsonify({
                    'success': False, 
                    'message': 'No data found in CSV file.'
                })
            else:
                email_column = email_columns[0]
                
        except Exception as e:
            logger.error(f"Error reading CSV with headers: {str(e)}")
            # If reading with headers fails, try without headers
            try:
                df = pd.read_csv(filepath, header=None)
                if len(df.columns) == 0:
                    return jsonify({
                        'success': False, 
                        'message': 'Empty CSV file.'
                    })
                logger.info("CSV read without headers, using first column as emails")
                email_column = 0  # Use first column
            except Exception as e2:
                logger.error(f"Error reading CSV without headers: {str(e2)}")
                return jsonify({
                    'success': False, 
                    'message': f'Error reading CSV file: {str(e2)}'
                })
        
        logger.info(f"Using column for emails: {email_column}")
        
        # Get all emails from the column
        all_emails = df[email_column].astype(str).tolist()
        logger.info(f"Found {len(all_emails)} email addresses in the CSV")
        
        # Validate emails
        valid_emails = []
        invalid_emails = []
        
        for email in all_emails:
            if is_valid_email(email):
                valid_emails.append(email)
            else:
                invalid_emails.append(email)
        
        logger.info(f"Validation results: {len(valid_emails)} valid, {len(invalid_emails)} invalid")
        
        # Don't store validation results in session to prevent persistence issues
        # We'll rely on the client-side state instead
        
        # Return the results without adding to history yet
        # We'll add to history after emails are actually sent
        return jsonify({
            'success': True,
            'valid_emails': valid_emails,
            'invalid_emails': invalid_emails,
            'filename': filename,
            'original_filename': file.filename,
            'valid_count': len(valid_emails),
            'invalid_count': len(invalid_emails)
        })
        
    except Exception as e:
        logger.error(f"Error processing CSV file: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)})

@app.route('/send', methods=['POST'])
@login_required
def send_emails():
    """
    Send emails to valid recipients with optional attachments
    
    Returns:
        JSON response with sending results
    """
    try:
        # Check if request has form data (for file uploads)
        if request.files:
            # Get form data
            sender_email = request.form.get('senderEmail')
            sender_api_key = request.form.get('senderApiKey')
            subject = request.form.get('subject', '')
            message = request.form.get('message', '')
            emails = json.loads(request.form.get('emails', '[]'))
            
            # Process file attachments
            attachments = []
            for file_key in request.files:
                file = request.files[file_key]
                if file.filename:  # Only process if file was selected
                    file_content = base64.b64encode(file.read()).decode('utf-8')
                    attachments.append({
                        'filename': file.filename,
                        'content': file_content,
                        'type': file.content_type or 'application/octet-stream',
                        'disposition': 'attachment'
                    })
        else:
            # Handle JSON data (for backward compatibility)
            data = request.get_json()
            if not data:
                logger.error("No data received in request")
                return jsonify({'success': False, 'message': 'No data received'})
                
            subject = data.get('subject', '')
            message = data.get('message', '')
            emails = data.get('emails', [])
            sender_email = data.get('senderEmail')
            sender_api_key = data.get('senderApiKey')
            attachments = data.get('attachments', [])
        
        # Check if we have all required data (subject/message only required if no attachments)
        if not emails or (not subject and not message and not attachments):
            logger.warning("Missing required data for sending emails")
            return jsonify({
                'success': False, 
                'message': 'Missing required data (emails and either subject/message or attachments)'
            })
        
        # Check if sender email and API key are provided
        use_custom_sender = sender_email and sender_api_key
        
        # If not using custom sender, check if default SendGrid API key is configured
        if not use_custom_sender and not SENDGRID_API_KEY:
            logger.error("SendGrid API key not configured")
            return jsonify({
                'success': False, 
                'message': 'SendGrid API key not configured. Please set SENDGRID_API_KEY in .env file or provide your own.'
            })
        
        logger.info(f"Attempting to send emails to {len(emails)} recipients")
        
        # Send email to each recipient
        successful_sends = 0
        failed_sends = 0
        
        for email in emails:
            try:
                logger.debug(f"Sending email to {email}")
                
                # Send the email using our helper function with attachments
                if use_custom_sender:
                    success, status_code, response_text = send_email_with_sendgrid(
                        email, 
                        subject or '(No subject)', 
                        message or '(No message)', 
                        from_email=sender_email, 
                        api_key=sender_api_key,
                        attachments=attachments
                    )
                else:
                    success, status_code, response_text = send_email_with_sendgrid(
                        email, 
                        subject or '(No subject)', 
                        message or '(No message)',
                        attachments=attachments
                    )
                
                # Log the response
                logger.debug(f"SendGrid response: {status_code} - {response_text}")
                
                # Check if email was sent successfully
                if success:
                    successful_sends += 1
                    logger.debug(f"Email sent successfully to {email}")
                else:
                    failed_sends += 1
                    logger.warning(f"Failed to send email to {email}: {status_code} - {response_text}")
                    
            except Exception as e:
                failed_sends += 1
                logger.error(f"Error preparing email for {email}: {str(e)}")
        
        # Add to CSV history if filename is provided and emails were attempted to be sent
        history_entry = None
        if (successful_sends + failed_sends > 0) and 'filename' in data and 'original_filename' in data and 'valid_count' in data and 'invalid_count' in data:
            # Determine which sender email to use
            actual_sender_email = sender_email if use_custom_sender else FROM_EMAIL
            
            history_entry = add_csv_to_history(
                filename=data['filename'],
                original_filename=data['original_filename'],
                valid_count=data['valid_count'],
                invalid_count=data['invalid_count'],
                sender_email=actual_sender_email
            )
            logger.info(f"Added to history after sending: {history_entry}")
        
        # Return the results
        result = {
            'success': True,
            'message': f'Sent {successful_sends} emails successfully. {failed_sends} failed.',
            'successful_sends': successful_sends,
            'failed_sends': failed_sends,
            'history_entry': history_entry
        }
        logger.info(f"Email sending complete: {result}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in send_emails: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)})

# Route to get CSV upload history
@app.route('/history', methods=['GET'])
@login_required
def get_history():
    """
    Get the CSV upload history
    
    Returns:
        JSON response with upload history
    """
    try:
        # Filter history by logged-in user
        current_user_email = session.get('email')
        full_history = get_csv_history()
        user_history = [entry for entry in full_history if entry.get('user_email') == current_user_email]

        return jsonify({
            'success': True,
            'history': user_history
        })
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)})

# Run the application
if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True)