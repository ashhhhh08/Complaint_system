"""
Smart Complaint Management System
Flask Backend Application with Security Features
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
import os
import re
import hashlib
import secrets
import logging
import uuid
from html import escape

# Configure logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production-2024')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True for HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout
app.config['JSON_SORT_KEYS'] = False

# Security headers
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

# Allowed extensions for file upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif'}

# Rate limiting storage
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds

# Database configuration
DATABASE = os.path.join(os.path.dirname(__file__), 'database.db')

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks"""
    if not isinstance(text, str):
        return text
    # Escape HTML special characters
    text = escape(text)
    # Remove any script tags or dangerous content
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    return text.strip()


def validate_password(password):
    """Validate password meets security requirements"""
    errors = []
    
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    if not re.search(r'[0-9]', password):
        errors.append('Password must contain at least one number')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character (!@#$%^&*)')
    
    return errors


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def check_rate_limit(identifier):
    """Check if user has exceeded login attempts"""
    now = datetime.now().timestamp()
    
    if identifier in LOGIN_ATTEMPTS:
        attempts, locked_until = LOGIN_ATTEMPTS[identifier]
        
        # Check if still locked out
        if locked_until > now:
            return False, int(locked_until - now)
        
        # Reset if lockout period expired
        if attempts >= MAX_LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[identifier]
    
    return True, 0


def record_login_attempt(identifier, success=False):
    """Record login attempt for rate limiting"""
    now = datetime.now().timestamp()
    
    if identifier not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[identifier] = [0, now]
    
    attempts, _ = LOGIN_ATTEMPTS[identifier]
    
    if success:
        # Clear attempts on successful login
        if identifier in LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[identifier]
        logger.info(f'Successful login: {identifier}')
    else:
        # Increment failed attempts
        attempts += 1
        locked_until = now + LOCKOUT_DURATION if attempts >= MAX_LOGIN_ATTEMPTS else now
        LOGIN_ATTEMPTS[identifier] = [attempts, locked_until]
        logger.warning(f'Failed login attempt {attempts}: {identifier}')


def log_activity(user_id, action, details=''):
    """Log user activity for audit trail"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create activity log table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        ip_address = request.remote_addr if request else 'system'
        cursor.execute(
            'INSERT INTO activity_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
            (user_id, action, details, ip_address)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f'Error logging activity: {str(e)}')


def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Complaints table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            image_path TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create admin user if doesn't exist
    admin_exists = cursor.execute('SELECT * FROM users WHERE email = ?', ('admin@example.com',)).fetchone()
    if not admin_exists:
        admin_password = generate_password_hash('admin123')
        cursor.execute(
            'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
            ('Admin', 'admin@example.com', admin_password, 'admin')
        )
    
    conn.commit()
    conn.close()


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to check if user is admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    elif 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Input validation
        if not name:
            flash('Name is required', 'danger')
            return redirect(url_for('register'))
        
        if len(name) < 2 or len(name) > 100:
            flash('Name must be between 2 and 100 characters', 'danger')
            return redirect(url_for('register'))
        
        if not email:
            flash('Email is required', 'danger')
            return redirect(url_for('register'))
        
        if not validate_email(email):
            flash('Invalid email format', 'danger')
            return redirect(url_for('register'))
        
        if not password:
            flash('Password is required', 'danger')
            return redirect(url_for('register'))
        
        # Validate password requirements
        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                flash(error, 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Sanitize inputs
        name = sanitize_input(name)
        email = sanitize_input(email)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email already exists
        existing_user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            flash('Email already registered', 'danger')
            conn.close()
            log_activity(None, 'FAILED_REGISTER', f'Email already exists: {email}')
            return redirect(url_for('register'))
        
        # Create new user with secure password hash
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            cursor.execute(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                (name, email, password_hash, 'user')
            )
            conn.commit()
            logger.info(f'New user registered: {email}')
            log_activity(None, 'USER_REGISTERED', f'Email: {email}')
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            logger.error(f'Database error during registration: {str(e)}')
            flash('Error registering user', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Rate limiting check
        allowed, wait_time = check_rate_limit(email)
        if not allowed:
            flash(f'Too many failed login attempts. Please try again in {wait_time} seconds.', 'danger')
            logger.warning(f'Login attempt blocked due to rate limiting: {email}')
            return redirect(url_for('login'))
        
        # Input validation
        if not email or not password:
            flash('Email and password required', 'danger')
            record_login_attempt(email, success=False)
            return redirect(url_for('login'))
        
        if not validate_email(email):
            flash('Invalid email format', 'danger')
            record_login_attempt(email, success=False)
            return redirect(url_for('login'))
        
        # Sanitize inputs
        email = sanitize_input(email)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        user = cursor.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'user')).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=2)
            record_login_attempt(email, success=True)
            flash(f'Welcome, {user["name"]}!', 'success')
            log_activity(user['id'], 'LOGIN', 'User login successful')
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(email, success=False)
            flash('Invalid email or password', 'danger')
            log_activity(None, 'FAILED_LOGIN', f'Email: {email}')
    
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's complaints
    complaints = cursor.execute(
        'SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    # Get statistics
    total_complaints = len(complaints)
    pending = len([c for c in complaints if c['status'] == 'Pending'])
    in_progress = len([c for c in complaints if c['status'] == 'In Progress'])
    resolved = len([c for c in complaints if c['status'] == 'Resolved'])
    
    conn.close()
    
    return render_template('dashboard.html', 
                         complaints=complaints,
                         total=total_complaints,
                         pending=pending,
                         in_progress=in_progress,
                         resolved=resolved)


@app.route('/submit_complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    """Submit a new complaint"""
    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        image_path = None
        
        # Input validation
        if not category:
            flash('Category is required', 'danger')
            return redirect(url_for('submit_complaint'))
        
        if not description:
            flash('Description is required', 'danger')
            return redirect(url_for('submit_complaint'))
        
        if len(description) < 10:
            flash('Description must be at least 10 characters', 'danger')
            return redirect(url_for('submit_complaint'))
        
        if len(description) > 5000:
            flash('Description must not exceed 5000 characters', 'danger')
            return redirect(url_for('submit_complaint'))
        
        # Sanitize inputs
        category = sanitize_input(category)
        description = sanitize_input(description)
        
        # Handle file upload with validation
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Check file extension
                if not allowed_file(file.filename):
                    flash('Only image files (jpg, jpeg, png, gif) are allowed', 'danger')
                    return redirect(url_for('submit_complaint'))
                
                # Check file size (max 5MB)
                file.seek(0, os.SEEK_END)
                file_length = file.tell()
                if file_length > 5 * 1024 * 1024:  # 5MB
                    flash('File size must not exceed 5MB', 'danger')
                    return redirect(url_for('submit_complaint'))
                
                file.seek(0)
                
                # Security: Generate unique filename
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + str(uuid.uuid4())[:8] + '_' + filename
                
                try:
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = filename
                except Exception as e:
                    logger.error(f'Error saving file: {str(e)}')
                    flash('Error saving image file', 'danger')
                    return redirect(url_for('submit_complaint'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO complaints (user_id, category, description, image_path, status) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], category, description, image_path, 'Pending')
            )
            conn.commit()
            complaint_id = cursor.lastrowid
            logger.info(f'New complaint submitted by user {session["user_id"]}: ID {complaint_id}')
            log_activity(session['user_id'], 'COMPLAINT_SUBMITTED', f'Category: {category}')
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.Error as e:
            logger.error(f'Database error submitting complaint: {str(e)}')
            flash('Error submitting complaint', 'danger')
            return redirect(url_for('submit_complaint'))
        finally:
            conn.close()
    
    return render_template('complaint_form.html')


@app.route('/complaint/<int:complaint_id>')
@login_required
def complaint_status(complaint_id):
    """View single complaint status"""
    conn = get_db_connection()
    complaint = conn.execute(
        'SELECT * FROM complaints WHERE id = ? AND user_id = ?',
        (complaint_id, session['user_id'])
    ).fetchone()
    conn.close()
    
    if not complaint:
        flash('Complaint not found', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('complaint_status.html', complaint=complaint)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Rate limiting for admin
        allowed, wait_time = check_rate_limit(f'admin_{email}')
        if not allowed:
            flash(f'Too many failed attempts. Please try again in {wait_time} seconds.', 'danger')
            logger.warning(f'Admin login blocked due to rate limiting: {email}')
            return redirect(url_for('admin_login'))
        
        # Input validation
        if not email or not password:
            flash('Email and password required', 'danger')
            record_login_attempt(f'admin_{email}', success=False)
            return redirect(url_for('admin_login'))
        
        if not validate_email(email):
            flash('Invalid email format', 'danger')
            record_login_attempt(f'admin_{email}', success=False)
            return redirect(url_for('admin_login'))
        
        # Sanitize inputs
        email = sanitize_input(email)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        user = cursor.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, 'admin')).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['admin_id'] = user['id']
            session['admin_name'] = user['name']
            session.permanent = True
            record_login_attempt(f'admin_{email}', success=True)
            flash(f'Welcome, Admin {user["name"]}!', 'success')
            log_activity(user['id'], 'ADMIN_LOGIN', 'Admin login successful')
            return redirect(url_for('admin_dashboard'))
        else:
            record_login_attempt(f'admin_{email}', success=False)
            flash('Invalid admin credentials', 'danger')
            log_activity(None, 'FAILED_ADMIN_LOGIN', f'Email: {email}')
    
    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    status_filter = request.args.get('status', 'All')
    category_filter = request.args.get('category', 'All')
    search_query = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Build query based on filters
    query = 'SELECT complaints.*, users.name, users.email FROM complaints JOIN users ON complaints.user_id = users.id WHERE 1=1'
    params = []
    
    if status_filter != 'All':
        query += ' AND complaints.status = ?'
        params.append(status_filter)
    
    if category_filter != 'All':
        query += ' AND complaints.category = ?'
        params.append(category_filter)
    
    if search_query:
        query += ' AND (complaints.description LIKE ? OR users.name LIKE ? OR users.email LIKE ?)'
        like_query = f'%{search_query}%'
        params.extend([like_query, like_query, like_query])
    
    query += ' ORDER BY complaints.created_at DESC'
    
    complaints = cursor.execute(query, params).fetchall()
    
    # Get statistics
    all_complaints = cursor.execute('SELECT * FROM complaints').fetchall()
    stats = {
        'total': len(all_complaints),
        'pending': len([c for c in all_complaints if c['status'] == 'Pending']),
        'in_progress': len([c for c in all_complaints if c['status'] == 'In Progress']),
        'resolved': len([c for c in all_complaints if c['status'] == 'Resolved'])
    }
    
    # Get unique categories
    categories = cursor.execute('SELECT DISTINCT category FROM complaints').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                         complaints=complaints,
                         stats=stats,
                         categories=[c['category'] for c in categories],
                         current_status=status_filter,
                         current_category=category_filter,
                         search_query=search_query)


@app.route('/update_status/<int:complaint_id>', methods=['POST'])
@admin_required
def update_status(complaint_id):
    """Update complaint status"""
    status = request.form.get('status', '').strip()
    
    # Input validation
    if not isinstance(complaint_id, int) or complaint_id <= 0:
        flash('Invalid complaint ID', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    valid_statuses = ['Pending', 'In Progress', 'Resolved']
    if status not in valid_statuses:
        flash('Invalid status', 'danger')
        logger.warning(f'Invalid status update attempt: {status}')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify complaint exists
    complaint = cursor.execute('SELECT * FROM complaints WHERE id = ?', (complaint_id,)).fetchone()
    if not complaint:
        flash('Complaint not found', 'danger')
        conn.close()
        return redirect(url_for('admin_dashboard'))
    
    try:
        cursor.execute('UPDATE complaints SET status = ? WHERE id = ?', (status, complaint_id))
        conn.commit()
        logger.info(f'Complaint {complaint_id} status updated to {status}')
        log_activity(session.get('admin_id'), 'STATUS_UPDATED', f'Complaint {complaint_id}: {status}')
        flash('Status updated successfully', 'success')
    except sqlite3.Error as e:
        logger.error(f'Error updating complaint status: {str(e)}')
        flash('Error updating status', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_complaint/<int:complaint_id>', methods=['POST'])
@admin_required
def delete_complaint(complaint_id):
    """Delete a complaint"""
    # Input validation
    if not isinstance(complaint_id, int) or complaint_id <= 0:
        flash('Invalid complaint ID', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get complaint to delete image if exists
    complaint = cursor.execute('SELECT * FROM complaints WHERE id = ?', (complaint_id,)).fetchone()
    
    if not complaint:
        flash('Complaint not found', 'danger')
        conn.close()
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete image file if exists
        if complaint['image_path']:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], complaint['image_path'])
            try:
                if os.path.exists(image_path):
                    os.remove(image_path)
                    logger.info(f'Deleted image file: {complaint["image_path"]}')
            except Exception as e:
                logger.error(f'Error deleting image file: {str(e)}')
        
        # Delete complaint from database
        cursor.execute('DELETE FROM complaints WHERE id = ?', (complaint_id,))
        conn.commit()
        
        logger.info(f'Complaint {complaint_id} deleted by admin')
        log_activity(session.get('admin_id'), 'COMPLAINT_DELETED', f'Complaint ID: {complaint_id}')
        flash('Complaint deleted successfully', 'success')
    except sqlite3.Error as e:
        logger.error(f'Error deleting complaint: {str(e)}')
        flash('Error deleting complaint', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    """Logout user or admin"""
    user_id = session.get('user_id') or session.get('admin_id')
    user_name = session.get('user_name') or session.get('admin_name')
    
    log_activity(user_id, 'LOGOUT', f'User: {user_name}')
    
    session.clear()
    flash('You have been logged out', 'info')
    logger.info(f'User {user_name} (ID: {user_id}) logged out')
    return redirect(url_for('login'))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return redirect(f'/static/uploads/{filename}')


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500


if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
