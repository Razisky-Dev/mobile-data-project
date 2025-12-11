"""
RazilHub - Mobile Data Vending Platform
A complete Flask application for vending mobile data packages
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask import make_response
from flask_sqlalchemy import SQLAlchemy
import random
import time
import re
import sqlite3
import os
import contextlib
import logging
from datetime import datetime
import secrets
from functools import wraps

# Import middleware
from middleware import SecurityMiddleware, RateLimitMiddleware, LoggingMiddleware, ErrorHandlingMiddleware, log_business_event

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'razilhub_secret_key_2025')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/razilhub.log'),
        logging.StreamHandler()
    ]
)

# Initialize middleware
SecurityMiddleware(app)
RateLimitMiddleware(app)
LoggingMiddleware(app)
ErrorHandlingMiddleware(app)

# Database configuration
DATABASE = 'data_vending.db'

def get_db_connection():
    """Get database connection with proper timeout and WAL mode"""
    conn = sqlite3.connect(DATABASE, timeout=60.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=1000')
    conn.execute('PRAGMA temp_store=memory')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

@contextlib.contextmanager
def get_db():
    """Context manager for database connections"""
    conn = None
    try:
        conn = get_db_connection()
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize database with required tables"""
    conn = get_db_connection()
    
    # Check if users table exists and has the required columns
    try:
        conn.execute('SELECT first_name FROM users LIMIT 1')
    except sqlite3.OperationalError:
        # Table exists but doesn't have new columns, add them
        try:
            conn.execute('ALTER TABLE users ADD COLUMN first_name TEXT')
            conn.execute('ALTER TABLE users ADD COLUMN last_name TEXT')
            conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
            conn.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
            conn.execute('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE')
            conn.execute('ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            conn.execute('ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            print("Updated existing users table with new columns")
        except sqlite3.OperationalError:
            # Columns already exist, continue
            pass
    
    # Users table with enhanced fields (CREATE IF NOT EXISTS)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            otp TEXT,
            wallet REAL DEFAULT 50.0,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            is_admin BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Transactions table with enhanced fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            network TEXT,
            recipient TEXT,
            data_package TEXT,
            status TEXT DEFAULT 'completed',
            reference TEXT UNIQUE,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Services table for different service offerings
    conn.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Orders table for service bookings
    conn.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            service_id INTEGER,
            status TEXT DEFAULT 'pending',
            total_amount REAL NOT NULL,
            delivery_address TEXT,
            special_instructions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (service_id) REFERENCES services (id)
        )
    ''')
    
    # Add missing columns to orders table if they don't exist
    try:
        conn.execute('ALTER TABLE orders ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        print("Added updated_at column to orders table")
    except sqlite3.OperationalError:
        # Column already exists, continue
        pass
    
    # Notifications table for user notifications
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin user
    admin_phone = '0540000000'
    admin_exists = conn.execute('SELECT id FROM users WHERE phone = ?', (admin_phone,)).fetchone()
    if not admin_exists:
        conn.execute('''
            INSERT INTO users (phone, first_name, last_name, is_admin, wallet) 
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_phone, 'Admin', 'User', True, 1000.0))
    
    # Insert default services
    default_services = [
        ('Car Detailing - Basic', 'car_detailing', 25.0, 'Exterior wash and dry'),
        ('Car Detailing - Premium', 'car_detailing', 45.0, 'Interior and exterior wash with wax'),
        ('Food Delivery', 'food', 15.0, 'Food delivery service fee'),
        ('Parcel Delivery', 'delivery', 30.0, 'Parcel delivery within city'),
    ]
    
    for service in default_services:
        exists = conn.execute('SELECT id FROM services WHERE name = ?', (service[0],)).fetchone()
        if not exists:
            conn.execute('''
                INSERT INTO services (name, category, price, description) 
                VALUES (?, ?, ?, ?)
            ''', service)
    
    conn.commit()
    conn.close()

def generate_reference():
    """Generate unique transaction reference"""
    return f"RZ{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_by_phone(phone):
    """Get user by phone number"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()
    conn.close()
    return user

def create_user(phone, otp, first_name=None, last_name=None, email=None):
    """Create a new user"""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            INSERT INTO users (phone, otp, first_name, last_name, email) 
            VALUES (?, ?, ?, ?, ?)
        ''', (phone, otp, first_name, last_name, email))
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        # User already exists, update OTP
        conn.execute('''
            UPDATE users SET otp = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE phone = ?
        ''', (otp, phone))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE phone = ?', (phone,)).fetchone()
        user_id = user['id']
    finally:
        conn.close()
    return user_id

def get_user_wallet(user_id):
    """Get user wallet balance"""
    conn = get_db_connection()
    user = conn.execute('SELECT wallet FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user['wallet'] if user else 0.0

def update_wallet(user_id, amount, transaction_type, network=None, recipient=None, data_package=None, description=None):
    """Update user wallet and create transaction record"""
    reference = generate_reference()
    
    with get_db() as conn:
        # Update wallet balance
        if transaction_type == 'deposit':
            conn.execute('''
                UPDATE users SET wallet = wallet + ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (amount, user_id))
        elif transaction_type in ['withdrawal', 'data_purchase', 'service_payment']:
            conn.execute('''
                UPDATE users SET wallet = wallet - ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (amount, user_id))
        
        # Create transaction record
        conn.execute('''
            INSERT INTO transactions (user_id, type, amount, network, recipient, data_package, reference, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, transaction_type, amount, network, recipient, data_package, reference, description))
        
        conn.commit()
    
    return reference

def verify_otp(phone, entered_otp):
    """Verify OTP for user"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE phone = ? AND otp = ?', (phone, entered_otp)).fetchone()
    conn.close()
    return user

# Initialize database on startup
try:
    init_db()
    print("✅ Database initialized successfully")
except Exception as e:
    print(f"❌ Database initialization failed: {e}")
    logging.error(f"Database initialization failed: {e}")

# ----------------------------
# AUTHENTICATION ROUTES
# ----------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()

        # Normalize +233 format to local 0 format
        if phone.startswith("+233"):
            phone = "0" + phone[4:]

        # Ghana valid prefixes
        ghana_pattern = re.compile(r"^0(20|24|25|26|27|50|53|54|55|56|57|59)\d{7}$")

        if not ghana_pattern.match(phone):
            flash("❌ Please enter a valid Ghana mobile number (e.g. 0541234567 or +233541234567)", "error")
            return render_template("login.html")

        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Create or update user with OTP
        create_user(phone, otp)
        
        session["phone"] = phone

        # Show OTP on screen for demo
        flash(f"📱 OTP for {phone} is: {otp}", "success")
        flash("✅ Please verify to continue.", "info")
        return redirect(url_for("verify"))

    return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        phone = session.get("phone")

        if not phone:
            flash("❌ Session expired. Please login again.", "error")
            return redirect(url_for("login"))

        user = verify_otp(phone, entered_otp)
        if user:
            session["user_id"] = user["id"]
            session["phone"] = user["phone"]
            session["is_admin"] = user["is_admin"]
            
            # Log successful login
            log_business_event('user_login', {
                'user_id': user["id"],
                'phone': user["phone"],
                'is_admin': user["is_admin"]
            })
            
            flash("✅ Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            # Log failed login attempt
            log_business_event('login_failed', {
                'phone': phone,
                'reason': 'invalid_otp'
            })
            flash("❌ Invalid OTP. Please try again.", "error")

    return render_template("verify.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("✅ Logged out successfully.", "info")
    return redirect(url_for("login"))

# ----------------------------
# MAIN DASHBOARD
# ----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    balance = get_user_wallet(session["user_id"])
    
    # Get recent transactions
    conn = get_db_connection()
    recent_transactions = conn.execute('''
        SELECT * FROM transactions WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT 5
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template("dashboard.html", 
                         balance=balance, 
                         recent_transactions=recent_transactions,
                         is_admin=session.get('is_admin', False))

# ----------------------------
# USER PROFILE MANAGEMENT
# ----------------------------
@app.route("/profile")
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template("profile.html", user=user)

@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip()
    
    conn = get_db_connection()
    conn.execute('''
        UPDATE users SET first_name = ?, last_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (first_name, last_name, email, session['user_id']))
    conn.commit()
    conn.close()
    
    flash("✅ Profile updated successfully!", "success")
    return redirect(url_for("profile"))

# ----------------------------
# TRANSACTION HISTORY
# ----------------------------
@app.route("/transactions")
@login_required
def transactions():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    # Get total count
    total = conn.execute('SELECT COUNT(*) as count FROM transactions WHERE user_id = ?', (session['user_id'],)).fetchone()['count']
    
    # Get transactions
    user_transactions = conn.execute('''
        SELECT * FROM transactions WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT ? OFFSET ?
    ''', (session['user_id'], per_page, offset)).fetchall()
    
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template("transactions.html", 
                         transactions=user_transactions,
                         current_page=page,
                         total_pages=total_pages)

# ----------------------------
# DATA SERVICES
# ----------------------------
@app.route("/data")
@login_required
def data():
    balance = get_user_wallet(session["user_id"])
    return render_template("data_services.html", balance=balance)

@app.route("/buy_data", methods=["POST"])
@login_required
def buy_data():
    user_id = session["user_id"]
    network = request.form.get("network")
    price = float(request.form.get("price", 0))
    recipient = request.form.get("recipient", "")
    payment_method = request.form.get("payment_method")

    # Validate recipient number format
    ghana_pattern = re.compile(r"^0(20|24|25|26|27|50|53|54|55|56|57|59)\d{7}$")
    if not recipient or not ghana_pattern.match(recipient):
        flash("❌ Please enter a valid Ghana mobile number", "error")
        return redirect(url_for("buy_data"))

    if price <= 0:
        flash("❌ Invalid package selected.", "error")
        return redirect(url_for("buy_data"))

    # Map prices to data amounts
    data_plans = {
        5: "1GB", 10: "2GB", 15: "3GB", 20: "4GB", 24: "5GB", 29: "6GB", 37: "8GB", 44: "10GB", 62: "15GB",
        83: "20GB", 102: "25GB", 122: "30GB", 162: "40GB", 198: "50GB",  # MTN
        23: "5GB", 44: "10GB", 62: "15GB", 79: "20GB", 97: "25GB", 117: "30GB", 149: "40GB", 185: "50GB",
        359: "100GB",  # Telecel
        4.5: "1GB", 9.5: "2GB", 13.5: "3GB", 17.5: "4GB", 22: "5GB", 24: "6GB", 32: "8GB", 39: "10GB", 58: "15GB",
        81: "20GB", 95: "25GB"  # AirtelTigo
    }

    plan = data_plans.get(price, f"GHS {price}")
    description = f"Data purchase: {plan} {network} for {recipient}"

    # Wallet payment
    if payment_method == "wallet":
        current_balance = get_user_wallet(user_id)

        if current_balance < price:
            flash("❌ Insufficient balance. Please deposit to continue.", "error")
            return redirect(url_for("buy_data"))

        # Deduct and create transaction
        reference = update_wallet(user_id, price, "data_purchase", network, recipient, plan, description)

        # Create notification
        with get_db() as conn:
            conn.execute(
                '''INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                (user_id, "transaction", "Data Purchase",
                 f"Successfully purchased {plan} {network} data for {recipient}. Reference: {reference}")
            )
            conn.commit()

        flash(f"✅ Successfully purchased {plan} {network} data for {recipient}! Reference: {reference}", "success")
        return redirect(url_for("buy_data"))

    # MOMO redirect
    if payment_method == "momo":
        return redirect(url_for("momo_payment", network=network, price=price, recipient=recipient))

    flash("❌ Invalid payment method.", "error")
    return redirect(url_for("buy_data"))

# ----------------------------
# WALLET MANAGEMENT
# ----------------------------
@app.route("/deposit", methods=["POST"])
@login_required
def deposit():
    amount = float(request.form.get("amount", 0))
    if amount <= 0:
        flash("❌ Enter a valid deposit amount.", "error")
    else:
        user_id = session["user_id"]
        reference = update_wallet(user_id, amount, 'deposit', description=f"Wallet deposit")
        
        # Create notification for deposit
        with get_db() as conn:
            conn.execute('''
                INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, 'transaction', 'Wallet Deposit', f"Successfully deposited GHS {amount:.2f} to your wallet. Reference: {reference}"))
            conn.commit()
        
        flash(f"✅ Deposited GHS {amount:.2f} successfully. Reference: {reference}", "success")
    return redirect(url_for("dashboard"))

@app.route("/withdraw", methods=["POST"])
@login_required
def withdraw():
    amount = float(request.form.get("amount", 0))
    user_id = session["user_id"]
    current_balance = get_user_wallet(user_id)
    
    if amount <= 0:
        flash("❌ Enter a valid withdrawal amount.", "error")
    elif amount > current_balance:
        flash("❌ Insufficient balance for withdrawal.", "error")
    else:
        reference = update_wallet(user_id, amount, 'withdrawal', description=f"Wallet withdrawal")
        
        # Create notification for withdrawal
        with get_db() as conn:
            conn.execute('''
                INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, 'transaction', 'Wallet Withdrawal', f"Successfully withdrew GHS {amount:.2f} from your wallet. Reference: {reference}"))
            conn.commit()
        
        flash(f"✅ Withdrew GHS {amount:.2f} successfully. Reference: {reference}", "success")
    return redirect(url_for("dashboard"))

# ----------------------------
# SERVICE BOOKINGS
# ----------------------------
@app.route("/car_detailing")
@login_required
def car_detailing():
    conn = get_db_connection()
    services = conn.execute('SELECT * FROM services WHERE category = ? AND is_active = TRUE', ('car_wash',)).fetchall()
    conn.close()
    return render_template("car_detailing.html", services=services)

@app.route("/delivery")
@login_required
def delivery():
    conn = get_db_connection()
    services = conn.execute('SELECT * FROM services WHERE category = ? AND is_active = TRUE', ('delivery',)).fetchall()
    conn.close()
    return render_template("delivery.html", services=services)

@app.route("/food")
@login_required
def food():
    conn = get_db_connection()
    services = conn.execute('SELECT * FROM services WHERE category = ? AND is_active = TRUE', ('food',)).fetchall()
    conn.close()
    return render_template("food.html", services=services)

@app.route("/book_service", methods=["POST"])
@login_required
def book_service():
    service_id = request.form.get("service_id")
    delivery_address = request.form.get("delivery_address", "").strip()
    special_instructions = request.form.get("special_instructions", "").strip()
    
    try:
        with get_db() as conn:
            service = conn.execute('SELECT * FROM services WHERE id = ?', (service_id,)).fetchone()
            
            if not service:
                flash("❌ Service not found.", "error")
                return redirect(url_for("dashboard"))
            
            user_id = session["user_id"]
            
            # Get current balance within the same connection
            user = conn.execute('SELECT wallet FROM users WHERE id = ?', (user_id,)).fetchone()
            current_balance = user['wallet'] if user else 0.0
            
            if current_balance < service['price']:
                flash("❌ Insufficient balance for this service.", "error")
                return redirect(url_for("dashboard"))
            
            # Generate reference
            reference = generate_reference()
            
            # Update wallet balance
            conn.execute('''
                UPDATE users SET wallet = wallet - ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (service['price'], user_id))
            
            # Create transaction record
            conn.execute('''
                INSERT INTO transactions (user_id, type, amount, network, recipient, data_package, reference, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, 'service_payment', service['price'], None, None, None, reference, f"Payment for {service['name']}"))
            
            # Create order
            conn.execute('''
                INSERT INTO orders (user_id, service_id, total_amount, delivery_address, special_instructions)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, service_id, service['price'], delivery_address, special_instructions))
            
            # Create notification for booking
            conn.execute('''
                INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, 'booking', 'Service Booked', f"Your {service['name']} has been booked successfully. Reference: {reference}"))
            
            conn.commit()
            
            flash(f"✅ {service['name']} booked successfully! Reference: {reference}", "success")
            return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"❌ An error occurred while booking the service: {str(e)}", "error")
        return redirect(url_for("dashboard"))

# ----------------------------
# ADMIN ROUTES
# ----------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Get statistics
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    total_transactions = conn.execute('SELECT COUNT(*) as count FROM transactions').fetchone()['count']
    total_revenue = conn.execute('SELECT SUM(amount) as total FROM transactions WHERE type IN ("data_purchase", "service_payment")').fetchone()['total'] or 0
    
    # Get recent transactions
    recent_transactions = conn.execute('''
        SELECT t.*, u.phone FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC LIMIT 10
    ''').fetchall()
    
    # Get recent users
    recent_users = conn.execute('SELECT * FROM users ORDER BY created_at DESC LIMIT 10').fetchall()
    
    conn.close()
    
    return render_template("admin_dashboard.html",
                         total_users=total_users,
                         total_transactions=total_transactions,
                         total_revenue=total_revenue,
                         recent_transactions=recent_transactions,
                         recent_users=recent_users)

@app.route("/admin/users")
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', 'all', type=str)
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        # Build query conditions
        conditions = []
        params = []
        
        if search:
            conditions.append("(phone LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param, search_param])
        
        if status_filter == 'active':
            conditions.append("is_active = 1 AND is_admin = 0")
        elif status_filter == 'inactive':
            conditions.append("is_active = 0 AND is_admin = 0")
        elif status_filter == 'admin':
            conditions.append("is_admin = 1")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        # Get total count
        count_query = f"SELECT COUNT(*) as count FROM users WHERE {where_clause}"
        total = conn.execute(count_query, params).fetchone()['count']
        
        # Get users with enhanced data
        users_query = f'''
            SELECT u.*, 
                   COUNT(t.id) as transaction_count,
                   COALESCE(SUM(t.amount), 0) as total_spent
            FROM users u
            LEFT JOIN transactions t ON u.id = t.user_id
            WHERE {where_clause}
            GROUP BY u.id
            ORDER BY u.created_at DESC 
            LIMIT ? OFFSET ?
        '''
        params.extend([per_page, offset])
        users = conn.execute(users_query, params).fetchall()
        
        # Get statistics
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN is_active = 1 AND is_admin = 0 THEN 1 END) as active_users,
                COUNT(CASE WHEN is_active = 0 AND is_admin = 0 THEN 1 END) as inactive_users,
                COUNT(CASE WHEN is_admin = 1 THEN 1 END) as admin_users,
                COUNT(CASE WHEN created_at >= datetime('now', '-30 days') THEN 1 END) as new_users_month,
                AVG(wallet) as avg_wallet_balance
            FROM users
        ''').fetchone()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template("admin_users.html", 
                         users=users,
                         current_page=page,
                         total_pages=total_pages,
                         search=search,
                         status_filter=status_filter,
                         stats=stats)

@app.route("/admin/users/toggle_status/<int:user_id>", methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        # Prevent admin from deactivating themselves
        if user['is_admin'] and user_id == session.get('user_id'):
            flash('You cannot deactivate your own admin account', 'error')
            return redirect(url_for('admin_users'))
        
        new_status = not user['is_active']
        conn.execute('UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                    (new_status, user_id))
        
        status_text = 'activated' if new_status else 'deactivated'
        flash(f'User {status_text} successfully', 'success')
        
        log_business_event(f"admin_user_status_toggle", {
            "admin_id": session.get('user_id'),
            "target_user_id": user_id,
            "new_status": new_status,
            "user_phone": user['phone']
        })
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/update_wallet/<int:user_id>", methods=['POST'])
@admin_required
def update_user_wallet(user_id):
    amount = request.form.get('amount', type=float)
    action = request.form.get('action')  # 'add' or 'set'
    
    if not amount or amount < 0:
        flash('Invalid amount', 'error')
        return redirect(url_for('admin_users'))
    
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        if action == 'add':
            new_balance = user['wallet'] + amount
            description = f"Admin wallet adjustment: +GHS {amount:.2f}"
        else:  # set
            new_balance = amount
            description = f"Admin wallet adjustment: Set to GHS {amount:.2f}"
        
        conn.execute('UPDATE users SET wallet = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                    (new_balance, user_id))
        
        # Log transaction
        conn.execute('''
            INSERT INTO transactions (user_id, amount, type, description, reference)
            VALUES (?, ?, 'admin_adjustment', ?, ?)
        ''', (user_id, amount if action == 'add' else amount - user['wallet'], 
              description, f"ADMIN_{int(time.time())}"))
        
        flash(f'Wallet updated successfully. New balance: GHS {new_balance:.2f}', 'success')
        
        log_business_event(f"admin_wallet_adjustment", {
            "admin_id": session.get('user_id'),
            "target_user_id": user_id,
            "amount": amount,
            "action": action,
            "new_balance": new_balance,
            "user_phone": user['phone']
        })
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/edit/<int:user_id>", methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        if request.method == 'POST':
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            email = request.form.get('email', '').strip()
            
            conn.execute('''
                UPDATE users SET first_name = ?, last_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (first_name, last_name, email, user_id))
            
            flash('User information updated successfully', 'success')
            
            log_business_event(f"admin_user_edit", {
                "admin_id": session.get('user_id'),
                "target_user_id": user_id,
                "user_phone": user['phone'],
                "updated_fields": ['first_name', 'last_name', 'email']
            })
            
            return redirect(url_for('admin_users'))
        
        return render_template('edit_user.html', user=user)

@app.route("/admin/users/export")
@admin_required
def export_users():
    format_type = request.args.get('format', 'csv')
    
    with get_db() as conn:
        users = conn.execute('''
            SELECT u.*, 
                   COUNT(t.id) as transaction_count,
                   COALESCE(SUM(t.amount), 0) as total_spent
            FROM users u
            LEFT JOIN transactions t ON u.id = t.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''').fetchall()
    
    if format_type == 'csv':
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Phone', 'First Name', 'Last Name', 'Email', 'Wallet Balance', 
                        'Status', 'Admin', 'Transaction Count', 'Total Spent', 'Created At'])
        
        # Write data
        for user in users:
            status = 'Active' if user['is_active'] else 'Inactive'
            if user['is_admin']:
                status = 'Admin'
            
            writer.writerow([
                user['id'],
                user['phone'],
                user['first_name'] or '',
                user['last_name'] or '',
                user['email'] or '',
                f"GHS {user['wallet']:.2f}",
                status,
                'Yes' if user['is_admin'] else 'No',
                user['transaction_count'],
                f"GHS {user['total_spent']:.2f}",
                user['created_at']
            ])
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=users_export_{int(time.time())}.csv'
        return response
    
    flash('Unsupported export format', 'error')
    return redirect(url_for('admin_users'))

@app.route("/admin/bookings")
@admin_required
def admin_bookings():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', 'all', type=str)
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        # Build query conditions
        conditions = []
        params = []
        
        if search:
            conditions.append("(o.service_name LIKE ? OR u.phone LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param, search_param])
        
        if status_filter == 'pending':
            conditions.append("o.status = 'pending'")
        elif status_filter == 'confirmed':
            conditions.append("o.status = 'confirmed'")
        elif status_filter == 'completed':
            conditions.append("o.status = 'completed'")
        elif status_filter == 'cancelled':
            conditions.append("o.status = 'cancelled'")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        # Get total count
        count_query = f'''
            SELECT COUNT(*) as count FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE {where_clause}
        '''
        total = conn.execute(count_query, params).fetchone()['count']
        
        # Get bookings with user info
        bookings_query = f'''
            SELECT o.*, u.phone, u.first_name, u.last_name, u.email, s.name as service_name
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            LEFT JOIN services s ON o.service_id = s.id
            WHERE {where_clause}
            ORDER BY o.created_at DESC 
            LIMIT ? OFFSET ?
        '''
        params.extend([per_page, offset])
        bookings = conn.execute(bookings_query, params).fetchall()
        
        # Get statistics
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_bookings,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_bookings,
                COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed_bookings,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_bookings,
                COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_bookings,
                COUNT(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 END) as bookings_this_week,
                AVG(CAST(total_amount AS REAL)) as avg_booking_value
            FROM orders
        ''').fetchone()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template("admin_bookings.html", 
                         bookings=bookings,
                         current_page=page,
                         total_pages=total_pages,
                         search=search,
                         status_filter=status_filter,
                         stats=stats)

@app.route("/admin/bookings/update_status/<int:booking_id>", methods=['POST'])
@admin_required
def update_booking_status(booking_id):
    new_status = request.form.get('status')
    
    if new_status not in ['pending', 'completed', 'cancelled']:
        flash('Invalid status', 'error')
        return redirect(url_for('admin_bookings'))
    
    with get_db() as conn:
        # Get booking with user and service details
        booking = conn.execute('''
            SELECT o.*, u.phone, u.first_name, u.last_name, s.name as service_name
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            LEFT JOIN services s ON o.service_id = s.id
            WHERE o.id = ?
        ''', (booking_id,)).fetchone()
        
        if not booking:
            flash('Booking not found', 'error')
            return redirect(url_for('admin_bookings'))
        
        old_status = booking['status']
        conn.execute('UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                    (new_status, booking_id))
        
        # Send notification to user based on status change
        if new_status == 'completed' and old_status != 'completed':
            # Create notification for completed booking
            conn.execute('''
                INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (booking['user_id'], 'booking_completed', 
                  'Service Completed! 🎉', 
                  f'Great news! Your {booking["service_name"]} service has been completed. Thank you for choosing RazilHub!'))
            
            flash(f'✅ Booking completed and user notified!', 'success')
            
        elif new_status == 'cancelled' and old_status != 'cancelled':
            # Create notification for cancelled booking
            conn.execute('''
                INSERT INTO notifications (user_id, type, title, message, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (booking['user_id'], 'booking_cancelled', 
                  'Booking Cancelled', 
                  f'Your {booking["service_name"]} booking has been cancelled. Please contact support if you have any questions.'))
            
            flash(f'❌ Booking cancelled and user notified!', 'warning')
        
        status_text = new_status.title()
        if new_status not in ['completed', 'cancelled']:
            flash(f'Booking status updated to {status_text}', 'info')
        
        log_business_event(f"admin_booking_status_update", {
            "admin_id": session.get('user_id'),
            "booking_id": booking_id,
            "old_status": old_status,
            "new_status": new_status,
            "service_name": booking['service_name'],
            "user_phone": booking['phone']
        })
    
    return redirect(url_for('admin_bookings'))

@app.route("/admin/bookings/confirm/<int:booking_id>", methods=['POST'])
@admin_required
def confirm_booking(booking_id):
    """Confirm booking and notify user that workers are on their way"""
    
    with get_db() as conn:
        # Get booking with user and service details
        booking = conn.execute('''
            SELECT o.*, u.phone, u.first_name, u.last_name, s.name as service_name
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            LEFT JOIN services s ON o.service_id = s.id
            WHERE o.id = ?
        ''', (booking_id,)).fetchone()
        
        if not booking:
            flash('Booking not found', 'error')
            return redirect(url_for('admin_bookings'))
        
        if booking['status'] != 'pending':
            flash('Only pending bookings can be confirmed', 'error')
            return redirect(url_for('admin_bookings'))
        
        # Update booking status to confirmed (in_progress)
        conn.execute('UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
                    ('confirmed', booking_id))
        
        # Create notification for user
        conn.execute('''
            INSERT INTO notifications (user_id, type, title, message, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (booking['user_id'], 'booking_confirmed', 
              'Workers On The Way! 🚗', 
              f'Great news! Your {booking["service_name"]} service has been confirmed. Our workers are now on their way to your location. Expected arrival: 15-30 minutes.'))
        
        flash(f'✅ Booking confirmed! User notified that workers are on their way.', 'success')
        
        log_business_event(f"admin_booking_confirmed", {
            "admin_id": session.get('user_id'),
            "booking_id": booking_id,
            "service_name": booking['service_name'],
            "user_phone": booking['phone']
        })
    
    return redirect(url_for('admin_bookings'))

@app.route("/notifications")
@login_required
def user_notifications():
    """User notifications page"""
    with get_db() as conn:
        notifications = conn.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (session.get('user_id'),)).fetchall()
        
        # Mark notifications as read
        conn.execute('UPDATE notifications SET is_read = TRUE WHERE user_id = ?', 
                    (session.get('user_id'),))
    
    return render_template("notifications.html", notifications=notifications)

@app.route("/api/notifications/count")
def notification_count():
    """Get notification count for current user"""
    if 'user_id' not in session:
        return jsonify({"count": 0})
    
    with get_db() as conn:
        count = conn.execute("""
            SELECT COUNT(*) as count FROM notifications 
            WHERE user_id = ? AND is_read = FALSE
        """, (session['user_id'],)).fetchone()
        
        return jsonify({"count": count['count'] if count else 0})

@app.route("/api/notifications/recent")
def recent_notifications():
    """Get recent notifications for dropdown"""
    if 'user_id' not in session:
        return jsonify({"notifications": []})
    
    with get_db() as conn:
        notifications = conn.execute("""
            SELECT * FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        """, (session['user_id'],)).fetchall()
        
        return jsonify({"notifications": [dict(n) for n in notifications]})

@app.route("/api/notifications/mark-all-read", methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications as read for current user"""
    if 'user_id' not in session:
        return jsonify({"success": False})
    
    with get_db() as conn:
        conn.execute("""
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE user_id = ? AND is_read = FALSE
        """, (session['user_id'],))
    
    return jsonify({"success": True})

@app.route("/admin/transactions")
@admin_required
def admin_transactions():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    # Get total count
    total = conn.execute('SELECT COUNT(*) as count FROM transactions').fetchone()['count']
    
    # Get transactions
    transactions = conn.execute('''
        SELECT t.*, u.phone FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()
    
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template("admin_transactions.html", 
                         transactions=transactions,
                         current_page=page,
                         total_pages=total_pages)

# ----------------------------
# API ENDPOINTS
# ----------------------------
@app.route("/api/user/balance")
@login_required
def api_user_balance():
    balance = get_user_wallet(session["user_id"])
    return jsonify({"balance": balance, "currency": "GHS"})

@app.route("/api/transactions")
@login_required
def api_transactions():
    conn = get_db_connection()
    transactions = conn.execute('''
        SELECT * FROM transactions WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT 50
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify([dict(transaction) for transaction in transactions])

@app.route("/api/services")
def api_services():
    category = request.args.get('category')
    conn = get_db_connection()
    
    if category:
        services = conn.execute('SELECT * FROM services WHERE category = ? AND is_active = TRUE', (category,)).fetchall()
    else:
        services = conn.execute('SELECT * FROM services WHERE is_active = TRUE').fetchall()
    
    conn.close()
    return jsonify([dict(service) for service in services])

# ----------------------------
# HEALTH CHECK ENDPOINT
# ----------------------------
@app.route("/health")
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connection
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

# ----------------------------
# ERROR HANDLERS
# ----------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# ----------------------------
# MAIN ENTRY POINT
# ----------------------------
if __name__ == "__main__":
    try:
        print("🚀 Starting RazilHub Mobile Data Vending Platform...")
        print("📍 Application will be available at: http://127.0.0.1:5001")
        print("🔧 Admin login: 0540000000 (use displayed OTP)")
        print("💡 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        app.run(
            debug=True,
            port=5001,
            host='127.0.0.1',
            use_reloader=True,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        logging.error(f"Server startup failed: {e}")
        raise