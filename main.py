import os
import psycopg2
from psycopg2 import errors
import json
import random
import time
import logging
from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, Response, stream_with_context, flash
from threading import Thread, Event
from contextlib import contextmanager
from psycopg2 import pool
from psycopg2.errors import UniqueViolation
import pytz
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse
from game_worker import run_game
import threading
from shared import get_db_connection
import string
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_from_directory
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta, timezone
from game_worker import run_game

now = datetime.now()
now_str = now.strftime("%Y-%m-%d %H:%M:%S")  # convert to string
date_part = now_str.split(" ")[0]  # now you can safely split

# --- Configuration & logging ---
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Required environment vars
DATABASE_URL = os.getenv('DATABASE_URL')
ADMIN_DATABASE = os.getenv('ADMIN_DATABASE')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

if not all([ADMIN_USERNAME, ADMIN_PASSWORD]):
    raise RuntimeError("Missing required environment variables: ADMIN_USERNAME and ADMIN_PASSWORD must be set.")

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiter that prefers logged-in user id, otherwise IP
def rate_limit_key():
    return session.get("user_id") or get_remote_address()

limiter = Limiter(
    key_func=rate_limit_key,
    default_limits=[]
)
limiter.init_app(app)

stop_event = threading.Event()

# --- Utility functions ---
def hashed_password(password: str) -> str:
    return generate_password_hash(password.strip(), method='pbkdf2:sha256')

def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password.strip())

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

def generate_game_code():
    import string
    return ''.join(random.choices(string.ascii_uppercase + '0123456789', k=6))

# --- Database initialization ---
def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                wallet NUMERIC DEFAULT 0.0
            )
        """)        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_activity (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                ip_address TEXT,
                path TEXT,
                method TEXT,
                user_agent TEXT,
                referrer TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS visit_logs (
                id SERIAL PRIMARY KEY,
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                path TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS game_queue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id SERIAL PRIMARY KEY,
                game_code TEXT UNIQUE,
                timestamp TIMESTAMP,
                num_users INTEGER,
                total_amount NUMERIC,
                deduction NUMERIC,
                winner TEXT,
                winner_amount NUMERIC,
                outcome_message TEXT,
                status TEXT DEFAULT 'upcoming'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('deposit', 'withdrawal', 'game_entry', 'win')),
                amount NUMERIC NOT NULL,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS allowed_users (
                username TEXT PRIMARY KEY
            )
        """)
# Withdrawal requests
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS withdrawal_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                requested_amount NUMERIC NOT NULL,
                withdrawal_fee NUMERIC NOT NULL,
                net_amount NUMERIC NOT NULL,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'completed')),
                request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_time TIMESTAMP NULL,
                processed_by INTEGER NULL,
                admin_notes TEXT,
                receipt_code TEXT UNIQUE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(processed_by) REFERENCES admins(id) ON DELETE SET NULL
            )
        """)
        # Deposit requests table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deposit_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                amount NUMERIC NOT NULL,
                voucher_code TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'rejected')),
                request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_time TIMESTAMP NULL,
                processed_by INTEGER NULL,
                admin_notes TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(processed_by) REFERENCES admins(id) ON DELETE SET NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_suspensions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                suspension_end TIMESTAMP NOT NULL,
                suspended_by INTEGER,
                suspended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(suspended_by) REFERENCES admins(id) ON DELETE SET NULL
            )
        """)           
        # Withdrawal limits (tracks user withdrawal frequency)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS withdrawal_limits (
                user_id INTEGER PRIMARY KEY,
                last_withdrawal_time TIMESTAMP NULL,
                daily_attempts INTEGER DEFAULT 0,
                last_attempt_time TIMESTAMP NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # Withdrawal fees (defines withdrawal fee brackets)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS withdrawal_fees (
                id SERIAL PRIMARY KEY,
                min_amount NUMERIC NOT NULL,
                max_amount NUMERIC NOT NULL,
                fee_amount NUMERIC DEFAULT 0,
                fee_percentage NUMERIC DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)        
        # Win earnings (tracks usersâ€™ winnings from games)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS win_earnings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                game_code TEXT NOT NULL,
                amount NUMERIC NOT NULL,
                earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_withdrawn BOOLEAN DEFAULT FALSE,
                withdrawn_at TIMESTAMP NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("SELECT COUNT(*) FROM withdrawal_fees")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO withdrawal_fees (min_amount, max_amount, fee_amount, fee_percentage, is_active) 
                VALUES 
                (100, 1000, 10, 0, TRUE),
                (1001, 5000, 25, 0, TRUE),
                (5001, 20000, 50, 0, TRUE),
                (20001, 50000, 100, 0, TRUE)
            """)        
        conn.commit()
        
        # Add performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_game_queue_user_id ON game_queue(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_id ON users(id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON results(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_id ON withdrawal_requests(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deposit_requests_user_id ON deposit_requests(user_id)")        
        
        cursor.execute("SELECT id FROM admins WHERE username = %s LIMIT 1", (ADMIN_USERNAME,))
        exists = cursor.fetchone()
        if not exists:
            hashed = hashed_password(ADMIN_PASSWORD)
            cursor.execute("INSERT INTO admins (username, hashed_password) VALUES (%s, %s)", (ADMIN_USERNAME, hashed))
            conn.commit()
            print('Admin created successfully')

init_db()

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for('login'))
            
            if role is not None:
                user_role = session.get('user_role', 'user')
                
                # Define role hierarchy (admin > moderator > user)
                role_hierarchy = {'user': 0, 'moderator': 1, 'admin': 2}
                required_level = role_hierarchy.get(role, 0)
                user_level = role_hierarchy.get(user_role, 0)
                
                if user_level < required_level:
                    flash(f"Access denied. {role.title()} role required.", "error")
                    return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Wallet & transactions ---
def validate_wallet_sufficient(user_id, amount):
    """Check if user has sufficient wallet balance"""
    try:
        balance = get_wallet_balance(user_id)
        return balance >= amount
    except Exception as e:
        logging.error(f"Error validating wallet for user {user_id}: {e}")
        return False

def get_wallet_balance(user_id):
    if not user_id:
        return 0.0
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT wallet FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            if result and result[0] is not None:
                return float(result[0])
            else:
                logging.warning(f"User {user_id} not found or has null wallet balance")
                return 0.0
    except Exception as e:
        logging.error(f"Error getting wallet balance for user {user_id}: {e}")
        return 0.0

def update_wallet(user_id, amount):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (amount, user_id))
        conn.commit()

def log_transaction(user_id, transaction_type, amount):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO transactions (user_id, type, amount, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user_id, transaction_type, amount, get_timestamp()))
            conn.commit()
    except Exception as e:
        logging.error(f"Error in log_transaction(): {e}")

# --- Logging visitors / activity ---
def log_visit_entry(ip_address, user_agent, referrer=None, page=None, timestamp=None):
    # Ensure timestamp is always a string
    if timestamp is None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    elif isinstance(timestamp, datetime):
        ts = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
    else:
        ts = str(timestamp)

    # Insert visit log into the database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO visit_logs (ip_address, user_agent, referrer, page, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (ip_address, user_agent, referrer, page, ts))
        conn.commit()

@app.before_request
def log_user_activity():
    if request.path.startswith("/static"):
        return
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ua = request.headers.get("User-Agent", "")
        ref = request.referrer
        path = request.path
        method = request.method
        username = session.get("username")
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO user_activity (username, ip_address, path, method, user_agent, referrer)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, ip, path, method, ua, ref))
            conn.commit()
    except Exception as e:
        logging.debug(f"Failed to log user activity: {e}")

@app.before_request
def log_visitor():
    if request.path.startswith("/static"):
        return
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        agent = request.headers.get('User-Agent', 'unknown')
        ref = request.referrer or 'direct'
        path = request.path
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_visit_entry(ip, agent, ref, path, ts)
    except Exception as e:
        logging.debug(f"Visitor log error: {e}")

# --- Static files route (exposed) ---
@csrf.exempt
@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


#Routes
@app.route("/")
@limiter.limit("5 per hour")
def index():
    if 'user_id' in session:
        wallet_balance = get_wallet_balance(session['user_id'])
    else:
        wallet_balance = 0.0
        
    return render_template_string(base_html, 
                                wallet_balance=wallet_balance,
                                session=session)

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, hashed_password FROM admins WHERE username = %s", (username,))
            admin = cursor.fetchone()

            if admin and verify_password(admin[1], password):
                session["admin_id"] = admin[0]
                session["is_admin"] = True
                response = redirect(url_for("admin_dashboard"))
                response.headers['X-Frame-Options'] = 'SAMEORIGIN'
                return response
            else:
                return render_template_string(admin_login_html, error="Invalid admin credentials.")

    return render_template_string(admin_login_html, error=None)                
                
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("2 per minute")
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Rely on CSRFProtect for CSRF verification (token injected into template).
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                response = redirect(url_for("index"))
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
                return response
            else:
                return render_template_string(login_html, error="Invalid username or password.", message=None)             
    # âœ… Always return something for GET
    return render_template_string(login_html, error=None, message=None)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("2 per minute")
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        # Basic validation
        if not all([email, username, password]):
            return render_template_string(register_html, error="All fields are required")

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Check if username is allowed
            cursor.execute("SELECT 1 FROM allowed_users WHERE username = %s", (username,))
            if cursor.fetchone() is None:
                return render_template_string(register_html, error="Username is not allowed")

            # Hash password
            hashed_password = generate_password_hash(password)

            try:
                # Insert new user
                cursor.execute(
                    "INSERT INTO users (email, username, hashed_password) VALUES (%s, %s, %s)",
                    (email, username, hashed_password)
                )

                # Remove the username from allowed_users so it can't be reused
                cursor.execute("DELETE FROM allowed_users WHERE username = %s", (username,))

                conn.commit()
                return redirect(url_for("login"))

            except UniqueViolation:
                conn.rollback()
                return render_template_string(register_html, error="Email or username already exists")

            except Exception as e:
                conn.rollback()
                logging.error(f"Database error during registration: {e}")
                return render_template_string(register_html, error="Something went wrong. Try again later.")

    # GET request â€” show registration form
    return render_template_string(register_html)


@app.route("/offline")
def offline():
    return """
    <html><head><title>Offline</title></head>
    <body style="text-align:center;padding:40px;font-family:sans-serif;">
        <h1>You're Offline</h1>
        <p>It looks like you don't have an internet connection.</p>
        <p>Try again when you're back online.</p>
    </body></html>
    """
    
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/service-worker.js')
def sw():
    return send_from_directory('static', 'service-worker.js')
    
@app.route("/privacy")
@limiter.limit("2 per hour")
def privacy():
    return render_template_string(PRIVACY_CONTENT)

@app.route("/terms")
@limiter.limit("2 per hour")
def terms():
    return render_template_string(TERMS_CONTENT)

@app.route("/docs")
@limiter.limit("2  per hour")
def docs():
    return render_template_string(DOCS_CONTENT)
    

@app.route("/logout")
@login_required()
@limiter.limit("3 per hour")
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("index"))

@app.route("/stream")
def stream():
    def event_stream():
        while True:
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT game_code, status, timestamp, num_users, winner, winner_amount, outcome_message
                        FROM results
                        ORDER BY timestamp DESC
                        LIMIT 1
                    """)
                    game = cursor.fetchone()

                    if game:
                        data = {
                            "game_code": game[0],
                            "status": game[1] if game[1] else "unknown",
                            "timestamp": game[2].strftime("%Y-%m-%d %H:%M:%S") if game[2] else "N/A",
                            "num_users": game[3] if isinstance(game[3], int) else 0,
                            "winner": game[4] if game[4] else "N/A",
                            "winner_amount": float(game[5]) if isinstance(game[5], (int, float)) else 0.0,
                            "outcome_message": game[6] if isinstance(game[6], str) else "",
                        }
                        yield f"data: {json.dumps(data)}\n\n"

                time.sleep(1)

            except psycopg2.Error as e:
                logging.error(f"Database error in streaming: {e}")
                break

            except GeneratorExit:
                logging.info("Client disconnected from stream.")
                break

            except Exception as e:
                logging.error(f"Unexpected error in event stream: {e}")
                break

    return Response(stream_with_context(event_stream()), content_type="text/event-stream")


@app.route("/game_data")
@login_required()
def game_data():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get upcoming game
            cursor.execute("SELECT game_code, timestamp FROM results WHERE status = 'upcoming' ORDER BY timestamp DESC LIMIT 1")
            upcoming_game = cursor.fetchone()
            upcoming_game_data = {
                "game_code": upcoming_game[0] if upcoming_game else "N/A",
                "timestamp": upcoming_game[1] if upcoming_game else "N/A",
                "outcome_message": "Starting soon..."
            } if upcoming_game else None

            # Get in-progress game
            cursor.execute("""
                SELECT game_code, timestamp, num_users, total_amount, winner, winner_amount 
                FROM results 
                WHERE status = 'in progress' 
                ORDER BY timestamp DESC LIMIT 1
            """)
            in_progress_game = cursor.fetchone()
            in_progress_game_data = {
                "game_code": in_progress_game[0] if in_progress_game else "N/A",
                "timestamp": in_progress_game[1] if in_progress_game else "N/A",
                "num_users": in_progress_game[2] if in_progress_game else 0,
                "total_amount": float(in_progress_game[3]) if in_progress_game and in_progress_game[3] else 0.0,
                "winner": in_progress_game[4] if in_progress_game else "N/A",
                "winner_amount": float(in_progress_game[5]) if in_progress_game and in_progress_game[5] else 0.0,
                "status": "in progress",
                "outcome_message": "Game in progress"
            } if in_progress_game else None

            # Get completed games
            cursor.execute("""
                SELECT game_code, timestamp, num_users, total_amount, deduction, winner, winner_amount
                FROM results
                WHERE status = 'completed'
                ORDER BY timestamp DESC
                LIMIT 50
            """)
            completed_games = cursor.fetchall()

            completed_games_data = [
                {
                    "game_code": game[0],
                    "timestamp": game[1],
                    "num_users": game[2],
                    "total_amount": f"Ksh. {float(game[3]):.2f}" if game[3] else "Ksh. 0.00",
                    "deduction": f"Ksh. {float(game[4]):.2f}" if game[4] else "Ksh. 0.00",
                    "winner": game[5] if game[5] else "N/A",
                    "winner_amount": f"Ksh. {float(game[6]):.2f}" if game[6] else "Ksh. 0.00",
                    "outcome_message": f"Winner: {game[5]}" if game[5] else "No winner"
                }
                for game in completed_games
            ]

            # Check if current user is queued using your game_queue table
            current_user_queued = False
            if session.get('user_id'):
                cursor.execute("SELECT COUNT(*) FROM game_queue WHERE user_id = %s", (session['user_id'],))
                current_user_queued = cursor.fetchone()[0] > 0

        response_data = {
            "upcoming_game": upcoming_game_data or {
                "game_code": "N/A", 
                "timestamp": "N/A", 
                "outcome_message": "No upcoming games"
            },
            "in_progress_game": in_progress_game_data,
            "completed_games": completed_games_data,
            "current_user_queued": current_user_queued
        }

        return jsonify(response_data)

    except Exception as e:
        print(f"Error in game_data: {str(e)}")
        return jsonify({
            "error": "Unable to fetch game data",
            "upcoming_game": {"game_code": "N/A", "timestamp": "N/A", "outcome_message": "Error loading"},
            "completed_games": [],
            "current_user_queued": False
        }), 500

@app.route("/play", methods=["POST"])
@login_required()
@limiter.limit("3 per minute")
def play():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index", error="You must be logged in to play."))

    wallet_balance = get_wallet_balance(user_id)
    if wallet_balance < 1.0:
        return redirect(url_for("index", error="Insufficient funds. Please deposit."))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Check if user is already in queue
            cursor.execute("SELECT user_id FROM game_queue WHERE user_id = %s", (user_id,))
            if cursor.fetchone():
                return redirect(url_for("index", message="Already enrolled in current game"))

            # DEDUCTION with balance validation
            cursor.execute("UPDATE users SET wallet = wallet - 1.0 WHERE id = %s AND wallet >= 1.0", (user_id,))
            
            # Verify deduction was successful
            if cursor.rowcount == 0:
                # Re-check balance to provide accurate error message
                cursor.execute("SELECT wallet FROM users WHERE id = %s", (user_id,))
                current_balance = cursor.fetchone()[0]
                return redirect(url_for("index", error=f"Insufficient funds. Current balance: Ksh. {current_balance:.2f}"))

            # Record transaction
            cursor.execute("INSERT INTO transactions (user_id, type, amount, timestamp) VALUES (%s, 'game_entry', %s, %s)",
                          (user_id, -1.0, get_timestamp()))
            
            # Add to game queue
            cursor.execute("INSERT INTO game_queue (user_id, timestamp) VALUES (%s, %s)",
                          (user_id, get_timestamp()))
            conn.commit()

            return redirect(url_for("index", message="Successfully enrolled in the next game!"))

    except psycopg2.IntegrityError:
        return redirect(url_for("index", message="Already enrolled in current game"))
    except psycopg2.Error as e:
        logging.error(f"Database error during enrollment: {str(e)}") 
        return redirect(url_for("index", error="An error occurred while enrolling. Please try again."))
    except Exception as e:
        logging.error(f"Unexpected error during enrollment: {str(e)}")
        return redirect(url_for("index", error="An unexpected error occurred. Please try again."))

@app.route("/admin/add_allowed_user", methods=["POST"])
@login_required(role='admin')
@limiter.limit("50 per hour")
def admin_add_allowed_user():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Unauthorized access."))

    username = request.form.get("allowed_username")

    if not username:
        return redirect(url_for("admin_dashboard", error="Username is required."))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO allowed_users (username) VALUES (%s) ON CONFLICT DO NOTHING",
                (username,)
            )
            conn.commit()
            return redirect(url_for("admin_dashboard", message="Allowed username added successfully."))
        except Exception as e:
            logging.error(f"Error adding allowed user: {e}")
            return redirect(url_for("admin_dashboard", error="Failed to add allowed username."))

@app.route("/admin/dashboard")
@login_required(role='admin')
@limiter.limit("5 per hour")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Please log in as an admin."))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id ASC")
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM user_activity ORDER BY timestamp DESC LIMIT 100")
        logs = cursor.fetchall()

    return render_template_string(
        admin_html,
        users=users,
        logs=logs,
        error=request.args.get("error"),
        message=request.args.get("message")
    )  
        
@app.route("/admin/visitor_log")
@login_required(role='admin')
@limiter.limit("5 per hour")
def view_visits():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Unauthorized access."))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address, user_agent, referrer, path, timestamp
            FROM visit_logs
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        logs = cursor.fetchall()

    return render_template_string("""
    <h2>Recent Site Visits</h2>
    <table border="1" cellpadding="5">
        <tr><th>IP Address</th><th>User Agent</th><th>Referrer</th><th>Path</th><th>Time</th></tr>
        {% for log in logs %}
            <tr>
                <td>{{ log[0] }}</td>
                <td>{{ log[1] }}</td>
                <td>{{ log[2] }}</td>
                <td>{{ log[3] }}</td>
                <td>{{ log[4] }}</td>
            </tr>
        {% endfor %}
    </table>
    <br>
    <a href="/admin/dashboard">â† Back to Admin Dashboard</a>
    """, logs=logs)

@app.route("/admin/logout")
@login_required(role='admin')
@limiter.limit("3 per hour")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))
    
@app.route('/robots.txt')
def robots_txt():
    return (
        "User-agent: *\nDisallow:\n",
        200,
        {'Content-Type': 'text/plain'}
    )

#OLD CODE
@app.route("/admin/update_wallet", methods=["POST"])
@login_required(role='admin')
@limiter.limit("50 per hour")
def admin_update_wallet():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Unauthorized access."))

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    action = request.form.get("action")

    try:
        amount = float(amount)
        if action not in ["deposit", "withdraw"]:
            return redirect(url_for("admin_dashboard", error="Invalid action."))

        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            if not cursor.fetchone():
                return redirect(url_for("admin_dashboard", error="User not found."))

            if action == "deposit":
                update_wallet(user_id, amount)
                log_transaction(user_id, "deposit", amount)

            elif action == "withdraw":
                wallet_balance = get_wallet_balance(user_id)
                if wallet_balance is None or wallet_balance < amount:
                    return redirect(url_for("admin_dashboard", error="Insufficient balance for withdrawal."))

                update_wallet(user_id, -amount)
                log_transaction(user_id, "withdrawal", amount)

        return redirect(url_for("admin_dashboard", message="Wallet updated successfully."))

    except ValueError:
        return redirect(url_for("admin_dashboard", error="Invalid amount. Please enter a valid number."))
        
###########
@app.route("/cashbook")
@login_required(role='admin')
@limiter.limit("5 per hour")
def cashbook():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Unauthorized access."))
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Total Gross Profit (ALWAYS POSITIVE) - Simple query only
            cursor.execute("""
                SELECT COALESCE(SUM(deduction), 0) 
                FROM results 
                WHERE status = 'completed' AND deduction > 0
            """)
            result = cursor.fetchone()
            total_gross_profit = float(result[0]) if result and result[0] is not None else 0.0
            total_gross_profit = max(0.0, total_gross_profit)  # Ensure no negative
            
            # 2. Total Profitable Games Count
            cursor.execute("""
                SELECT COUNT(*) 
                FROM results 
                WHERE status = 'completed' AND deduction > 0
            """)
            result = cursor.fetchone()
            total_profitable_games = int(result[0]) if result and result[0] is not None else 0
            
            # 3. Recent Profit Transactions (Last 5 only)
            cursor.execute("""
                SELECT 
                    game_code,
                    timestamp,
                    num_users,
                    total_amount,
                    deduction
                FROM results 
                WHERE status = 'completed'
                AND deduction > 0
                ORDER BY timestamp DESC
                LIMIT 5
            """)
            recent_profits = cursor.fetchall()
            
            # Convert to safe data types
            safe_recent_profits = []
            for profit in recent_profits:
                safe_recent_profits.append((
                    str(profit[0]) if profit[0] else "N/A",
                    profit[1] if profit[1] else "N/A",
                    int(profit[2]) if profit[2] is not None else 0,
                    float(profit[3]) if profit[3] is not None else 0.0,
                    float(profit[4]) if profit[4] is not None else 0.0
                ))
        
        cashbook_data = {
            "total_gross_profit": total_gross_profit,
            "total_profitable_games": total_profitable_games,
            "recent_profits": safe_recent_profits
        }
        
        return render_template_string(cashbook_html, data=cashbook_data)
        
    except Exception as e:
        logging.error(f"Cashbook error: {e}")
        # Return safe default data on error
        cashbook_data = {
            "total_gross_profit": 0.0,
            "total_profitable_games": 0,
            "recent_profits": []
        }
        return render_template_string(cashbook_html, data=cashbook_data)
        
###############
        
@app.route("/withdraw", methods=["GET", "POST"])
@login_required()
@limiter.limit("3 per hour")
def withdraw_request():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session.get('username')
    
    # Check if user is suspended
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT suspension_end, reason 
            FROM user_suspensions 
            WHERE user_id = %s AND suspension_end > CURRENT_TIMESTAMP
            ORDER BY suspended_at DESC LIMIT 1
        """, (user_id,))
        suspension = cursor.fetchone()
        
        if suspension:
            suspension_end = suspension[0]
            reason = suspension[1]
            return render_template_string(withdraw_html, 
                error=f"Account suspended until {suspension_end}. Reason: {reason}",
                can_withdraw=False)

    if request.method == "POST":
        try:
            amount = float(request.form.get('amount', 0))
            
            # Validation checks
            if amount < 100:
                return render_template_string(withdraw_html, 
                    error="Minimum withdrawal amount is KES 100",
                    can_withdraw=True)
            
            if amount > 50000:
                return render_template_string(withdraw_html, 
                    error="Maximum withdrawal amount is KES 50,000",
                    can_withdraw=True)

            # Calculate withdrawal fee
            cursor.execute("""
                SELECT fee_amount 
                FROM withdrawal_fees 
                WHERE %s BETWEEN min_amount AND COALESCE(max_amount, 999999)
                AND is_active = TRUE
                ORDER BY min_amount
                LIMIT 1
            """, (amount,))
            fee_result = cursor.fetchone()
            withdrawal_fee = fee_result[0] if fee_result else 10
            net_amount = amount - withdrawal_fee

            # Check wallet balance from wins only
            cursor.execute("""
                SELECT COALESCE(SUM(amount), 0) 
                FROM win_earnings 
                WHERE user_id = %s AND is_withdrawn = FALSE
            """, (user_id,))
            available_balance = cursor.fetchone()[0]
            
            if amount > available_balance:
                return render_template_string(withdraw_html, 
                    error=f"Insufficient win earnings. Available: KES {available_balance:.2f}",
                    can_withdraw=True)
            
            # Check 24-hour withdrawal limit
            cursor.execute("""
                SELECT last_withdrawal_time 
                FROM withdrawal_limits 
                WHERE user_id = %s
            """, (user_id,))
            limit_data = cursor.fetchone()
            
            if limit_data and limit_data[0]:
                last_withdrawal = limit_data[0]
                time_since_last = datetime.now() - last_withdrawal
                if time_since_last.total_seconds() < 86400:
                    return render_template_string(withdraw_html, 
                        error="You can only withdraw once every 24 hours",
                        can_withdraw=True)
            
            # Check daily attempts
            cursor.execute("""
                SELECT daily_attempts, last_attempt_time 
                FROM withdrawal_limits 
                WHERE user_id = %s
            """, (user_id,))
            attempt_data = cursor.fetchone()
            
            current_time = datetime.now()
            if attempt_data:
                daily_attempts = attempt_data[0]
                last_attempt = attempt_data[1]
                
                if last_attempt and last_attempt.date() < current_time.date():
                    daily_attempts = 0
                
                if daily_attempts >= 5:
                    suspension_end = current_time + timedelta(hours=6)
                    cursor.execute("""
                        INSERT INTO user_suspensions (user_id, reason, suspension_end, suspended_by)
                        VALUES (%s, %s, %s, %s)
                    """, (user_id, "Excessive withdrawal attempts", suspension_end, 1))
                    
                    cursor.execute("""
                        UPDATE withdrawal_limits 
                        SET daily_attempts = 0 
                        WHERE user_id = %s
                    """, (user_id,))
                    
                    conn.commit()
                    return render_template_string(withdraw_html, 
                        error="Account suspended for 6 hours due to excessive attempts",
                        can_withdraw=False)
            
            # Generate receipt code
            receipt_code = f"WDL{datetime.now().strftime('%Y%m%d%H%M%S')}{user_id}"
            
            # Create withdrawal request
            cursor.execute("""
                INSERT INTO withdrawal_requests 
                (user_id, username, requested_amount, withdrawal_fee, net_amount, receipt_code)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, username, amount, withdrawal_fee, net_amount, receipt_code))
            
            # Update withdrawal limits
            if attempt_data:
                cursor.execute("""
                    UPDATE withdrawal_limits 
                    SET daily_attempts = daily_attempts + 1, last_attempt_time = %s
                    WHERE user_id = %s
                """, (current_time, user_id))
            else:
                cursor.execute("""
                    INSERT INTO withdrawal_limits (user_id, daily_attempts, last_attempt_time)
                    VALUES (%s, 1, %s)
                """, (user_id, current_time))
            
            conn.commit()
            
            # Show receipt page
            return redirect(url_for('withdrawal_receipt', receipt_code=receipt_code))
            
        except ValueError:
            return render_template_string(withdraw_html, 
                error="Invalid amount format",
                can_withdraw=True)
        except Exception as e:
            conn.rollback()
            logging.error(f"Withdrawal error: {e}")
            return render_template_string(withdraw_html, 
                error="System error. Please try again later.",
                can_withdraw=True)
    
    # GET request - show withdrawal form
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COALESCE(SUM(amount), 0) 
            FROM win_earnings 
            WHERE user_id = %s AND is_withdrawn = FALSE
        """, (user_id,))
        available_balance = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT last_withdrawal_time 
            FROM withdrawal_limits 
            WHERE user_id = %s
        """, (user_id,))
        limit_data = cursor.fetchone()
        
        can_withdraw_again = True
        if limit_data and limit_data[0]:
            time_since_last = datetime.now() - limit_data[0]
            if time_since_last.total_seconds() < 86400:
                can_withdraw_again = False
    
    return render_template_string(withdraw_html, 
        available_balance=available_balance,
        can_withdraw=can_withdraw_again,
        last_withdrawal=limit_data[0] if limit_data else None)
        

@app.route("/withdrawal_receipt/<receipt_code>")
def withdrawal_receipt(receipt_code):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM withdrawal_requests 
            WHERE receipt_code = %s AND user_id = %s
        """, (receipt_code, session['user_id']))
        withdrawal = cursor.fetchone()
        
        if not withdrawal:
            return redirect(url_for('index', error="Receipt not found"))
    
    return render_template_string(withdrawal_receipt_html, withdrawal=withdrawal)
    
@app.route("/admin/withdrawals")
@login_required(role='admin')
@limiter.limit("50 per hour")
def admin_withdrawals():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Unauthorized access."))
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT wr.*, u.email
            FROM withdrawal_requests wr
            JOIN users u ON wr.user_id = u.id
            ORDER BY wr.request_time DESC
            LIMIT 100
        """)
        withdrawals = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'pending'")
        pending_count = cursor.fetchone()[0]
    
    return render_template_string(admin_withdrawals_html, 
        withdrawals=withdrawals, 
        pending_count=pending_count)

@app.route("/admin/process_withdrawal", methods=["POST"])
@login_required(role='admin')
@limiter.limit("50 per hour")
def process_withdrawal():
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403
    
    withdrawal_id = request.form.get("withdrawal_id")
    action = request.form.get("action")
    admin_notes = request.form.get("admin_notes", "")
    
    if not withdrawal_id or not action:
        return jsonify({"error": "Missing parameters"}), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT user_id, requested_amount, status 
                FROM withdrawal_requests 
                WHERE id = %s
            """, (withdrawal_id,))
            withdrawal = cursor.fetchone()
            
            if not withdrawal:
                return jsonify({"error": "Withdrawal not found"}), 404
            
            user_id, amount, current_status = withdrawal
            
            if current_status != 'pending':
                return jsonify({"error": "Withdrawal already processed"}), 400
            
            admin_id = session.get("admin_id")
            processed_time = datetime.now()
            
            if action == 'approve':
                # Check win earnings balance
                cursor.execute("""
                    SELECT COALESCE(SUM(amount), 0) 
                    FROM win_earnings 
                    WHERE user_id = %s AND is_withdrawn = FALSE
                """, (user_id,))
                available_balance = cursor.fetchone()[0]
                
                if amount > available_balance:
                    return jsonify({"error": "Insufficient win earnings"}), 400
                
                # Mark earnings as withdrawn
                cursor.execute("""
                    UPDATE win_earnings 
                    SET is_withdrawn = TRUE, withdrawn_at = %s
                    WHERE user_id = %s AND is_withdrawn = FALSE
                """, (processed_time, user_id))
                
                # Update withdrawal request
                cursor.execute("""
                    UPDATE withdrawal_requests 
                    SET status = 'completed', processed_time = %s, 
                        processed_by = %s, admin_notes = %s
                    WHERE id = %s
                """, (processed_time, admin_id, admin_notes, withdrawal_id))
                
                # Update withdrawal limit
                cursor.execute("""
                    UPDATE withdrawal_limits 
                    SET last_withdrawal_time = %s 
                    WHERE user_id = %s
                """, (processed_time, user_id))
                
            elif action == 'reject':
                cursor.execute("""
                    UPDATE withdrawal_requests 
                    SET status = 'rejected', processed_time = %s, 
                        processed_by = %s, admin_notes = %s
                    WHERE id = %s
                """, (processed_time, admin_id, admin_notes, withdrawal_id))
            
            conn.commit()
            return jsonify({"success": True, "message": f"Withdrawal {action}ed"})
            
    except Exception as e:
        conn.rollback()
        logging.error(f"Process withdrawal error: {e}")
        return jsonify({"error": "System error"}), 500
        
@app.route("/deposit", methods=["GET", "POST"])
@login_required()
@limiter.limit("5 per hour")
def deposit_request():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session.get('username')
    
    if request.method == "POST":
        try:
            amount = float(request.form.get('amount', 0))
            
            # Validation
            if amount < 50:
                return render_template_string(deposit_html, 
                    error="Minimum deposit amount is KES 50",
                    can_deposit=True)
            
            if amount > 50000:
                return render_template_string(deposit_html, 
                    error="Maximum deposit amount is KES 50,000",
                    can_deposit=True)

            # Generate deposit voucher
            voucher_code = f"DPT{datetime.now().strftime('%Y%m%d%H%M%S')}{user_id}"
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Create deposit request
                cursor.execute("""
                    INSERT INTO deposit_requests 
                    (user_id, username, amount, voucher_code, status)
                    VALUES (%s, %s, %s, %s, 'pending')
                """, (user_id, username, amount, voucher_code))
                
                conn.commit()
            
            # Redirect to voucher page
            return redirect(url_for('deposit_voucher', voucher_code=voucher_code))
            
        except ValueError:
            return render_template_string(deposit_html, 
                error="Invalid amount format",
                can_deposit=True)
        except Exception as e:
            logging.error(f"Deposit request error: {e}")
            return render_template_string(deposit_html, 
                error="System error. Please try again.",
                can_deposit=True)
    
    # GET request - show deposit form
    return render_template_string(deposit_html, can_deposit=True)

@app.route("/deposit_voucher/<voucher_code>")
def deposit_voucher(voucher_code):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM deposit_requests 
            WHERE voucher_code = %s AND user_id = %s
        """, (voucher_code, session['user_id']))
        deposit = cursor.fetchone()
        
        if not deposit:
            return redirect(url_for('index', error="Voucher not found"))
    
    return render_template_string(deposit_voucher_html, deposit=deposit)

@app.route("/admin/process_deposit", methods=["POST"])
@login_required(role='admin')
@limiter.limit("50 per hour")
def process_deposit():
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 403
    
    deposit_id = request.form.get("deposit_id")
    action = request.form.get("action")
    admin_notes = request.form.get("admin_notes", "")
    
    if not deposit_id or not action:
        return jsonify({"error": "Missing parameters"}), 400
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT user_id, amount, status 
                FROM deposit_requests 
                WHERE id = %s
            """, (deposit_id,))
            deposit = cursor.fetchone()
            
            if not deposit:
                return jsonify({"error": "Deposit not found"}), 404
            
            user_id, amount, current_status = deposit
            
            if current_status != 'pending':
                return jsonify({"error": "Deposit already processed"}), 400
            
            admin_id = session.get("admin_id")
            processed_time = datetime.now()
            
            if action == 'approve':
                # Add funds to user wallet
                cursor.execute("""
                    UPDATE users 
                    SET wallet = wallet + %s 
                    WHERE id = %s
                """, (amount, user_id))
                
                # Record transaction
                cursor.execute("""
                    INSERT INTO transactions (user_id, type, amount, timestamp)
                    VALUES (%s, 'deposit', %s, %s)
                """, (user_id, amount, processed_time))
                
                # Update deposit request
                cursor.execute("""
                    UPDATE deposit_requests 
                    SET status = 'completed', processed_time = %s, 
                        processed_by = %s, admin_notes = %s
                    WHERE id = %s
                """, (processed_time, admin_id, admin_notes, deposit_id))
                
            elif action == 'reject':
                cursor.execute("""
                    UPDATE deposit_requests 
                    SET status = 'rejected', processed_time = %s, 
                        processed_by = %s, admin_notes = %s
                    WHERE id = %s
                """, (processed_time, admin_id, admin_notes, deposit_id))
            
            conn.commit()
            return jsonify({"success": True, "message": f"Deposit {action}ed"})
            
    except Exception as e:
        conn.rollback()
        logging.error(f"Process deposit error: {e}")
        return jsonify({"error": "System error"}), 500        
        
#NON MONETARY ADMIN FUNCTIONS
###################

admin_withdrawals_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Withdrawal Management - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(to right, #43cea2, #185a9d);
            color: white;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border-radius: 15px;
        }
        h1 {
            color: #ffcc00;
            text-align: center;
        }
        .pending-badge {
            background: #ff5722;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9rem;
            margin-left: 10px;
        }
        .withdrawal-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(255,255,255,0.1);
        }
        .withdrawal-table th, .withdrawal-table td {
            padding: 12px;
            border: 1px solid #444;
            text-align: left;
        }
        .withdrawal-table th {
            background: rgba(76, 175, 80, 0.3);
            color: #ffcc00;
        }
        .status-pending { color: #ff9800; font-weight: bold; }
        .status-completed { color: #4CAF50; font-weight: bold; }
        .status-rejected { color: #f44336; font-weight: bold; }
        .action-buttons {
            display: flex;
            gap: 5px;
        }
        .btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
        }
        .btn-approve { background: #4CAF50; color: white; }
        .btn-reject { background: #f44336; color: white; }
        .btn:disabled {
            background: #666;
            cursor: not-allowed;
        }
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Withdrawal Management <span class="pending-badge">{{ pending_count }} Pending</span></h1>
        
        <table class="withdrawal-table">
            <thead>
                <tr>
                    <th>Receipt Code</th>
                    <th>User</th>
                    <th>Requested</th>
                    <th>Fee</th>
                    <th>Net Amount</th>
                    <th>Status</th>
                    <th>Request Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for w in withdrawals %}
                <tr>
                    <td><strong>{{ w[11] }}</strong></td>
                    <td>{{ w[2] }}<br><small>{{ w[12] }}</small></td>
                    <td>KES {{ "%.2f"|format(w[3]) }}</td>
                    <td>KES {{ "%.2f"|format(w[4]) }}</td>
                    <td><strong>KES {{ "%.2f"|format(w[5]) }}</strong></td>
                    <td class="status-{{ w[6] }}">{{ w[6]|upper }}</td>
                    <td>{{ w[7].strftime('%Y-%m-%d %H:%M') }}</td>
                    <td class="action-buttons">
                        {% if w[6] == 'pending' %}
                        <button class="btn btn-approve" onclick="processWithdrawal({{ w[0] }}, 'approve')">Approve</button>
                        <button class="btn btn-reject" onclick="processWithdrawal({{ w[0] }}, 'reject')">Reject</button>
                        {% else %}
                        <button class="btn" disabled>Processed</button>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div class="back-link">
            <a href="/admin/dashboard">â† Back to Admin Dashboard</a>
        </div>
    </div>

    <script>
    function processWithdrawal(withdrawalId, action) {
        const adminNotes = prompt('Enter admin notes:') || '';
        
        fetch('/admin/process_withdrawal', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `withdrawal_id=${withdrawalId}&action=${action}&admin_notes=${encodeURIComponent(adminNotes)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Withdrawal ' + action + 'ed successfully');
                location.reload();
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            alert('System error: ' + error);
        });
    }
    </script>
</body>
</html>
"""             
       
withdraw_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Withdraw Earnings - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: rgba(0, 0, 0, 0.9);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 90%;
        }
        h1 {
            color: #ffcc00;
            text-align: center;
            margin-bottom: 20px;
        }
        .balance-display {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }
        .balance-amount {
            font-size: 2rem;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #ffcc00;
            font-weight: bold;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #333;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: white;
            font-size: 1rem;
            box-sizing: border-box;
        }
        input:focus {
            border-color: #ffcc00;
            outline: none;
        }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #ffcc00, #ff9900);
            color: #333;
            border: none;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255, 204, 0, 0.4);
        }
        button:disabled {
            background: #666;
            cursor: not-allowed;
        }
        .error {
            background: #d32f2f;
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .fee-info {
            background: rgba(255, 204, 0, 0.1);
            border: 1px solid #ffcc00;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .rules {
            margin-top: 25px;
            padding: 15px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
        }
        .rules h3 {
            color: #ffcc00;
            margin-bottom: 10px;
        }
        .rules ul {
            padding-left: 20px;
        }
        .rules li {
            margin-bottom: 8px;
            color: #ccc;
        }
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ðŸ’° Withdraw Earnings</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <div class="balance-display">
            <div>Available Win Earnings</div>
            <div class="balance-amount">KES {{ "%.2f"|format(available_balance|default(0)) }}</div>
        </div>
        
        {% if can_withdraw %}
        <div class="fee-info">
            <strong>ðŸ’° Withdrawal Fees:</strong><br>
            â€¢ KES 100-1,000: KES 10 fee<br>
            â€¢ KES 1,001-5,000: KES 25 fee<br>
            â€¢ KES 5,001-20,000: KES 50 fee<br>
            â€¢ KES 20,001-50,000: KES 100 fee
        </div>
        
        <form method="POST" action="/withdraw">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <div class="form-group">
                <label for="amount">Withdrawal Amount (KES)</label>
                <input type="number" id="amount" name="amount" 
                       min="100" max="50000" step="0.01" 
                       placeholder="Enter amount (min: KES 100)" required>
            </div>
            
            <button type="submit" {% if available_balance|default(0) < 100 %}disabled{% endif %}>
                {% if available_balance|default(0) < 100 %}
                    Minimum KES 100 Required
                {% else %}
                    Submit Withdrawal Request
                {% endif %}
            </button>
        </form>
        {% else %}
        <div class="fee-info">
            <strong>Withdrawal Limit Reached</strong>
            <p>You can only make one withdrawal every 24 hours.</p>
            {% if last_withdrawal %}
            <p>Last withdrawal: {{ last_withdrawal.strftime('%Y-%m-%d %H:%M') }}</p>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="rules">
            <h3>ðŸ“‹ Withdrawal Rules</h3>
            <ul>
                <li>âœ… Minimum withdrawal: KES 100</li>
                <li>âœ… Funds must be from game winnings only</li>
                <li>âœ… One withdrawal every 24 hours</li>
                <li>âœ… Withdrawal fees apply as shown above</li>
                <li>âŒ Excessive attempts = 6 hour suspension</li>
                <li>âœ… Processed within 24 hours by admin</li>
            </ul>
        </div>
        
        <div class="back-link">
            <a href="/">â† Back to Home</a>
        </div>
    </div>
</body>
</html>
"""
###############

admin_deposit_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deposit Management - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 15px;
            background: linear-gradient(to right, #43cea2, #185a9d);
            color: white;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border-radius: 10px;
        }
        h1 {
            color: #ffcc00;
            text-align: center;
            font-size: 1.5rem;
        }
        .pending-badge {
            background: #ff5722;
            color: white;
            padding: 3px 8px;
            border-radius: 15px;
            font-size: 0.8rem;
            margin-left: 8px;
        }
        .deposit-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: rgba(255,255,255,0.1);
            font-size: 0.8rem;
        }
        .deposit-table th, .deposit-table td {
            padding: 8px;
            border: 1px solid #444;
            text-align: left;
        }
        .deposit-table th {
            background: rgba(76, 175, 80, 0.3);
            color: #ffcc00;
        }
        .status-pending { color: #ff9800; font-weight: bold; }
        .status-completed { color: #4CAF50; font-weight: bold; }
        .status-rejected { color: #f44336; font-weight: bold; }
        .action-buttons {
            display: flex;
            gap: 3px;
        }
        .btn {
            padding: 4px 8px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.7rem;
        }
        .btn-approve { background: #4CAF50; color: white; }
        .btn-reject { background: #f44336; color: white; }
        .btn:disabled {
            background: #666;
            cursor: not-allowed;
        }
        .back-link {
            text-align: center;
            margin-top: 15px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Deposit Management <span class="pending-badge">{{ pending_count }} Pending</span></h1>
        
        <table class="deposit-table">
            <thead>
                <tr>
                    <th>Voucher Code</th>
                    <th>User</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Request Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for d in deposits %}
                <tr>
                    <td><strong>{{ d[4] }}</strong></td>
                    <td>{{ d[2] }}<br><small>{{ d[8] }}</small></td>
                    <td>KES {{ "%.2f"|format(d[3]) }}</td>
                    <td class="status-{{ d[5] }}">{{ d[5].upper() }}</td>
                    <td>{{ d[6].strftime('%Y-%m-%d %H:%M') }}</td>
                    <td class="action-buttons">
                        {% if d[5] == 'pending' %}
                        <button class="btn btn-approve" onclick="processDeposit({{ d[0] }}, 'approve')">Approve</button>
                        <button class="btn btn-reject" onclick="processDeposit({{ d[0] }}, 'reject')">Reject</button>
                        {% else %}
                        <button class="btn" disabled>Processed</button>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div class="back-link">
            <a href="/admin/dashboard">← Back to Admin Dashboard</a>
        </div>
    </div>

    <script>
    function processDeposit(depositId, action) {
        const adminNotes = prompt('Enter admin notes:') || '';
        
        fetch('/admin/process_deposit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `deposit_id=${depositId}&action=${action}&admin_notes=${encodeURIComponent(adminNotes)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Deposit ' + action + 'd successfully');
                location.reload();
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            alert('System error: ' + error);
        });
    }
    </script>
</body>
</html>
"""

withdrawal_receipt_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Withdrawal Receipt - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 10px;
            padding: 0;
            background: white;
            color: black;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .receipt-container {
            background: white;
            border: 2px solid #333;
            padding: 15px;
            border-radius: 8px;
            max-width: 300px;
            width: 100%;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .receipt-header {
            text-align: center;
            border-bottom: 2px dashed #333;
            padding-bottom: 10px;
            margin-bottom: 12px;
        }
        .receipt-header h1 {
            color: #ff6B35;
            margin: 0;
            font-size: 1.2rem;
        }
        .receipt-code {
            background: #333;
            color: #ffcc00;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-weight: bold;
            font-size: 0.9rem;
        }
        .receipt-details {
            margin-bottom: 15px;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 6px;
            padding: 4px 0;
            border-bottom: 1px solid #eee;
            font-size: 0.8rem;
        }
        .detail-label {
            font-weight: bold;
            color: #666;
        }
        .detail-value {
            font-weight: bold;
        }
        .amount-highlight {
            background: #4CAF50;
            color: white;
            padding: 8px;
            border-radius: 5px;
            text-align: center;
            margin: 10px 0;
        }
        .fee-deduction {
            color: #f44336;
            font-weight: bold;
        }
        .instructions {
            background: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #ffc107;
            margin: 12px 0;
            font-size: 0.75rem;
        }
        .action-buttons {
            text-align: center;
            margin-top: 15px;
        }
        .btn {
            padding: 8px 15px;
            margin: 0 3px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
            font-size: 0.8rem;
        }
        .btn-print {
            background: #2196F3;
            color: white;
        }
        .btn-home {
            background: #4CAF50;
            color: white;
        }
        @media print {
            body {
                padding: 0;
                margin: 0;
            }
            .receipt-container {
                box-shadow: none;
                border: 1px solid #333;
                max-width: 100%;
            }
            .action-buttons {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="receipt-container">
        <div class="receipt-header">
            <h1>HARAMBEE CASH</h1>
            <p style="margin: 5px 0; font-size: 0.9rem;">Withdrawal Receipt</p>
            <div class="receipt-code">{{ withdrawal[11] }}</div>
        </div>
        
        <div class="receipt-details">
            <div class="detail-row">
                <span class="detail-label">Username:</span>
                <span class="detail-value">{{ withdrawal[2] }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Email:</span>
                <span class="detail-value" style="font-size: 0.7rem;">{{ withdrawal[12] }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Date:</span>
                <span class="detail-value">{{ withdrawal[7].strftime('%Y-%m-%d') }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Time:</span>
                <span class="detail-value">{{ withdrawal[7].strftime('%H:%M') }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value" style="color: #ff9800;">{{ withdrawal[6].upper() }}</span>
            </div>
        </div>
        
        <div class="amount-highlight">
            <div style="font-size: 0.8rem; opacity: 0.9;">Requested Amount</div>
            <div style="font-size: 1.3rem; font-weight: bold;">KES {{ "%.2f"|format(withdrawal[3]) }}</div>
        </div>
        
        <div class="receipt-details">
            <div class="detail-row">
                <span class="detail-label">Withdrawal Fee:</span>
                <span class="detail-value fee-deduction">- KES {{ "%.2f"|format(withdrawal[4]) }}</span>
            </div>
            <div class="detail-row" style="border-bottom: 2px solid #333; font-size: 0.9rem;">
                <span class="detail-label">Net Amount:</span>
                <span class="detail-value" style="color: #4CAF50;">KES {{ "%.2f"|format(withdrawal[5]) }}</span>
            </div>
        </div>
        
        <div class="instructions">
            <strong>📋 FOR ADMIN PROCESSING:</strong><br>
            "Kindly send KES {{ "%.2f"|format(withdrawal[5]) }} to the user via platform M-Pesa number as per system approval."
            <br><br>
            <strong>ℹ️ VERIFICATION:</strong> Use independent M-Pesa records for transaction confirmation.
        </div>
        
        <div class="action-buttons">
            <button class="btn btn-print" onclick="window.print()">🖨️ Print</button>
            <a href="/" class="btn btn-home">🏠 Home</a>
        </div>
    </div>
</body>
</html>
"""

deposit_voucher_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deposit Voucher - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 10px;
            padding: 0;
            background: white;
            color: black;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .voucher-container {
            background: white;
            border: 2px solid #333;
            padding: 15px;
            border-radius: 8px;
            max-width: 300px;
            width: 100%;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .voucher-header {
            text-align: center;
            border-bottom: 2px dashed #333;
            padding-bottom: 10px;
            margin-bottom: 12px;
        }
        .voucher-header h1 {
            color: #ff6B35;
            margin: 0;
            font-size: 1.2rem;
        }
        .voucher-code {
            background: #333;
            color: #ffcc00;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-weight: bold;
            font-size: 0.9rem;
        }
        .voucher-details {
            margin-bottom: 15px;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 6px;
            padding: 4px 0;
            border-bottom: 1px solid #eee;
            font-size: 0.8rem;
        }
        .detail-label {
            font-weight: bold;
            color: #666;
        }
        .detail-value {
            font-weight: bold;
        }
        .amount-section {
            background: #4CAF50;
            color: white;
            padding: 8px;
            border-radius: 5px;
            text-align: center;
            margin: 10px 0;
        }
        .instructions {
            background: #fff3cd;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #ffc107;
            margin: 12px 0;
            font-size: 0.75rem;
        }
        .action-buttons {
            text-align: center;
            margin-top: 15px;
        }
        .btn {
            padding: 8px 15px;
            margin: 0 3px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
            font-size: 0.8rem;
        }
        .btn-print {
            background: #2196F3;
            color: white;
        }
        .btn-home {
            background: #4CAF50;
            color: white;
        }
        @media print {
            body {
                padding: 0;
                margin: 0;
            }
            .voucher-container {
                box-shadow: none;
                border: 1px solid #333;
                max-width: 100%;
            }
            .action-buttons {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="voucher-container">
        <div class="voucher-header">
            <h1>HARAMBEE CASH</h1>
            <p style="margin: 5px 0; font-size: 0.9rem;">Deposit Voucher</p>
            <div class="voucher-code">{{ deposit[4] }}</div>
        </div>
        
        <div class="voucher-details">
            <div class="detail-row">
                <span class="detail-label">Username:</span>
                <span class="detail-value">{{ deposit[2] }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Date:</span>
                <span class="detail-value">{{ deposit[6].strftime('%Y-%m-%d') }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Time:</span>
                <span class="detail-value">{{ deposit[6].strftime('%H:%M') }}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value" style="color: #ff9800;">{{ deposit[5].upper() }}</span>
            </div>
        </div>
        
        <div class="amount-section">
            <div style="font-size: 0.8rem; opacity: 0.9;">Deposit Amount</div>
            <div style="font-size: 1.3rem; font-weight: bold;">KES {{ "%.2f"|format(deposit[3]) }}</div>
        </div>
        
        <div class="instructions">
            <strong>📋 PRESENT TO ADMIN:</strong><br>
            "Kindly update my platform wallet account with the M-Pesa amount sent to your platform recently!"
            <br><br>
            <strong>ℹ️ NOTE:</strong> No M-Pesa confirmation message needed. Platform has official M-Pesa number for verification.
        </div>
        
        <div class="action-buttons">
            <button class="btn btn-print" onclick="window.print()">🖨️ Print</button>
            <a href="/" class="btn btn-home">🏠 Home</a>
        </div>
    </div>
</body>
</html>
"""

deposit_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deposit Funds - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: rgba(0, 0, 0, 0.9);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
            max-width: 450px;
            width: 95%;
        }
        h1 {
            color: #ffcc00;
            text-align: center;
            margin-bottom: 15px;
            font-size: 1.4rem;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            color: #ffcc00;
            font-weight: bold;
            font-size: 0.9rem;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 2px solid #333;
            border-radius: 6px;
            background: rgba(255,255,255,0.1);
            color: white;
            font-size: 0.9rem;
            box-sizing: border-box;
        }
        input:focus {
            border-color: #ffcc00;
            outline: none;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: bold;
            cursor: pointer;
            margin: 10px 0;
        }
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 3px 10px rgba(76, 175, 80, 0.4);
        }
        .error {
            background: #d32f2f;
            color: white;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            text-align: center;
            font-size: 0.9rem;
        }
        .info-box {
            background: rgba(255, 204, 0, 0.1);
            border: 1px solid #ffcc00;
            padding: 12px;
            border-radius: 6px;
            margin: 15px 0;
            font-size: 0.85rem;
        }
        .rules {
            margin-top: 20px;
            padding: 12px;
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            font-size: 0.8rem;
        }
        .rules h3 {
            color: #ffcc00;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        .rules ul {
            padding-left: 15px;
            margin: 0;
        }
        .rules li {
            margin-bottom: 5px;
        }
        .back-link {
            text-align: center;
            margin-top: 15px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>💰 Deposit Funds</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <div class="info-box">
            <strong>📱 Payment Instructions:</strong><br>
            1. Send money via M-Pesa to our official number<br>
            2. Generate deposit voucher below<br>
            3. Present voucher to admin for verification<br>
            4. Funds added to wallet after confirmation
        </div>
        
        {% if can_deposit %}
        <form method="POST" action="/deposit">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <div class="form-group">
                <label for="amount">Deposit Amount (KES)</label>
                <input type="number" id="amount" name="amount" 
                       min="50" max="50000" step="0.01" 
                       placeholder="Enter amount (min: KES 50)" required>
            </div>
            
            <button type="submit">
                Generate Deposit Voucher
            </button>
        </form>
        {% endif %}
        
        <div class="rules">
            <h3>📋 Deposit Rules</h3>
            <ul>
                <li>✅ Minimum deposit: KES 50</li>
                <li>✅ Maximum deposit: KES 50,000</li>
                <li>✅ Use official M-Pesa number only</li>
                <li>✅ Keep transaction details safe</li>
                <li>✅ Processing time: Within 2 hours</li>
                <li>❌ No fake deposits tolerated</li>
            </ul>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
"""                              



cashbook_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Financial Cashbook - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(to right, #43cea2, #185a9d);
            color: white;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .cashbook-windows {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .cashbook-window {
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .cashbook-window h3 {
            color: #ffcc00;
            margin-bottom: 15px;
            text-align: center;
        }
        .financial-item {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        .financial-value {
            font-weight: bold;
            color: #4CAF50;
        }
        .back-link {
            text-align: center;
            margin-top: 20px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
        .transaction-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .transaction-table th, .transaction-table td {
            padding: 8px;
            text-align: center;
            border: 1px solid #444;
        }
        .transaction-table th {
            background: rgba(76, 175, 80, 0.3);
        }
        .profit-badge {
            background: #4CAF50;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8rem;
        }
        .last-updated {
            text-align: center;
            color: #ccc;
            font-size: 0.9rem;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Financial Cashbook</h1>
        <div class="last-updated">
            Last updated: <span id="currentTime"></span>
        </div>
        
        <div class="cashbook-windows">
            <div class="cashbook-window">
                <h3>ðŸ’° GROSS PLATFORM PROFIT</h3>
                <div class="financial-item">
                    <span>Total Profit:</span>
                    <span class="financial-value">Ksh. {{ "%.2f"|format(data.total_gross_profit) }}</span>
                </div>
                <div class="financial-item">
                    <span>Profitable Games:</span>
                    <span class="financial-value">{{ data.total_profitable_games }}</span>
                </div>
            </div>
        </div>

        <div class="cashbook-window">
            <h3>ðŸ“ RECENT PROFIT TRANSACTIONS</h3>
            {% if data.recent_profits %}
            <table class="transaction-table">
                <thead>
                    <tr>
                        <th>Game Code</th>
                        <th>Time</th>
                        <th>Players</th>
                        <th>Total Pool</th>
                        <th>Platform Profit</th>
                    </tr>
                </thead>
                <tbody>
                    {% for profit in data.recent_profits %}
                    <tr>
                        <td>{{ profit[0] }}</td>
                        <td>
                            {% if profit[1] != 'N/A' %}
                                {{ profit[1].strftime('%H:%M') }}
                            {% else %}
                                N/A
                            {% endif %}
                        </td>
                        <td>{{ profit[2] }}</td>
                        <td>Ksh. {{ "%.2f"|format(profit[3]) }}</td>
                        <td><span class="profit-badge">Ksh. {{ "%.2f"|format(profit[4]) }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div style="text-align: center; color: #ccc; padding: 20px;">
                No profitable games recorded yet.
            </div>
            {% endif %}
        </div>
        
        <div class="back-link">
            <a href="/admin/dashboard">â† Back to Admin Dashboard</a>
        </div>
    </div>

    <script>
        // Simple time display - no auto refresh
        document.getElementById('currentTime').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
"""

base_html = """
<!DOCTYPE html>
<html lang="en">  
<head>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794" crossorigin="anonymous"></script>
    <meta charset="UTF-8" />  
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />  
    <title>HARAMBEE CASH - Play & Win Big!</title>  
    <link rel="manifest" href="{{ url_for('static', filename='manifest.json') }}" />  
    <meta name="theme-color" content="#D4AF37" />  
    <link rel="icon" type="image/png" href="{{ url_for('static', filename='favicon.ico') }}" />  
    <link rel="apple-touch-icon" href="{{ url_for('static', filename='apple-touch-icon.png') }}" />  
    <meta name="description" content="Harambee Cash - Play exciting games and win big prizes. Join our community gaming platform today!" />
    <meta name="keywords" content="gaming, cash prizes, harambee, win money, online games" />
    <style>  
        :root {
            --gold-primary: #D4AF37;
            --gold-secondary: #FFD700;
            --gold-light: #F7EF8A;
            --gold-dark: #B8860B;
            --gold-accent: #FFC125;
            --gold-gradient: linear-gradient(135deg, #D4AF37 0%, #FFD700 50%, #F7EF8A 100%);
            --gold-gradient-reverse: linear-gradient(135deg, #F7EF8A 0%, #FFD700 50%, #D4AF37 100%);
            --gold-gradient-subtle: linear-gradient(135deg, rgba(212, 175, 55, 0.1) 0%, rgba(255, 215, 0, 0.1) 100%);
            --dark-bg: #1A1A1A;
            --dark-card: #2D2D2D;
            --text-light: #FFFFFF;
            --text-gold: #FFD700;
            --text-muted: #CCCCCC;
            --shadow: 0 8px 30px rgba(212, 175, 55, 0.15);
            --shadow-hover: 0 15px 40px rgba(212, 175, 55, 0.25);
            --radius: 20px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            --success: #00C9B1;
            --error: #FF6B35;
            --warning: #FFD166;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            background: var(--dark-bg);
            background-attachment: fixed;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            color: var(--text-light);
            text-align: center;
            line-height: 1.6;
        }

        .container {
            background: var(--dark-card);
            backdrop-filter: blur(20px);
            padding: 40px 30px;
            border-radius: var(--radius);
            max-width: 800px;
            width: 95%;
            box-shadow: var(--shadow);
            position: relative;
            margin: 20px;
            border: 1px solid rgba(212, 175, 55, 0.2);
            transition: var(--transition);
            overflow: hidden;
        }

        .container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gold-gradient);
            z-index: 1;
        }

        .logo-container {
            margin-bottom: 25px;
            position: relative;
        }
        
        .logo {
            width: 150px;
            height: 150px;
            margin: 0 auto 15px;
        }        

        .logo-text {
            font-size: 2rem;
            font-weight: 800;
            color: var(--dark-bg);
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
}

        .logo-img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            border-radius: 50%;
            filter: none !important;
        }

        .tagline {
            font-size: 1.3rem;
            margin-bottom: 30px;
            color: var(--text-gold);
            font-weight: 500;
            letter-spacing: 0.5px;
        }

        .balance-display {
            background: var(--gold-gradient-subtle);
            border: 1px solid rgba(212, 175, 55, 0.3);
            border-radius: var(--radius);
            padding: 20px;
            margin: 25px auto;
            max-width: 300px;
            box-shadow: var(--shadow);
            backdrop-filter: blur(10px);
            transition: var(--transition);
        }

        .balance-display:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
        }

        .balance-label {
            font-size: 1rem;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .balance-amount {
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--gold-secondary);
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.3);
        }

        .welcome-section {
            margin: 30px 0;
            padding: 25px;
            background: var(--gold-gradient-subtle);
            border-radius: var(--radius);
            border: 1px solid rgba(212, 175, 55, 0.2);
        }

        .welcome-section h2 {
            font-size: 1.8rem;
            margin-bottom: 15px;
            color: var(--text-gold);
            font-weight: 700;
        }

        .welcome-section h3 {
            font-size: 1.5rem;
            margin: 20px 0 10px;
            color: var(--gold-light);
            font-weight: 600;
        }

        .welcome-section p {
            color: var(--text-muted);
            margin-bottom: 15px;
            font-size: 1.1rem;
            line-height: 1.7;
        }

        .cta-button {
            background: var(--gold-gradient);
            color: var(--dark-bg);
            border: none;
            padding: 15px 40px;
            font-size: 1.2rem;
            font-weight: 700;
            border-radius: 50px;
            cursor: pointer;
            margin: 20px 0;
            box-shadow: var(--shadow);
            transition: var(--transition);
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .cta-button:hover {
            transform: translateY(-3px);
            box-shadow: var(--shadow-hover);
            background: var(--gold-gradient-reverse);
        }

        .cta-button:disabled {
            opacity: 0.7;
            cursor: not-allowed;
            transform: none;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .feature-card {
            background: var(--gold-gradient-subtle);
            border: 1px solid rgba(212, 175, 55, 0.2);
            border-radius: var(--radius);
            padding: 20px 15px;
            transition: var(--transition);
        }

        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow);
            border-color: rgba(212, 175, 55, 0.4);
        }

        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: var(--gold-secondary);
        }

        .feature-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--text-gold);
        }

        .feature-desc {
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(212, 175, 55, 0.2);
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .gold-text {
            background: var(--gold-gradient);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            font-weight: 700;
        }

        .glow-effect {
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.5);
        }

        /* Error and Message Styles */
        .error {
            background: rgba(255, 107, 53, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
            padding: 15px;
            border-radius: var(--radius);
            margin: 15px 0;
        }

        .message {
            background: rgba(0, 201, 177, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 15px;
            border-radius: var(--radius);
            margin: 15px 0;
        }

        .warning {
            background: rgba(255, 209, 102, 0.1);
            border: 1px solid var(--warning);
            color: var(--warning);
            padding: 15px;
            border-radius: var(--radius);
            margin: 15px 0;
        }

        /* Game Results Styles */
        .game-window {
            margin: 30px 0;
            padding: 25px;
            background: var(--gold-gradient-subtle);
            border-radius: var(--radius);
            border: 1px solid rgba(212, 175, 55, 0.2);
        }

        .game-result {
            background: rgba(0, 0, 0, 0.3);
            border-radius: var(--radius);
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid var(--gold-primary);
        }

        /* Enrollment Status */
        .enrollment-status {
            background: rgba(0, 201, 177, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 15px;
            border-radius: var(--radius);
            margin: 15px 0;
            animation: pulse 2s infinite;
        }

        /* Loading Spinner */
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: var(--gold-primary);
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
        }

        /* Offline Styles */
        .offline-banner {
            background: rgba(255, 107, 53, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
            padding: 20px;
            border-radius: var(--radius);
            margin: 20px 0;
        }

        .offline-btn {
            background: var(--gold-gradient-subtle);
            border: 1px solid rgba(212, 175, 55, 0.3);
            color: var(--text-gold);
            padding: 12px 20px;
            border-radius: var(--radius);
            margin: 10px;
            cursor: pointer;
            transition: var(--transition);
        }

        .offline-btn:hover {
            background: var(--gold-gradient);
            color: var(--dark-bg);
        }

        /* Trivia Styles */
        .trivia-option {
            background: var(--gold-gradient-subtle);
            border: 1px solid rgba(212, 175, 55, 0.3);
            padding: 15px;
            margin: 10px 0;
            border-radius: var(--radius);
            cursor: pointer;
            transition: var(--transition);
        }

        .trivia-option:hover {
            background: rgba(212, 175, 55, 0.2);
        }

        .trivia-correct {
            background: rgba(0, 201, 177, 0.2);
            border-color: var(--success);
        }

        .trivia-wrong {
            background: rgba(255, 107, 53, 0.2);
            border-color: var(--error);
        }

        /* Achievement Notification */
        .achievement-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--gold-gradient);
            color: var(--dark-bg);
            padding: 20px;
            border-radius: var(--radius);
            box-shadow: var(--shadow-hover);
            z-index: 1000;
            animation: slideInRight 0.5s ease-out;
        }

        /* Game Animation */
        .game-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 999;
            flex-direction: column;
        }

        .animation-content {
            text-align: center;
            color: white;
        }

        .animated-image {
            font-size: 8rem;
            margin-bottom: 20px;
            animation: bounce 1s infinite;
        }

        .animation-text {
            font-size: 2rem;
            font-weight: bold;
            text-shadow: 0 0 10px rgba(255, 215, 0, 0.8);
        }

        .rocket, .confetti {
            position: absolute;
            font-size: 2rem;
            animation: floatUp 2s ease-out forwards;
        }

        .confetti {
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }

        /* Social Icons */
        .socials {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin: 20px 0;
        }

        .social-icon {
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--gold-gradient-subtle);
            border-radius: 50%;
            transition: var(--transition);
        }

        .social-icon:hover {
            transform: translateY(-3px);
            background: var(--gold-gradient);
        }

        .social-icon img {
            width: 20px;
            height: 20px;
        }

        /* Install Button */
        #install-btn {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--gold-gradient);
            color: var(--dark-bg);
            border: none;
            padding: 10px 20px;
            border-radius: 50px;
            cursor: pointer;
            box-shadow: var(--shadow);
            display: none;
            z-index: 100;
            font-weight: 600;
        }

        /* Animations */
        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }

        @keyframes slideInRight {
            from { transform: translateX(100%); }
            to { transform: translateX(0); }
        }

        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }

        @keyframes floatUp {
            to {
                transform: translateY(-100vh) rotate(360deg);
                opacity: 0;
            }
        }

        @media (max-width: 480px) {
            h1 { font-size: 2.2rem; }
            .container { padding: 25px 15px; margin: 15px; }
            .logo { width: 130px; height: 130px; }
            .logo-text { font-size: 1.6rem; }
            .balance-display { font-size: 1.2rem; min-width: 200px; padding: 15px; }
            .balance-amount { font-size: 1.8rem; }
            .welcome-section h2 { font-size: 1.5rem; }
            .welcome-section h3 { font-size: 1.3rem; }
            .cta-button { padding: 12px 30px; font-size: 1.1rem; }
            .animated-image { font-size: 4rem; }
            .animation-text { font-size: 1.5rem; }
            #install-btn { top: 10px; right: 10px; padding: 8px 16px; font-size: 0.9rem; }
        }
    </style>
</head>
<body>
    <button id="install-btn">📱 Install App</button>

    <div class="logo">
        <img src="{{ url_for('static', filename='piclog.png') }}" alt="Harambee Cash Logo" class="logo-img" style="filter: none !important;">
    </div>

        <p id="timestamp-display">Loading time...</p>

        {% if error %}<div class="error">{{ error }}</div>{% endif %}  
        {% if message %}<div class="message">{{ message }}</div>{% endif %}
        {% if warning %}<div class="warning">{{ warning }}</div>{% endif %}

        {% if not session.get('user_id') %}
            <div class="welcome-section">
                <h2>Welcome to <span class="gold-text">Harambee Cash</span></h2>
                <p>Join our exciting gaming platform where you can play and win real prizes!</p>
                
                <div style="text-align: center; margin: 25px 0;">
                    <p style="font-size: 1.2rem; margin-bottom: 20px;"><strong>Ready to play?</strong></p>
                    <a href="/register" style="display: inline-block; margin: 10px;">
                        <button class="cta-button">Create Account</button>
                    </a>
                    <a href="/login" style="display: inline-block; margin: 10px;">
                        <button class="cta-button" style="background: var(--gold-gradient-reverse);">Login</button>
                    </a>
                </div>

                <div class="features-grid">
                    <div class="feature-card">
                        <div class="feature-icon">💰</div>
                        <div class="feature-title">Win Real Cash</div>
                        <div class="feature-desc">Play with just Ksh. 1.00 and win exciting cash prizes</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">⚡</div>
                        <div class="feature-title">Fast Games</div>
                        <div class="feature-desc">New games every 30 seconds with instant results</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🛡️</div>
                        <div class="feature-title">Secure & Safe</div>
                        <div class="feature-desc">Advanced security with fair gameplay guaranteed</div>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🏆</div>
                        <div class="feature-title">Community</div>
                        <div class="feature-desc">Join thousands of players winning together</div>
                    </div>
                </div>

                <h3>How to Play</h3>
                <ul style="text-align: left; display: inline-block; color: var(--text-muted);">
                    <li>Create your free account</li>
                    <li>Login to access games</li>
                    <li>Play with just Ksh. 1.00 per round</li>
                    <li>Win exciting cash prizes</li>
                </ul>
            </div>
        {% else %}
            <p style="font-size: 1.3rem; color: var(--text-gold); font-weight: 700;">Welcome back, {{ session.get('username') }}! 👋</p>  
            <div class="balance-display">
                <div class="balance-label">Your Wallet Balance</div>
                <div class="balance-amount">Ksh. {{ wallet_balance | default(0.0) | float | round(2) }}</div>
            </div>

            <!-- Enrollment Status Display -->
            <div id="enrollmentStatus" class="enrollment-status" style="display: none;">
                <span id="statusText"></span>
            </div>

            <!-- Protected Form -->
            <form method="POST" action="/play" id="playForm" onsubmit="return handlePlayClick(event)">  
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />  
                <button type="submit" id="playButton" class="cta-button" onclick="return handlePlayClick(event)">
                    🎮 PLAY NOW & WIN BIG!
                </button>  
            </form>
            
            {% if session.get('user_id') %}
                <div style="margin: 15px 0; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
                    <a href="/deposit" style="text-decoration: none;">
                        <button class="cta-button" style="background: var(--success); margin: 5px;">
                            💰 Deposit Funds
                        </button>
                    </a>
                    <a href="/withdraw" style="text-decoration: none;">
                        <button class="cta-button" style="background: var(--gold-gradient); margin: 5px;">
                            📤 Withdraw Earnings
                        </button>
                    </a>
                </div>
            {% endif %}            

            <a href="/logout" style="display: inline-block; margin-top: 15px; color: var(--text-gold); text-decoration: none;">Logout</a>  
            
            <div class="game-window">  
                <h2>Game Status</h2>  
                <p><strong>Next Game:</strong> <span id="next-game">Loading...</span></p>  
                <h2>Recent Results (Last 50 Games)</h2>  
                <div id="game-results">Loading recent games...</div>  
            </div>  
        {% endif %}

        <!-- Offline Content -->
        <div id="offlineBanner" class="offline-banner" style="display: none;">
            <h3>📶 You're Offline - But the Fun Continues!</h3>
            <p>Try these activities while you reconnect:</p>
        </div>
        
        <div id="offlineEntertainment" style="display: none;">
            <div class="game-window">
                <h2>🎮 {% if session.get('user_id') %}Offline Training Zone{% else %}Offline Fun Zone{% endif %}</h2>
                <div class="offline-options">
                    <button class="offline-btn" onclick="startTriviaGame()">
                        🧠 {% if session.get('user_id') %}Harambee Trivia{% else %}Trivia Challenge{% endif %}
                    </button>
                    <button class="offline-btn" onclick="showGamingTips()">
                        📚 {% if session.get('user_id') %}Winning Strategies{% else %}Gaming Tips{% endif %}
                    </button>
                    <button class="offline-btn" onclick="showPracticeMode()">
                        💪 {% if session.get('user_id') %}Practice Games{% else %}Practice Strategies{% endif %}
                    </button>
                    {% if session.get('user_id') %}
                    <button class="offline-btn" onclick="viewAchievements()">
                        🏆 My Achievements
                    </button>
                    {% endif %}
                </div>
                <div id="offlineContent"></div>
            </div>
        </div>

        <div class="footer">
            <p>
                <a href="/terms" style="color: var(--text-gold); text-decoration: none;">Terms & Conditions</a> | 
                <a href="/privacy" style="color: var(--text-gold); text-decoration: none;">Privacy Policy</a> | 
                <a href="/docs" style="color: var(--text-gold); text-decoration: none;">Documentation</a>
            </p>
            <div class="socials">
                <a href="https://m.facebook.com/jamesboyid.ochuna" target="_blank" title="Facebook" class="social-icon">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg" alt="Facebook" />
                </a>
                <a href="https://wa.me/254701207062" target="_blank" title="WhatsApp" class="social-icon">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/6/6b/WhatsApp.svg" alt="WhatsApp" />
                </a>
                <a href="tel:+254701207062" title="Call Us" class="social-icon">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/8c/Phone_font_awesome.svg" alt="Phone" />               
                </a>  
            </div>
            <p style="text-align: center; font-size: 0.9rem; margin-top: 30px; color: var(--text-muted);">
                © 2025 Pigasimu. All rights reserved.
            </p>
        </div>  
    </div>

    <!-- Game Animation Elements -->
    <div id="gameAnimation" class="game-animation">
        <div class="animation-content">
            <div class="animated-image" id="animatedImage">🎮</div>
            <div class="animation-text" id="animationText"></div>
        </div>
    </div>

    <script>  
        // Game Submission Protection System
        class SubmissionProtector {
            constructor() {
                this.isSubmitting = false;
                this.submissionTimeout = null;
                this.userEnrolled = false;
                this.currentGame = null;
                this.audioEnabled = false;
            }

            initialize() {
                this.loadSubmissionState();
                this.setupFormProtection();
                this.setupBeforeUnload();
                this.setupAudioPermission();
            }

            setupAudioPermission() {
                document.addEventListener('click', () => {
                    this.audioEnabled = true;
                }, { once: true });
            }

            loadSubmissionState() {
                const savedState = sessionStorage.getItem('harambeeSubmissionState');
                if (savedState) {
                    try {
                        const state = JSON.parse(savedState);
                        this.isSubmitting = state.isSubmitting || false;
                        this.userEnrolled = state.userEnrolled || false;
                        
                        if (this.isSubmitting) {
                            this.disablePlayButton('⏳ Processing...');
                        } else if (this.userEnrolled) {
                            this.showEnrollmentStatus('✅ Already enrolled in current game');
                            this.disablePlayButton('✅ Already Enrolled');
                        }
                    } catch (e) {
                        console.error('Error loading submission state:', e);
                        this.resetState();
                    }
                }
            }

            saveSubmissionState() {
                const state = {
                    isSubmitting: this.isSubmitting,
                    userEnrolled: this.userEnrolled,
                    timestamp: Date.now()
                };
                try {
                    sessionStorage.setItem('harambeeSubmissionState', JSON.stringify(state));
                } catch (e) {
                    console.error('Error saving submission state:', e);
                }
            }

            setupFormProtection() {
                const form = document.getElementById('playForm');
                const button = document.getElementById('playButton');

                if (form && button) {
                    form.addEventListener('submit', (e) => {
                        if (this.isSubmitting || this.userEnrolled) {
                            e.preventDefault();
                            e.stopImmediatePropagation();
                            return false;
                        }
                        
                        return this.handleFormSubmission();
                    });

                    button.addEventListener('click', (e) => {
                        if (this.isSubmitting || this.userEnrolled) {
                            e.preventDefault();
                            e.stopImmediatePropagation();
                            return false;
                        }
                    }, true);
                }
            }

            setupBeforeUnload() {
                window.addEventListener('beforeunload', (e) => {
                    if (this.isSubmitting) {
                        e.preventDefault();
                        e.returnValue = 'Your game enrollment is being processed. Are you sure you want to leave?';
                        return e.returnValue;
                    }
                });
            }

            handleFormSubmission() {
                if (this.isSubmitting || this.userEnrolled) {
                    return false;
                }

                this.isSubmitting = true;
                this.disablePlayButton('⏳ Processing...');
                this.saveSubmissionState();

                this.submissionTimeout = setTimeout(() => {
                    if (this.isSubmitting) {
                        this.isSubmitting = false;
                        this.enablePlayButton();
                        this.saveSubmissionState();
                        this.showTemporaryMessage('Submission timeout. Please try again.', 'warning');
                    }
                }, 10000);

                return true;
            }

            handleSubmissionSuccess(message = '✅ Successfully enrolled in the next game!') {
                clearTimeout(this.submissionTimeout);
                this.isSubmitting = false;
                this.userEnrolled = true;
                this.showEnrollmentStatus(message);
                this.disablePlayButton('✅ Already Enrolled');
                this.saveSubmissionState();

                if (this.audioEnabled) {
                    this.playSuccessSound();
                }

                setTimeout(() => {
                    this.userEnrolled = false;
                    this.enablePlayButton();
                    this.hideEnrollmentStatus();
                    this.saveSubmissionState();
                }, 35000);
            }

            handleSubmissionError() {
                clearTimeout(this.submissionTimeout);
                this.isSubmitting = false;
                this.enablePlayButton();
                this.saveSubmissionState();
            }

            playSuccessSound() {
                try {
                    const context = new (window.AudioContext || window.webkitAudioContext)();
                    const oscillator = context.createOscillator();
                    const gainNode = context.createGain();
                    
                    oscillator.connect(gainNode);
                    gainNode.connect(context.destination);
                    
                    oscillator.frequency.value = 800;
                    oscillator.type = 'sine';
                    
                    gainNode.gain.setValueAtTime(0.3, context.currentTime);
                    gainNode.gain.exponentialRampToValueAtTime(0.01, context.currentTime + 0.5);
                    
                    oscillator.start(context.currentTime);
                    oscillator.stop(context.currentTime + 0.5);
                } catch (e) {
                    console.log('Web Audio API not supported');
                }
            }

            disablePlayButton(text = '⏳ Processing...') {
                const button = document.getElementById('playButton');
                if (button) {
                    button.disabled = true;
                    button.innerHTML = `<span class="loading-spinner"></span>${text}`;
                }
            }

            enablePlayButton() {
                const button = document.getElementById('playButton');
                if (button) {
                    button.disabled = false;
                    button.innerHTML = '🎮 PLAY NOW & WIN BIG!';
                }
            }

            showEnrollmentStatus(message) {
                const statusDiv = document.getElementById('enrollmentStatus');
                const statusText = document.getElementById('statusText');
                if (statusDiv && statusText) {
                    statusText.textContent = message;
                    statusDiv.style.display = 'block';
                }
            }

            hideEnrollmentStatus() {
                const statusDiv = document.getElementById('enrollmentStatus');
                if (statusDiv) {
                    statusDiv.style.display = 'none';
                }
            }

            showTemporaryMessage(message, type = 'error') {
                const messageDiv = document.createElement('div');
                messageDiv.className = type;
                messageDiv.textContent = message;
                messageDiv.style.margin = '10px 0';
                
                const container = document.querySelector('.container');
                if (container) {
                    container.insertBefore(messageDiv, container.firstChild);
                    
                    setTimeout(() => {
                        if (messageDiv.parentNode) {
                            messageDiv.parentNode.removeChild(messageDiv);
                        }
                    }, 5000);
                }
            }

            resetState() {
                this.isSubmitting = false;
                this.userEnrolled = false;
                clearTimeout(this.submissionTimeout);
                this.enablePlayButton();
                this.hideEnrollmentStatus();
                try {
                    sessionStorage.removeItem('harambeeSubmissionState');
                } catch (e) {}
            }
        }

        // Game Animator Class
        class GameAnimator {
            constructor() {
                this.animation = document.getElementById('gameAnimation');
                this.animatedImage = document.getElementById('animatedImage');
                this.animationText = document.getElementById('animationText');
                this.lastGameStatus = null;
                this.animationActive = false;
            }

            async playGameStart(gameCode) {
                if (this.animationActive) return;
                this.animationActive = true;
                
                this.animatedImage.innerHTML = '🚀';
                this.animationText.textContent = `GAME ${gameCode} STARTED!`;
                this.animation.className = 'game-animation game-start';
                this.animation.style.display = 'flex';
                
                this.createRocketEffect();
                
                setTimeout(() => {
                    this.hideAnimation();
                }, 3000);
            }

            async playGameEnd(gameCode, winner, amount) {
                if (this.animationActive) return;
                this.animationActive = true;
                
                this.animatedImage.innerHTML = '🎉';
                this.animationText.textContent = `WINNER: ${winner} 🏆 Ksh.${amount}`;
                this.animation.className = 'game-animation game-end';
                this.animation.style.display = 'flex';
                
                this.createConfettiEffect();
                
                setTimeout(() => {
                    this.hideAnimation();
                    if (window.submissionProtector) {
                        window.submissionProtector.resetState();
                    }
                }, 4000);
            }

            createRocketEffect() {
                for (let i = 0; i < 3; i++) {
                    setTimeout(() => {
                        const rocket = document.createElement('div');
                        rocket.className = 'rocket';
                        rocket.innerHTML = '🚀';
                        rocket.style.left = `${20 + i * 30}%`;
                        this.animation.appendChild(rocket);
                        
                        setTimeout(() => {
                            if (rocket.parentNode) {
                                rocket.parentNode.removeChild(rocket);
                            }
                        }, 2000);
                    }, i * 300);
                }
            }

            createConfettiEffect() {
                const colors = ['#FF6B35', '#00C9B1', '#FFD166', '#4ECDC4', '#FFE66D'];
                for (let i = 0; i < 50; i++) {
                    setTimeout(() => {
                        const confetti = document.createElement('div');
                        confetti.className = 'confetti';
                        confetti.style.left = `${Math.random() * 100}%`;
                        confetti.style.background = colors[Math.floor(Math.random() * colors.length)];
                        confetti.style.animationDelay = `${Math.random() * 2}s`;
                        this.animation.appendChild(confetti);
                        
                        setTimeout(() => {
                            if (confetti.parentNode) {
                                confetti.parentNode.removeChild(confetti);
                            }
                        }, 3000);
                    }, i * 50);
                }
            }

            hideAnimation() {
                this.animation.style.display = 'none';
                const effects = this.animation.querySelectorAll('.confetti, .rocket');
                effects.forEach(effect => {
                    if (effect.parentNode) {
                        effect.parentNode.removeChild(effect);
                    }
                });
                this.animationActive = false;
            }

            monitorGameStatus() {
                setInterval(() => {
                    if (!navigator.onLine) return;
                    
                    fetch('/game_data')
                        .then(response => {
                            if (!response.ok) throw new Error('Network error');
                            return response.json();
                        })
                        .then(data => {
                            if (data.in_progress_game) {
                                const currentGame = data.in_progress_game;
                                
                                if (currentGame.status === 'in progress' && 
                                    (!this.lastGameStatus || this.lastGameStatus.status !== 'in progress')) {
                                    this.playGameStart(currentGame.game_code);
                                }
                                
                                if (currentGame.status === 'completed' && 
                                    this.lastGameStatus && this.lastGameStatus.status === 'in progress') {
                                    this.playGameEnd(currentGame.game_code, currentGame.winner, currentGame.winner_amount);
                                }
                                
                                this.lastGameStatus = {...currentGame};
                            }
                        })
                        .catch(error => console.error('Error monitoring game status:', error));
                }, 2000);
            }
        }

        // Offline Entertainment Features
        const triviaQuestions = [
            {
                question: "What is the minimum play amount in Harambee Cash?",
                options: ["Ksh. 1", "Ksh. 5", "Ksh. 10", "Ksh. 20"],
                answer: 0
            },
            {
                question: "How often do games run in Harambee Cash?",
                options: ["Every 5 minutes", "Every 30 seconds", "Every hour", "Once a day"],
                answer: 1
            },
            {
                question: "What should you do before playing any game?",
                options: ["Set a budget", "Borrow money", "Play continuously", "Ignore rules"],
                answer: 0
            },
            {
                question: "Which is a good gaming practice?",
                options: ["Take regular breaks", "Chase losses", "Play when emotional", "Ignore time"],
                answer: 0
            }
        ];

        const achievements = {
            'offline_explorer': { 
                name: 'Offline Explorer', 
                description: 'Used the app while offline',
                unlocked: false 
            },
            'trivia_master': { 
                name: 'Trivia Master', 
                description: 'Got perfect score in trivia',
                unlocked: false 
            },
            'knowledge_seeker': { 
                name: 'Knowledge Seeker', 
                description: 'Read all gaming tips',
                unlocked: false 
            },
            'app_installer': {
                name: 'App Installer',
                description: 'Installed the PWA app',
                unlocked: false
            }
        };

        let currentTriviaQuestion = 0;
        let triviaScore = 0;

        function startTriviaGame() {
            currentTriviaQuestion = 0;
            triviaScore = 0;
            showTriviaQuestion();
        }

        function showTriviaQuestion() {
            if (currentTriviaQuestion >= triviaQuestions.length) {
                endTriviaGame();
                return;
            }

            const question = triviaQuestions[currentTriviaQuestion];
            let html = `
                <h3>🧠 Question ${currentTriviaQuestion + 1}/${triviaQuestions.length}</h3>
                <p style="font-size: 1.2rem; margin: 20px 0;">${question.question}</p>
                <div id="triviaOptions">
            `;

            question.options.forEach((option, index) => {
                html += `
                    <div class="trivia-option" onclick="checkTriviaAnswer(${index})">
                        ${option}
                    </div>
                `;
            });

            html += `</div><p style="margin-top: 15px;">Score: ${triviaScore}</p>`;
            document.getElementById('offlineContent').innerHTML = html;
        }

        function checkTriviaAnswer(selectedIndex) {
            const question = triviaQuestions[currentTriviaQuestion];
            const options = document.querySelectorAll('.trivia-option');
            
            options.forEach((option, index) => {
                if (index === question.answer) {
                    option.classList.add('trivia-correct');
                } else if (index === selectedIndex && index !== question.answer) {
                    option.classList.add('trivia-wrong');
                }
                option.style.pointerEvents = 'none';
            });

            if (selectedIndex === question.answer) {
                triviaScore++;
                playSoundFeedback(true);
            } else {
                playSoundFeedback(false);
            }

            setTimeout(() => {
                currentTriviaQuestion++;
                showTriviaQuestion();
            }, 2000);
        }

        function playSoundFeedback(isCorrect) {
            if (!submissionProtector.audioEnabled) return;
            
            try {
                const context = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = context.createOscillator();
                const gainNode = context.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(context.destination);
                
                oscillator.frequency.value = isCorrect ? 800 : 300;
                oscillator.type = 'sine';
                
                gainNode.gain.setValueAtTime(0.3, context.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, context.currentTime + 0.5);
                
                oscillator.start(context.currentTime);
                oscillator.stop(context.currentTime + 0.5);
            } catch (e) {
                console.log('Web Audio API not supported');
            }
        }

        function endTriviaGame() {
            let message = '';
            if (triviaScore === triviaQuestions.length) {
                message = "🎉 Perfect! You're a Harambee Cash expert!";
                unlockAchievement('trivia_master');
            } else if (triviaScore >= triviaQuestions.length / 2) {
                message = "👍 Great job! You know your stuff!";
            } else {
                message = "💪 Keep learning! Read the tips to improve!";
            }

            document.getElementById('offlineContent').innerHTML = `
                <div style="text-align: center; padding: 30px;">
                    <h3>🏆 Trivia Complete!</h3>
                    <p>Final Score: ${triviaScore}/${triviaQuestions.length}</p>
                    <p>${message}</p>
                    <button class="offline-btn" onclick="startTriviaGame()">Play Again</button>
                </div>
            `;
        }

        function showGamingTips() {
            const tips = [
                "💰 Set a budget before you start playing and stick to it",
                "⏰ Take regular breaks - don't play for more than 1 hour continuously",
                "🎯 Understand the game rules completely before playing",
                "💡 Never chase losses - if you're losing, take a break",
                "📊 Keep track of your wins and losses",
                "🎮 Remember: Gaming should be fun, not a source of income",
                "🔄 Try different strategies in practice mode first",
                "📱 Install the app for better experience and notifications"
            ];

            let html = '<h3>📚 Smart Gaming Tips</h3><ul style="text-align: left; margin: 20px;">';
            tips.forEach(tip => {
                html += `<li style="margin: 10px 0; padding: 10px; background: rgba(0,201,177,0.1); border-radius: 8px;">${tip}</li>`;
            });
            html += '</ul><button class="offline-btn" onclick="showPracticeMode()">Next: Practice Strategies</button>';

            document.getElementById('offlineContent').innerHTML = html;
            unlockAchievement('knowledge_seeker');
        }

        function showPracticeMode() {
            document.getElementById('offlineContent').innerHTML = `
                <div style="text-align: center;">
                    <h3>💪 Practice Strategies</h3>
                    <p>Think through these scenarios to improve your gameplay:</p>
                    
                    <div style="text-align: left; margin: 20px 0;">
                        <div class="game-result">
                            <h4>Scenario 1: Winning Streak</h4>
                            <p>You've won 3 games in a row. What should you do?</p>
                            <p><em>Answer: Consider taking a break or setting aside some winnings.</em></p>
                        </div>
                        
                        <div class="game-result">
                            <h4>Scenario 2: Losing Streak</h4>
                            <p>You've lost 5 consecutive games. Your next move?</p>
                            <p><em>Answer: Take a break, don't chase losses. Come back fresh later.</em></p>
                        </div>
                        
                        <div class="game-result">
                            <h4>Scenario 3: Budget Management</h4>
                            <p>You've reached your daily budget limit but want to play more.</p>
                            <p><em>Answer: Stop playing. Stick to your budget always.</em></p>
                        </div>
                    </div>
                    
                    <button class="offline-btn" onclick="startTriviaGame()">Test Your Knowledge</button>
                </div>
            `;
        }

        function unlockAchievement(achievementId) {
            if (achievements[achievementId] && !achievements[achievementId].unlocked) {
                achievements[achievementId].unlocked = true;
                showAchievementNotification(achievements[achievementId].name);
                saveAchievements();
            }
        }

        function showAchievementNotification(achievementName) {
            const notification = document.createElement('div');
            notification.className = 'achievement-notification';
            notification.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem;">🏆</div>
                    <h4 style="margin: 10px 0;">Achievement Unlocked!</h4>
                    <p style="margin: 0;">${achievementName}</p>
                </div>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideInRight 0.5s ease-out reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 500);
            }, 3000);
        }

        function viewAchievements() {
            let html = '<h3>🏆 My Achievements</h3><div style="text-align: left;">';
            
            Object.keys(achievements).forEach(achievementId => {
                const achievement = achievements[achievementId];
                html += `
                    <div style="padding: 15px; margin: 10px 0; background: ${achievement.unlocked ? 'var(--success)' : 'var(--dark-card)'}; color: white; border-radius: 10px; border: 1px solid ${achievement.unlocked ? 'var(--success)' : 'var(--text-muted)'};">
                        <strong>${achievement.unlocked ? '✅' : '🔒'} ${achievement.name}</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9rem;">${achievement.description}</p>
                    </div>
                `;
            });
            
            html += '</div>';
            document.getElementById('offlineContent').innerHTML = html;
        }

        function saveAchievements() {
            try {
                localStorage.setItem('harambeeAchievements', JSON.stringify(achievements));
            } catch (e) {
                console.error('Error saving achievements:', e);
            }
        }

        function loadAchievements() {
            try {
                const saved = localStorage.getItem('harambeeAchievements');
                if (saved) {
                    const loaded = JSON.parse(saved);
                    Object.keys(loaded).forEach(key => {
                        if (achievements[key]) {
                            achievements[key].unlocked = loaded[key].unlocked;
                        }
                    });
                }
            } catch (e) {
                console.error('Error loading achievements:', e);
            }
        }

        function updateOnlineStatus() {
            const offlineBanner = document.getElementById('offlineBanner');
            const offlineEntertainment = document.getElementById('offlineEntertainment');
            
            if (!navigator.onLine) {
                offlineBanner.style.display = 'block';
                offlineEntertainment.style.display = 'block';
                unlockAchievement('offline_explorer');
            } else {
                offlineBanner.style.display = 'none';
                offlineEntertainment.style.display = 'none';
            }
        }

        function handlePlayClick(event) {
            if (window.submissionProtector &&         (submissionProtector.isSubmitting || submissionProtector.userEnrolled)) {
                event.preventDefault();
                event.stopImmediatePropagation();
        
                // Show immediate feedback
                if (submissionProtector.isSubmitting) {
                    submissionProtector.showTemporaryMessage('⏳ Processing your previous request...', 'warning');
                } else if (submissionProtector.userEnrolled) {
                    submissionProtector.showTemporaryMessage('✅ Already enrolled in current game!', 'message');
                }
        
                return false;
            }
            return true;
        }

        // Initialize everything when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {
            const submissionProtector = new SubmissionProtector();
            submissionProtector.initialize();

            // PWA Service Worker
            if ('serviceWorker' in navigator) {  
                navigator.serviceWorker.register('{{ url_for("static", filename="service-worker.js") }}')  
                    .then(reg => console.log('✅ Service Worker registered:', reg))  
                    .catch(err => console.log('❌ Service Worker registration failed:', err));  
            }

            // PWA Install Prompt
            let deferredPrompt;
            const installBtn = document.getElementById('install-btn');
            
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                deferredPrompt = e;
                installBtn.style.display = 'block';
            });

            installBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    const { outcome } = await deferredPrompt.userChoice;
                    
                    if (outcome === 'accepted') {
                        installBtn.style.display = 'none';
                        unlockAchievement('app_installer');
                    }
                    deferredPrompt = null;
                }
            });
            
            window.addEventListener('appinstalled', () => {
                installBtn.style.display = 'none';
            });

            // Network status monitoring
            window.addEventListener('online', updateOnlineStatus);
            window.addEventListener('offline', updateOnlineStatus);
            updateOnlineStatus();

            // Load achievements
            loadAchievements();

            // Time display
            function updateLocalTime() {  
                const time = new Date();  
                const formatter = new Intl.DateTimeFormat('en-KE', {  
                    dateStyle: 'full',  
                    timeStyle: 'medium',  
                    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,  
                    hour12: false  
                });  
                document.getElementById("timestamp-display").textContent =  
                    `🕒 ${formatter.format(time)}`;  
            }  

            updateLocalTime();  
            setInterval(updateLocalTime, 1000);  

            {% if session.get('user_id') %}
            // Game data fetching for logged-in users
            function fetchGameData() {
                fetch("/game_data")
                    .then(response => {
                        if (!response.ok) throw new Error('Network response was not ok');
                        return response.json();
                    })
                    .then(data => {
                        document.getElementById("next-game").textContent = data.upcoming_game
                            ? `${data.upcoming_game.game_code} at ${data.upcoming_game.timestamp} (${data.upcoming_game.outcome_message})`
                            : "No active game";

                        let resultsContainer = document.getElementById("game-results");
                        resultsContainer.innerHTML = "";
                        data.completed_games.forEach(game => {
                            resultsContainer.innerHTML += `
                                <div class="game-result">
                                    <p><strong>🎯 Game Code:</strong> ${game.game_code}</p>
                                    <p><strong>🕒 Timestamp:</strong> ${game.timestamp}</p>
                                    <p><strong>👥 Players:</strong> ${game.num_users}</p>
                                    <p><strong>💰 Total Amount:</strong> ${game.total_amount}</p>
                                    <p><strong>🏆 Winner:</strong> ${game.winner}</p>
                                    <p><strong>🎁 Win Amount:</strong> ${game.winner_amount}</p>
                                    <p><strong>📊 Outcome:</strong> ${game.outcome_message}</p>
                                </div>
                            `;
                        });

                        if (data.current_user_queued) {
                            submissionProtector.handleSubmissionSuccess('✅ Already enrolled in current game');
                        }
                    })
                    .catch(error => {
                        console.error("Error fetching game data:", error);
                        document.getElementById("next-game").textContent = "Error loading game data";
                    });
            }

            fetchGameData();  
            setInterval(fetchGameData, 9000);

            // Initialize game animator
            const gameAnimator = new GameAnimator();
            gameAnimator.monitorGameStatus();
            window.gameAnimator = gameAnimator;
            {% endif %}  

            // Auto-clear messages
            setTimeout(() => {
                const errorElements = document.querySelectorAll('.error');
                const messageElements = document.querySelectorAll('.message');
                const warningElements = document.querySelectorAll('.warning');
                
                errorElements.forEach(el => el.style.display = 'none');
                messageElements.forEach(el => el.style.display = 'none');
                warningElements.forEach(el => el.style.display = 'none');
            }, 9000);

            // Handle URL parameters for form responses
            const urlParams = new URLSearchParams(window.location.search);
            
            if (urlParams.has('message')) {
                const message = urlParams.get('message');
                if (message.includes('Successfully enrolled') || message.includes('already enrolled')) {
                    submissionProtector.handleSubmissionSuccess(message);
                }
            }
            
            if (urlParams.has('error')) {
                submissionProtector.handleSubmissionError();
            }

            // Make objects globally available
            window.submissionProtector = submissionProtector;
            window.handlePlayClick = handlePlayClick;
        });
    </script>
</body>  
</html>
"""

register_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Register â€“ Harambee Cash</title>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}" />
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #a8edea, #fed6e3); display:flex; align-items:center; justify-content:center; height:100vh; margin:0; color:#333; }
        .register-container { background:#ffffffee; padding:30px; border-radius:20px; box-shadow:0 6px 20px rgba(0,0,0,0.2); max-width:400px; width:90%; }
        h2 { color:#4caf50; margin-bottom:20px; font-size:1.8rem; text-align:center; }
        .error { color:#e53935; text-align:center; margin-bottom:10px; }
        .message { color:#43a047; text-align:center; margin-bottom:10px; }
        label { display:block; margin-bottom:5px; color:#4caf50; }
        input { width:100%; padding:12px; margin-bottom:15px; border:2px solid #4caf50; border-radius:8px; background:#f9fff9; }
        button { width:100%; padding:12px; background:#4caf50; border:none; color:white; font-weight:bold; border-radius:10px; cursor:pointer; transition:background 0.3s ease; }
        button:hover { background:#388e3c; }
        .back-link { text-align:center; margin-top:15px; }
        .back-link a { color:#4caf50; text-decoration:none; font-weight:bold; }
    </style>
</head>
<body>
    <div class="register-container">
        <h2>Create Account</h2>

        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if message %}<p class="message">{{ message }}</p>{% endif %}

        <form method="POST" action="/register">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="email">Email:</label>
            <input type="email" name="email" id="email" required />

            <label for="username">Username (Tel Number):</label>
            <input type="text" name="username" id="username" required />

            <label for="password">Password:</label>
            <input type="password" name="password" id="password" required />

            <button type="submit">Register</button>
        </form>

        <div class="back-link">
            <p>Already have an account? <a href="/login">Login</a></p>
            <p><a href="/">â† Back to Home</a></p>
        </div>
    </div>
</body>
</html>
"""

login_html = """  
<!DOCTYPE html>  
<html lang="en">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>Login - HARAMBEE CASH!</title>  
    <style>  
        body { font-family: Arial, sans-serif; margin:0; padding:0; display:flex; justify-content:center; align-items:center; min-height:100vh; background:linear-gradient(to right,#ff7e5f,#feb47b); color:white; }
        .container { width:90%; max-width:400px; padding:20px; background:rgba(0,0,0,0.8); border-radius:15px; text-align:center; box-sizing:border-box; }
        h1 { font-size:1.8rem; margin-bottom:15px; color:#ffcc00; }
        .error { color:#ffcccb; font-weight:bold; margin-bottom:10px; }
        .message { color:#43a047; font-weight:bold; margin-bottom:10px; }
        form { display:flex; flex-direction:column; gap:15px; }
        label { font-size:1rem; text-align:left; color:#ffcccb; }
        input, button { padding:10px; font-size:1rem; border-radius:5px; width:100%; box-sizing:border-box; }
        input { border:1px solid #ccc; background:rgba(255,255,255,0.1); color:white; }
        button { background-color:#4CAF50; color:white; cursor:pointer; border:none; transition:background-color 0.3s ease; font-weight:bold; }
        button:hover { background-color:#45a049; }
        a { color:#4CAF50; text-decoration:none; font-weight:bold; }
        a:hover { color:#45a049; text-decoration:underline; }
    </style>  
</head>  
<body>  
    <div class="container">  
        <h1>Login</h1>  
        {% if error %} <p class="error">{{ error }}</p> {% endif %}  
        {% if message %} <p class="message">{{ message }}</p> {% endif %}  
        <form method="POST" action="/login" id="loginForm" autocomplete="on">  
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="username">Username:</label>  
            <input type="text" id="username" name="username" required autocomplete="username" placeholder="Enter your username">  
            <label for="password">Password:</label>  
            <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="Enter your password">  
            <button type="submit">Login</button>  
        </form>  
        <p>Don't have an account? <a href="/register">Register</a></p>  
    </div>  
    <script>  
        document.getElementById('loginForm').addEventListener('submit', function() {  
            console.log('Login form submitted');  
        });  
        {% if session.get('user_id') %}  
        setTimeout(function() {  
            const form = document.getElementById('loginForm');  
            if (form) { form.style.display = 'none'; console.log('Successful login detected'); }  
        }, 500);  
        {% endif %}  
    </script>  
</body>  
</html>  
"""

admin_login_html = """  
<!DOCTYPE html>  
<html lang="en">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>Admin Login - HARAMBEE CASH!</title>  
    <style>  
        body { font-family: Arial, sans-serif; margin:0; padding:0; display:flex; justify-content:center; align-items:center; min-height:100vh; background:linear-gradient(to right,#43cea2,#185a9d); color:white; }
        .container { width:90%; max-width:400px; padding:20px; background:rgba(0,0,0,0.8); border-radius:15px; text-align:center; box-sizing:border-box; }
        h1 { font-size:1.8rem; margin-bottom:15px; color:#ffcc00; }
        .error { color:#ffcccb; font-weight:bold; margin-bottom:10px; }
        form { display:flex; flex-direction:column; gap:15px; }
        label { font-size:1rem; text-align:left; color:#ffcccb; }
        input, button { padding:10px; font-size:1rem; border-radius:5px; width:100%; box-sizing:border-box; }
        input { border:1px solid #ccc; background:rgba(255,255,255,0.1); color:white; }
        button { background-color:#4CAF50; color:white; cursor:pointer; border:none; transition:background-color 0.3s ease; font-weight:bold; }
        button:hover { background-color:#45a049; }
    </style>  
</head>  
<body>  
    <div class="container">  
        <h1>Admin Login</h1>  
        {% if error %} <p class="error">{{ error }}</p> {% endif %}  
        <form method="POST" action="/admin/login" id="adminLoginForm" autocomplete="on">  
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="adminUsername">Username:</label>  
            <input type="text" id="adminUsername" name="username" required autocomplete="username" placeholder="Admin username">  
            <label for="adminPassword">Password:</label>  
            <input type="password" id="adminPassword" name="password" required autocomplete="current-password" placeholder="Admin password">  
            <button type="submit">Login</button>  
        </form>  
    </div>  
    <script>  
        document.getElementById('adminLoginForm').addEventListener('submit', function() { console.log('Admin login submitted'); });  
    </script>  
</body>  
</html>  
"""

admin_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - HARAMBEE CASH!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(to right, #43cea2, #185a9d);
            color: white;
        }
        .container {
            width: 90%;
            max-width: 800px;
            padding: 20px;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 15px;
            text-align: center;
            box-sizing: border-box;
        }
        h1 {
            font-size: 2rem;
            margin-bottom: 15px;
            color: #ffcc00;
        }
        h2 {
            font-size: 1.5rem;
            margin-top: 20px;
            color: #ffcc00;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ccc;
            text-align: center;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background: rgba(255, 255, 255, 0.1);
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
            text-align: left;
        }
        label {
            font-size: 1rem;
            font-weight: bold;
            color: #ffcccb;
        }
        input, select, button {
            padding: 10px;
            font-size: 1rem;
            border-radius: 5px;
            border: 1px solid #ccc;
            width: 100%;
            box-sizing: border-box;
        }
        input {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        input:focus {
            border-color: #ff9900;
            outline: none;
        }
        select {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        button {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
            border: none;
            transition: background-color 0.3s ease;
            font-weight: bold;
        }
        button:hover {
            background-color: #45a049;
        }
        .error {
            color: #ffcccb;
            font-weight: bold;
            margin-bottom: 10px;
        }
        a {
            display: inline-block;
            margin-top: 20px;
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
            transition: color 0.3s ease;
        }
        a:hover {
            color: #ff9900;
            text-decoration: underline;
        }

        .monitor-btn {
            margin-top: 25px;
            padding: 12px;
            background-color: #ff5722;
            color: white;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
        }
        .monitor-btn:hover {
            background-color: #e64a19;
        }

        .activity-table th {
            background-color: #3f51b5;
        }
        
        .cashbook-btn {
            margin-top: 25px;
            padding: 12px;
            background-color: #2196F3;
            color: white;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
        }
        .cashbook-btn:hover {
            background-color: #1976D2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Dashboard</h1>
        {% if error %} <p class="error">{{ error }}</p> {% endif %}
        {% if message %} <p class="message">{{ message }}</p> {% endif %}

        <h2>All Users</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Wallet Balance</th>
                </tr>
            </thead>
            <tbody>
                {% for user in users %}
                <tr>
                    <td>{{ user[0] }}</td>
                    <td>{{ user[2] }}</td>
                    <td>{{ user[1] }}</td>
                    <td>Ksh. {{ user[4] | round(2) }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Update User Wallet</h2>
        <form method="POST" action="/admin/update_wallet">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="user_id">User ID:</label>
            <input type="text" id="user_id" name="user_id" required>
            <label for="amount">Amount:</label>
            <input type="number" id="amount" name="amount" step="0.01" required>
            <label for="action">Action:</label>
            <select id="action" name="action" required>
                <option value="deposit">Deposit</option>
                <option value="withdraw">Withdraw</option>
            </select>
            <button type="submit">Update Wallet</button>
        </form>

        <h2>Add Allowed Username</h2>
        <form method="POST" action="/admin/add_allowed_user">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="allowed_username">Username:</label>
            <input type="text" id="allowed_username" name="allowed_username" required>
            <button type="submit">Add Allowed User</button>
        </form>

        <button class="monitor-btn" onclick="window.location.href='/admin/visitor_log'">View Visitor Log</button>
        <button class="cashbook-btn" onclick="window.location.href='/cashbook'">ðŸ’° View Gross Profit Dashboard</button>

        <h2>Recent User Activity (Last 100)</h2>
        <table class="activity-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Username</th>
                    <th>IP</th>
                    <th>Path</th>
                    <th>Method</th>
                    <th>User Agent</th>
                    <th>Referrer</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr>
                    <td>{{ log[1] }}</td>
                    <td>{{ log[2] or 'Guest' }}</td>
                    <td>{{ log[3] }}</td>
                    <td>{{ log[4] }}</td>
                    <td>{{ log[5] }}</td>
                    <td>{{ log[6][:60] }}{% if log[6]|length > 60 %}...{% endif %}</td>
                    <td>{{ log[7] or '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <button class="cashbook-btn" onclick="window.location.href='/admin/withdrawals'" 
                style="background-color: #9C27B0; margin-top: 15px;">
            ðŸ’³ Manage Withdrawals
        </button>
        
        <a href="/admin/logout">Logout</a>
    </div>
    <script>
    // Auto-refresh admin data every 1 hour
    function refreshAdminData() {
        location.reload();
    }

    // 1 hour = 60 minutes * 60 seconds * 1000 milliseconds
    setTimeout(refreshAdminData, 3600000);

    // Auto-clear admin messages after 1 hour
    setTimeout(() => {
        const errorElements = document.querySelectorAll('.error');
        const messageElements = document.    querySelectorAll('.message');
    
        errorElements.forEach(el => el.style.display = 'none');
        messageElements.forEach(el => el.style.display = 'none');
    }, 3600000);
    </script>
</body>
</html>
"""

TERMS_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
     crossorigin="anonymous"></script>
    <meta charset="UTF-8">
    <title>Terms and Conditions | Harambee Cash</title> 
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f2f2;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        h1 {
            text-align: center;
            color: #006400;
        }
        p, li {
            line-height: 1.6;
            font-size: 16px;
        }
        ul {
            padding-left: 20px;
        }
        footer {
            text-align: center;
            margin-top: 30px;
            font-size: 14px;
            color: #666;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #006400;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
        .container {
            background: #fff;
            padding: 25px;
            border-radius: 10px;
            max-width: 800px;
            margin: 0 auto;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Terms and Conditions</h1>
        
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
        crossorigin="anonymous"></script>
        <ins class="adsbygoogle"
            style="display:block"
            data-ad-client="ca-pub-5190046541953794"
            data-ad-slot="2953235853"
            data-ad-format="auto"
            data-full-width-responsive="true"></ins>
        <script>
            (adsbygoogle = window.adsbygoogle || []).push({});
        </script>      
        
        <p><strong>Last Updated:</strong> 6th February 2025</p>
        <p>Welcome to <strong>Harambee Cash</strong> â€” your platform for exciting gameplay and rewards! Before getting started, please read through our Terms and Conditions carefully. By using our platform, you agree to these terms.</p>

        <h3>1. Acceptance of Terms</h3>
        <p>By accessing or using Harambee Cash, you agree to comply with these Terms and Conditions. If you do not agree with any part, please do not use the platform.</p>

        <h3>2. Eligibility</h3>
        <ul>
            <li>You must be at least 18 years old to participate.</li>
            <li>You are responsible for providing accurate and updated information during registration.</li>
        </ul>

        <h3>3. Account Registration</h3>
        <ul>
            <li>An account is required to access the platform's features.</li>
            <li>Keep your login credentials secureâ€”you are accountable for all activity under your account.</li>
        </ul>

        <h3>4. Game Rules</h3>
        <ul>
            <li>A minimum wallet balance of Ksh. 1.00 is required to participate.</li>
            <li>The game runs every 30 seconds. You can join anytime by pressing the <strong>Play</strong> button.</li>
            <li>10% of the prize pool is deducted as a platform fee; the rest is awarded to the winner.</li>
        </ul>

        <h3>5. Wallet and Transactions</h3>
        <ul>
            <li>You may deposit or withdraw funds via the platform.</li>
            <li>If automation fails or is undergoing maintenance, you may contact the <strong>Super Admin</strong> listed in the app for assistance.</li>
            <li>Transaction history is available upon request.</li>
        </ul>

        <h3>6. Prohibited Activities</h3>
        <ul>
            <li>Fraudulent or illegal activities are strictly prohibited.</li>
            <li>Any manipulation or abuse of the game system will result in account suspension and possible legal action.</li>
        </ul>

        <h3>7. Limitation of Liability</h3>
        <p>Harambee Cash is provided "as is." We do not guarantee uninterrupted service and are not responsible for any losses or damages incurred through platform use.</p>

        <h3>8. Amendments</h3>
        <p>We may update these terms from time to time. Continued use of the platform indicates your acceptance of any changes.</p>

        <footer>
            <p>&copy; 2025 Pigasimu. All rights reserved.</p>
        </footer>
        <a href="/">â† Back to Home</a>
    </div> 
</body>
</html>
"""

PRIVACY_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
     crossorigin="anonymous"></script>
    <meta charset="UTF-8">
    <title>Privacy Policy | Harambee Cash</title>    
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f2f2;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        h1 {
            text-align: center;
            color: #006400;
        }
        p, li {
            line-height: 1.6;
            font-size: 16px;
        }
        ul {
            padding-left: 20px;
        }
        footer {
            text-align: center;
            margin-top: 30px;
            font-size: 14px;
            color: #666;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #006400;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
        .container {
            background: #fff;
            padding: 25px;
            border-radius: 10px;
            max-width: 800px;
            margin: 0 auto;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Privacy Policy</h1>
        
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
        crossorigin="anonymous"></script>
        <ins class="adsbygoogle"
            style="display:block"
            data-ad-client="ca-pub-5190046541953794"
            data-ad-slot="2953235853"
            data-ad-format="auto"
            data-full-width-responsive="true"></ins>
        <script>
            (adsbygoogle = window.adsbygoogle || []).push({});
        </script>        
        
        <p><strong>Last Updated:</strong> 6th February 2025</p>
        <p>At <strong>Harambee Cash</strong>, your privacy is a top priority. This Privacy Policy outlines how we collect, use, and protect your personal data when you interact with our platform.</p>

        <h3>1. Information We Collect</h3>
        <ul>
            <li><strong>Personal Information:</strong> Such as your email, username, and password during registration.</li>
            <li><strong>Financial Information:</strong> Including your wallet balance and transaction history.</li>
            <li><strong>Usage Data:</strong> Such as login timestamps, game activity, and IP addresses.</li>
        </ul>

        <h3>2. How We Use Your Information</h3>
        <ul>
            <li>To operate, maintain, and improve the platform experience.</li>
            <li>To process payments, update wallet balances, and manage your account.</li>
            <li>To communicate with you about updates, support, or promotional offers.</li>
        </ul>

        <h3>3. Data Security</h3>
        <ul>
            <li>We use industry-standard security protocols to safeguard your information.</li>
            <li>Passwords are encrypted and not accessible to anyone, including our team.</li>
        </ul>

        <h3>4. Third-Party Sharing</h3>
        <p>We do not sell or share your personal data with third parties unless required by law.</p>

        <h3>5. Cookies</h3>
        <p>Our site uses cookies to enhance your experience. You can manage cookie settings in your browser, though disabling them may impact site functionality.</p>

        <h3>6. Your Rights</h3>
        <ul>
            <li>You may request to access, update, or delete your personal data at any time.</li>
            <li>You may opt out of promotional emails and notifications if applicable.</li>
        </ul>

        <h3>7. Changes to This Policy</h3>
        <p>We may revise this policy periodically. Any updates will be published on this page, and your continued use of the platform indicates your acceptance.</p>

        <footer>
            <p>&copy; 2025 Pigasimu. All rights reserved.</p>
        </footer>
        <a href="/">â† Back to Home</a>
    </div>   
</body>
</html>
"""

DOCS_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
     crossorigin="anonymous"></script>
    <meta charset="UTF-8">
    <title>Documentation | Harambee Cash</title>    
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f4f4;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        h1 {
            text-align: center;
            color: #006400;
        }
        h2 {
            margin-top: 30px;
            color: #444;
        }
        p, li {
            line-height: 1.6;
            font-size: 16px;
        }
        ul {
            padding-left: 20px;
        }
        .container {
            background: #fff;
            padding: 25px;
            border-radius: 10px;
            max-width: 900px;
            margin: auto;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        a {
            display: block;
            text-align: center;
            margin-top: 30px;
            color: #006400;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Harambee Cash Documentation</h1>
        
        <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
        crossorigin="anonymous"></script>
        <ins class="adsbygoogle"
            style="display:block"
            data-ad-client="ca-pub-5190046541953794"
            data-ad-slot="2953235853"
            data-ad-format="auto"
            data-full-width-responsive="true"></ins>
        <script>
            (adsbygoogle = window.adsbygoogle || []).push({});
        </script>        

        <h2>Overview</h2>
        <p>
            Harambee Cash is a web-based platform for participating in periodic games where winners are selected randomly from eligible users.
            The system supports user registration, wallet management, and administrative tools.
        </p>

        <h2>Key Features</h2>
        <ul>
            <li><strong>User Registration & Login:</strong> Users sign up with email, username, and password. Passwords are securely stored.</li>
            <li><strong>Wallet Management:</strong> Users can view their balances. Admins can deposit or withdraw funds.</li>
            <li><strong>Game Logic:</strong> A game runs every 30 seconds. Users with at least Ksh. 1.00 can enroll. A 10% fee is deducted from the pool; the winner gets the rest.</li>
            <li><strong>Admin Dashboard:</strong> Admins can manage users, view wallets, and process funds, especially for winners, until mobile money integration is complete (currently in progress).</li>
        </ul>

        <h2>Database Schema</h2>
        <ul>
            <li><strong>Users Table:</strong> Stores user data (email, username, password, wallet balance).</li>
            <li><strong>Admins Table:</strong> Stores admin login info.</li>
            <li><strong>Results Table:</strong> Logs game data (code, time, winner, pool amount, etc.).</li>
            <li><strong>Transactions Table:</strong> Tracks all wallet operations (type, amount, time).</li>
        </ul>

        <h2>API Endpoints</h2>
        <ul>
            <li><strong>GET /</strong> â€“ Homepage</li>
            <li><strong>POST /register</strong> â€“ Register a new user</li>
            <li><strong>POST /login</strong> â€“ User login</li>
            <li><strong>GET /logout</strong> â€“ User logout</li>
            <li><strong>POST /play</strong> â€“ Enroll in next game</li>
            <li><strong>GET /admin/login</strong> â€“ Admin login</li>
            <li><strong>GET /admin/dashboard</strong> â€“ Admin panel</li>
            <li><strong>GET /admin/logout</strong> â€“ Admin logout</li>
        </ul>

        <h2>Security Measures</h2>
        <ul>
            <li>Session timeout: 30-minute expiration for inactive users</li>
            <li>Password hashing using <code>bcrypt</code> (to be implemented)</li>
            <li>Input validation to prevent SQL injection and other attacks</li>
        </ul>

        <h2>Our future Enhancements plan</h2>
        <ul>
            <li>Sell APIs to startup developers to help them run similar businesses independently</li>
            <li>Provide employment opportunities through platform expansion</li>
            <li>Introduce periodic rewards or bonuses for highly active users</li>
            <li>Add email verification during signup</li>
            <li>Introduce 2FA (Two-Factor Authentication) for admins</li>
            <li>Complete mobile money integration for automatic payouts</li>
            <li>Introduce a referral system to reward users for inviting friends</li>
            <li>Add in-app notifications for game results, balance alerts, and new features</li>
            <li>Implement leaderboards and achievement badges to encourage competition</li>
            <li>Develop native mobile apps for Android and iOS users</li>
            <li>Integrate a real-time support chatbot for instant help and FAQs</li>
            <li>Enable downloadable transaction receipts and full account statements</li>
            <li>Add multi-language support for local and global audiences</li>
            <li>Build an advanced admin analytics dashboard for insights and reporting</li>
            <li>Launch an affiliate/franchise system for regional expansion via trusted agents</li>
            <li>Introduce user feedback and voting tools to guide new feature development</li>
        </ul>     

        <footer>
            <p>&copy; 2025 Pigasimu. All rights reserved.</p>
        </footer>
        <a href="/">â† Back to Home</a>
    </div>   
</body>
</html>
"""

# --- Background game loop start ---
@app.before_first_request
def start_background_game_loop():
    thread = threading.Thread(target=run_game, daemon=True)
    thread.start()

# --- Run ---
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
