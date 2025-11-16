#no edits new revert 3
import os
import json
import random
import time
import psycopg2
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, Response, stream_with_context, flash
from flask_wtf.csrf import CSRFProtect
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

# Use session ID if available, else fallback to IP address
def rate_limit_key():
    from flask import session
    return session.get("user_id") or get_remote_address()

# -----------------------------------------
# Configure Logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Flask App Initialization
app = Flask(__name__)
csrf = CSRFProtect(app)

# Global stop_event
stop_event = threading.Event()

limiter = Limiter(
    key_func=rate_limit_key,
    default_limits=[]  # No global limits
)
limiter.init_app(app)

# -----------------------------------------
# Configuring Environment Variables
app.secret_key = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')  # Optional if you need elsewhere
ADMIN_DATABASE = os.getenv('ADMIN_DATABASE')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Session lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

if not all([app.secret_key, ADMIN_USERNAME, ADMIN_PASSWORD]):
    raise RuntimeError("Missing required environment variables.")

# ----------------------------------------

def hash_password(password: str) -> str:
    """Hash passwords consistently using PBKDF2 (SHA256)."""
    return generate_password_hash(password.strip(), method='pbkdf2:sha256')

def verify_password(stored_hash: str, password: str) -> bool:
    """Verify stored hash using Werkzeug's checker."""
    return check_password_hash(stored_hash, password.strip())

# -----------------------------------------
# Helper Functions
def get_timestamp():
    """Returns the current timestamp in the format '%Y-%m-%d %H:%M:%S.%f' (no 'T')."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

def generate_game_code():
    """Generates a random 6-character game code."""
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))

# ----------------------------------------

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
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
        # Table for visitor logging
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
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                wallet NUMERIC DEFAULT 0.0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS game_queue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id SERIAL PRIMARY KEY,
                game_code TEXT UNIQUE,
                timestamp TEXT,
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
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS allowed_users (
                username TEXT PRIMARY KEY
            )
        """)
        conn.commit()

        # FIXED: Secure Admin Creation
        cursor.execute("SELECT 1 FROM admins WHERE username = %s LIMIT 1", (ADMIN_USERNAME,))
        exists = cursor.fetchone()

        if not exists:
            # ✅ HASH the password instead of storing plain text
            hashed_password = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256')
            cursor.execute("INSERT INTO admins (username, password) VALUES (%s, %s)", 
                         (ADMIN_USERNAME, hashed_password))
            conn.commit()
            logging.info(f"Admin user created: {ADMIN_USERNAME}")  # ✅ No password in logs

init_db()

def get_wallet_balance(user_id):
    """Fetches the wallet balance of a user."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT wallet FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        return float(result[0]) if result else 0.0  # Ensuring float return type

def update_wallet(user_id, amount):
    """Updates a user's wallet by adding or deducting an amount."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (amount, user_id))
        conn.commit()

def log_transaction(user_id, transaction_type, amount):
    """Logs a transaction for a user."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO transactions (user_id, type, amount, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (user_id, transaction_type, amount, get_timestamp()))
            conn.commit()
    except psycopg2.Error as e:
        logging.error(f"Database error in log_transaction(): {e}")
    except Exception as e:
        logging.error(f"Unexpected error in log_transaction(): {e}")
        
def log_visit():
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    referrer = request.referrer
    path = request.path
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Local time for timestamp

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO visit_logs (ip_address, user_agent, referrer, path, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (ip_address, user_agent, referrer, path, timestamp))
        conn.commit()        

# ================== ROUTES ================== #

@app.route("/static/<path:filename>")
def static_files(filename):
    """Serves static files."""
    return send_from_directory("static", filename)

@app.route("/", methods=["GET", "POST"])
def index():
    """Renders the homepage with user wallet balance and messages, and logs the visit."""
    
    # Log the visit for the current page
    log_visit()  # This will log the user's visit to the visit_logs table
    
    error = request.args.get("error")
    message = request.args.get("message")

    user_id = session.get("user_id")
    wallet_balance = get_wallet_balance(user_id) if user_id else 0.0

    return render_template_string(index_html,
                                  error=error,
                                  message=message,
                                  timestamp=get_timestamp(),
                                  wallet_balance=wallet_balance)


@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_login():
    """Handles admin login and session management."""
    # FIXED: No debug information leaked
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM admins WHERE username = %s", (username,))
            admin = cursor.fetchone()

            if admin and admin[1] == password:
                session["admin_id"] = admin[0]
                session["is_admin"] = True
                
                response = redirect(url_for("admin_dashboard"))
                response.headers['X-Frame-Options'] = 'SAMEORIGIN'
                return response
            else:
                # FIXED: Generic error message - no specific details
                return render_template_string(admin_login_html, error="Invalid admin credentials.")
                
    # FIXED: Always pass error as None for GET requests
    return render_template_string(admin_login_html, error=None)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """Handles user login securely with password manager support."""
    # If user is already logged in, redirect to index
    if session.get('user_id'):
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            # Check if username exists in allowed_users
            cursor.execute("SELECT 1 FROM allowed_users WHERE username = %s", (username,))
            allowed = cursor.fetchone()

            if user and check_password_hash(user[2], password) and allowed:
                session['user_id'] = user[0]
                session['username'] = user[1]
                
                # CRITICAL: Return proper redirect for password manager
                response = redirect(url_for("index"))
                # Add cache control headers
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
                return response
            else:
                return render_template_string(login_html, error="Invalid credentials or access not allowed.")

    return render_template_string(login_html, error=None)

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if not all([email, username, password]):
            return render_template_string(register_html, error="All fields are required.")

        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT 1 FROM allowed_users WHERE username = %s", (username,))
            if cursor.fetchone() is None:
                return render_template_string(register_html, error="""
                Registration not allowed for this username.<br>
                Kindly contact the Senior Admin to whitelist it.<br>
                Alternatively, send any amount to <strong>0701207062</strong> via M-Pesa.<br>
                The sender number will be whitelisted and credited automatically. Then try again.
                """)

            # ✅ FIX: Explicitly use PBKDF2 for compatibility
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            try:
                cursor.execute(
                    "INSERT INTO users (email, username, password) VALUES (%s, %s, %s)",
                    (email, username, hashed_password)
                )
                conn.commit()
                return redirect(url_for("login", message="Registration successful! Please log in."))
            except psycopg2.IntegrityError as e:
                from psycopg2.errors import UniqueViolation
                if isinstance(e.__cause__, UniqueViolation):
                    return render_template_string(register_html, error="Email or username already exists.")
                else:
                    logging.error(f"Database error during registration: {e}")
                    return render_template_string(register_html, error="An error occurred. Please try again.")

    return render_template_string(register_html)

@app.route("/offline")
def offline():
    return """
    <html><head><title>Offline</title></head>
    <body style="text-align:center;padding:40px;font-family:sans-serif;">
        <h1>You’re Offline</h1>
        <p>It looks like you don’t have an internet connection.</p>
        <p>Try again when you're back online.</p>
    </body></html>
    """
    
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/service-worker.js')
def sw():
    return send_from_directory('static', 'service-worker.js')    

# Add the missing /logout route
@app.route("/logout")
def logout():
    """Logs out the user and clears their session."""
    session.pop('user_id', None)
    session.pop('username', None)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("index"))
    
@app.route('/robots.txt')
def robots_txt():
    return (
        "User-agent: *\nDisallow:\n",
        200,
        {'Content-Type': 'text/plain'}
    )

@app.route("/stream")
def stream():
    """Streams live game updates to the client."""

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

                time.sleep(1)  # Avoid excessive CPU usage

            except psycopg2.Error as e:
                logging.error(f"Database error in streaming: {e}")
                break  # Stop the loop on DB failure

            except GeneratorExit:
                logging.info("Client disconnected from stream.")
                break  # Stop streaming if the client disconnects

            except Exception as e:
                logging.error(f"Unexpected error in event stream: {e}")
                break

    return Response(stream_with_context(event_stream()), content_type="text/event-stream")

@app.route("/privacy")
def privacy():
    return render_template_string(PRIVACY_CONTENT)

@app.route("/terms")
def terms():
    return render_template_string(TERMS_CONTENT)

@app.route("/docs")
def docs():
    return render_template_string(DOCS_CONTENT)


@app.route("/game_data")
def game_data():
    """Fetches the latest game data, including upcoming, in-progress, and last 5 completed games."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Fetch upcoming game
            cursor.execute("SELECT game_code, timestamp FROM results WHERE status = 'upcoming' ORDER BY timestamp DESC LIMIT 1")
            upcoming_game = cursor.fetchone()
            upcoming_game_data = {
                "game_code": upcoming_game[0] if upcoming_game else "N/A",
                "timestamp": upcoming_game[1] if upcoming_game else "N/A",
                "outcome_message": "Upcoming"
            } if upcoming_game else None

            # Fetch in-progress game
            cursor.execute("SELECT game_code, num_users FROM results WHERE status = 'in progress' ORDER BY timestamp DESC LIMIT 1")
            in_progress_game = cursor.fetchone()
            in_progress_game_data = {
                "game_code": in_progress_game[0] if in_progress_game else "N/A",
                "num_users": in_progress_game[1] if in_progress_game else 0,
                "outcome_message": "In Progress"
            } if in_progress_game else None

            # Fetch last 5 completed games
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
                    "outcome_message": "Completed"
                }
                for game in completed_games
            ] if completed_games else []

        response_data = {
            "upcoming_game": upcoming_game_data or {"game_code": "N/A", "timestamp": "N/A", "outcome_message": "No upcoming games"},
            "in_progress_game": in_progress_game_data or {"game_code": "N/A", "num_users": 0, "outcome_message": "No games in progress"},
            "completed_games": completed_games_data if completed_games_data else [{"game_code": "N/A", "outcome_message": "No completed games"}]
        }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/play", methods=["POST"])
@limiter.limit("3 per minute")
def play():
    """Handles user enrollment into the next game round."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("index", error="You must be logged in to play."))

    wallet_balance = get_wallet_balance(user_id)
    if wallet_balance is None or wallet_balance < 50.0:
        return redirect(url_for("index", error="Insufficient funds. Please deposit."))

    conn = None  # Ensure conn is defined before use

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Check if the user is already in the queue
            cursor.execute("SELECT user_id FROM game_queue WHERE user_id = %s", (user_id,))
            if cursor.fetchone():
                return redirect(url_for("index", error="You are already in the queue."))

            # Add user to the game queue (DO NOT DEDUCT HERE)
            cursor.execute("INSERT INTO game_queue (user_id, timestamp) VALUES (%s, %s)",
                          (user_id, get_timestamp()))
            conn.commit()

            # Check the latest game status
            cursor.execute("SELECT status FROM results ORDER BY timestamp DESC LIMIT 1")
            latest_game = cursor.fetchone()
            if latest_game and latest_game[0] == "completed":
                message = "The game is over! Check for results below and play again to try your luck!"
            else:
                message = "Enrolled in the next round!"

        return redirect(url_for("index", message=message))

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error during enrollment: {str(e)}")  # Internal logging
        return redirect(url_for("index", error="An error occurred while enrolling. Please try again."))

@app.route("/admin/add_allowed_user", methods=["POST"])
def admin_add_allowed_user():
    """Allows the admin to add a username to the allowed list."""
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
def admin_dashboard():
    """Displays the admin dashboard."""
    if not session.get("is_admin"):
        return redirect(url_for("admin_login", error="Please log in as an admin."))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id ASC")
        users = cursor.fetchall()

        # Fetch recent 100 user activities
        cursor.execute("SELECT * FROM user_activity ORDER BY timestamp DESC LIMIT 100")
        logs = cursor.fetchall()

    return render_template_string(
        admin_html,
        users=users,
        logs=logs,
        error=request.args.get("error"),
        message=request.args.get("message")
    )


@app.route("/admin/update_wallet", methods=["POST"])
def admin_update_wallet():
    """Allows the admin to update a user's wallet balance."""
    if not session.get("is_admin"):  # More secure check
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

            # Ensure user exists
            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            if not cursor.fetchone():
                return redirect(url_for("admin_dashboard", error="User not found."))

            if action == "deposit":
                update_wallet(user_id, amount)
                log_transaction(user_id, "deposit", amount)

            elif action == "withdraw":
                wallet_balance = get_wallet_balance(user_id)
                if wallet_balance is None or wallet_balance < amount:  # Prevents NoneType errors
                    return redirect(url_for("admin_dashboard", error="Insufficient balance for withdrawal."))

                update_wallet(user_id, -amount)
                log_transaction(user_id, "withdrawal", amount)

        return redirect(url_for("admin_dashboard", message="Wallet updated successfully."))

    except ValueError:
        return redirect(url_for("admin_dashboard", error="Invalid amount. Please enter a valid number."))
        
@app.route("/admin/visitor_log")
def view_visits():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/admin/login")

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
    """, logs=logs)
    
index_html = """
<!DOCTYPE html>
<html lang="en">  
<head>
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
     crossorigin="anonymous"></script>
    <meta charset="UTF-8" />  
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />  
    <title>HARAMBEE CASH - Play & Win Big!</title>  
    <link rel="manifest" href="{{ url_for('static', filename='manifest.json') }}" />  
    <meta name="theme-color" content="#FF6B35" />  
    <link rel="icon" type="image/png" href="{{ url_for('static', filename='favicon.ico') }}" />  
    <link rel="apple-touch-icon" href="{{ url_for('static', filename='apple-touch-icon.png') }}" />  
    <style>  
        :root {
            --primary: #FF6B35;
            --primary-dark: #E55A2B;
            --secondary: #00C9B1;
            --accent: #FFD166;
            --light: #FFFFFF;
            --dark: #2D3047;
            --gray: #6C757D;
            --success: #28A745;
            --warning: #FFC107;
            --danger: #DC3545;
            --gradient-primary: linear-gradient(135deg, #FF6B35 0%, #FF8E53 100%);
            --gradient-secondary: linear-gradient(135deg, #00C9B1 0%, #00E6C3 100%);
            --gradient-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --shadow: 0 8px 30px rgba(0,0,0,0.12);
            --shadow-hover: 0 15px 40px rgba(0,0,0,0.18);
            --radius: 20px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
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
            background: var(--gradient-bg);
            background-attachment: fixed;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            color: var(--dark);
            text-align: center;
            line-height: 1.6;
        }

        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            padding: 40px 30px;
            border-radius: var(--radius);
            max-width: 800px;
            width: 95%;
            box-shadow: var(--shadow);
            position: relative;
            margin: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: var(--transition);
        }

        .container:hover {
            box-shadow: var(--shadow-hover);
            transform: translateY(-5px);
        }

        .logo-container {
            position: relative;
            margin-bottom: 30px;
        }

        .logo {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            object-fit: cover;
            border: 4px solid var(--light);
            box-shadow: 0 8px 25px rgba(255, 107, 53, 0.3);
            transition: var(--transition);
        }

        .logo:hover {
            transform: scale(1.05) rotate(5deg);
        }

        .badge {
            position: absolute;
            top: -5px;
            right: 25%;
            background: var(--gradient-primary);
            color: white;
            padding: 8px 16px;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(255, 107, 53, 0.4);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        #timestamp-display {
            background: var(--gradient-secondary);
            color: white;
            padding: 12px 20px;
            border-radius: 50px;
            font-weight: 600;
            margin-bottom: 25px;
            box-shadow: 0 4px 15px rgba(0, 201, 177, 0.3);
            font-size: 1.1rem;
        }

        h1 {
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 3rem;
            margin-bottom: 20px;
            font-weight: 800;
            text-shadow: 0 4px 10px rgba(0,0,0,0.1);
            letter-spacing: -0.5px;
        }

        .subtitle {
            color: var(--gray);
            font-size: 1.3rem;
            margin-bottom: 40px;
            font-weight: 500;
        }

        p {
            margin: 15px 0;
            font-weight: 500;
            color: var(--dark);
            font-size: 1.1rem;
        }

        .error { 
            background: var(--danger);
            color: white;
            padding: 15px;
            border-radius: 15px;
            margin: 20px 0;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(220, 53, 69, 0.3);
        }
        
        .message { 
            background: var(--success);
            color: white;
            padding: 15px;
            border-radius: 15px;
            margin: 20px 0;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 30px;
        }

        label {
            color: var(--primary);
            text-align: left;
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: -10px;
        }

        input, button {
            padding: 18px 20px;
            font-size: 1.1rem;
            border-radius: 15px;
            width: 100%;
            box-sizing: border-box;
            transition: var(--transition);
            border: none;
            font-weight: 600;
        }

        input {
            border: 3px solid #E9ECEF;
            background: var(--light);
            color: var(--dark);
            font-size: 1rem;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            background: var(--light);
            box-shadow: 0 0 0 4px rgba(255, 107, 53, 0.1);
            transform: translateY(-2px);
        }

        button {
            background: var(--gradient-primary);
            color: white;
            border: none;
            font-weight: 700;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            box-shadow: 0 6px 20px rgba(255, 107, 53, 0.4);
        }

        button:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(255, 107, 53, 0.6);
        }

        button:active {
            transform: translateY(0);
        }

        button::after {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }

        button:hover::after {
            left: 100%;
        }

        #install-btn {
            display: none;
            position: absolute;
            top: 25px;
            right: 25px;
            padding: 12px 24px;
            background: var(--gradient-secondary);
            color: white;
            font-weight: 700;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            z-index: 100;
            box-shadow: 0 6px 20px rgba(0, 201, 177, 0.4);
            transition: var(--transition);
            font-size: 0.9rem;
        }

        #install-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 201, 177, 0.6);
        }

        .game-window {
            margin-top: 30px;
            padding: 30px;
            background: linear-gradient(135deg, #F8F9FF 0%, #F0F2FF 100%);
            border-radius: 20px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.08);
            text-align: left;
            color: var(--dark);
            border: 1px solid rgba(255, 255, 255, 0.5);
            transition: var(--transition);
        }

        .game-window:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 35px rgba(0,0,0,0.15);
        }

        .game-window h2 {
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 1.8rem;
            margin-bottom: 20px;
            font-weight: 700;
        }

        .footer {
            margin-top: 40px;
            font-size: 1rem;
            color: var(--gray);
        }

        .socials {
            margin-top: 25px;
            display: flex;
            justify-content: center;
            gap: 15px;
        }

        .socials a {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 55px;
            height: 55px;
            border-radius: 50%;
            background: var(--light);
            transition: var(--transition);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border: 2px solid transparent;
        }

        .socials a:hover {
            transform: translateY(-5px) scale(1.1);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            border-color: var(--primary);
        }

        .socials img {
            width: 24px;
            height: 24px;
        }

        a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 700;
            transition: var(--transition);
            position: relative;
        }

        a:hover {
            color: var(--primary-dark);
        }

        a::after {
            content: '';
            position: absolute;
            width: 0;
            height: 2px;
            bottom: -2px;
            left: 0;
            background: var(--gradient-primary);
            transition: width 0.3s ease;
        }

        a:hover::after {
            width: 100%;
        }

        .welcome-section {
            background: linear-gradient(135deg, #00C9B1 0%, #00A896 100%);
            color: white;
            padding: 40px;
            border-radius: 20px;
            margin: 40px auto;
            box-shadow: 0 10px 30px rgba(0, 201, 177, 0.3);
            text-align: left;
            position: relative;
            overflow: hidden;
        }

        .welcome-section::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1%, transparent 1%);
            background-size: 20px 20px;
            transform: rotate(30deg);
        }

        .welcome-section h2 {
            font-size: 2.2rem;
            margin-bottom: 20px;
            text-align: center;
            font-weight: 800;
        }

        .welcome-section h3 {
            color: var(--accent);
            font-size: 1.5rem;
            margin: 25px 0 15px;
            font-weight: 700;
        }

        .welcome-section ul {
            list-style-type: none;
            padding-left: 0;
        }

        .welcome-section li {
            padding: 8px 0;
            position: relative;
            padding-left: 30px;
        }

        .welcome-section li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: var(--accent);
            font-weight: bold;
            font-size: 1.2rem;
        }

        .balance-display {
            background: var(--gradient-primary);
            color: white;
            padding: 20px;
            border-radius: 20px;
            margin: 25px 0;
            font-size: 1.4rem;
            font-weight: 700;
            box-shadow: 0 6px 20px rgba(255, 107, 53, 0.3);
            display: inline-block;
            min-width: 250px;
        }

        .game-result {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            border-left: 5px solid var(--primary);
            transition: var(--transition);
        }

        .game-result:hover {
            transform: translateX(5px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.12);
        }

        /* Game Animation Styles */
        .game-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            animation: fadeIn 0.5s ease-in;
        }

        .animation-content {
            text-align: center;
            animation: zoomIn 0.5s ease-out;
        }

        .animated-image {
            font-size: 8rem;
            margin-bottom: 20px;
            animation: bounce 2s infinite, glow 1.5s infinite alternate;
        }

        .animation-text {
            font-size: 3rem;
            font-weight: bold;
            color: white;
            text-shadow: 0 0 20px rgba(255, 255, 255, 0.8);
            animation: textPulse 2s infinite;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes zoomIn {
            from { transform: scale(0.5); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }

        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0) scale(1); }
            40% { transform: translateY(-30px) scale(1.1); }
            60% { transform: translateY(-15px) scale(1.05); }
        }

        @keyframes glow {
            from { filter: drop-shadow(0 0 10px rgba(255, 107, 53, 0.6)); }
            to { filter: drop-shadow(0 0 30px rgba(255, 107, 53, 1)); }
        }

        @keyframes textPulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }

        @keyframes confetti {
            0% { transform: translateY(0) rotate(0deg); opacity: 1; }
            100% { transform: translateY(100vh) rotate(360deg); opacity: 0; }
        }

        @keyframes rocketLaunch {
            0% { transform: translateY(100px) scale(0.5); opacity: 0; }
            50% { transform: translateY(-50px) scale(1.2); opacity: 1; }
            100% { transform: translateY(-200px) scale(0.8); opacity: 0; }
        }

        .confetti {
            position: absolute;
            width: 15px;
            height: 15px;
            background: #FF6B35;
            animation: confetti 3s ease-in forwards;
        }

        .rocket {
            position: absolute;
            font-size: 4rem;
            animation: rocketLaunch 2s ease-out forwards;
        }

        /* Game start specific animations */
        .game-start .animated-image {
            animation: bounce 2s infinite, glow 1.5s infinite alternate, rotate 3s linear infinite;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Game end specific animations */
        .game-end .animated-image {
            animation: bounce 2s infinite, glow 1.5s infinite alternate, pulse 1s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }

        /* OFFLINE FEATURES STYLES */
        .offline-banner {
            background: linear-gradient(135deg, #FF6B35 0%, #FF8E53 100%);
            color: white;
            padding: 15px;
            border-radius: 15px;
            margin: 15px 0;
            text-align: center;
            animation: pulse 2s infinite;
            box-shadow: 0 4px 15px rgba(255, 107, 53, 0.4);
        }
        
        .offline-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .offline-btn {
            padding: 20px;
            background: var(--gradient-secondary);
            color: white;
            border: none;
            border-radius: 15px;
            font-size: 1.1rem;
            font-weight: 700;
            cursor: pointer;
            transition: var(--transition);
            box-shadow: 0 4px 15px rgba(0, 201, 177, 0.3);
        }
        
        .offline-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0, 201, 177, 0.5);
        }
        
        .achievement-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--gradient-primary);
            color: white;
            padding: 20px;
            border-radius: 15px;
            z-index: 10000;
            box-shadow: var(--shadow-hover);
            animation: slideInRight 0.5s ease-out;
            max-width: 300px;
        }
        
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .trivia-option {
            padding: 15px;
            margin: 10px 0;
            background: white;
            border: 2px solid #E9ECEF;
            border-radius: 10px;
            cursor: pointer;
            transition: var(--transition);
        }
        
        .trivia-option:hover {
            border-color: var(--primary);
            transform: translateY(-2px);
        }
        
        .trivia-correct {
            background: var(--success);
            color: white;
            border-color: var(--success);
        }
        
        .trivia-wrong {
            background: var(--danger);
            color: white;
            border-color: var(--danger);
        }

        @media (max-width: 768px) {
            h1 { font-size: 2.2rem; }
            .container { padding: 30px 20px; }
            .game-window { padding: 20px; }
            .game-window h2 { font-size: 1.5rem; }
            button, input { font-size: 1rem; padding: 16px; }
            #install-btn {
                position: static;
                margin: 10px auto;
                display: none;
                width: auto;
            }
            .welcome-section { padding: 25px; }
            .welcome-section h2 { font-size: 1.8rem; }
            .badge { position: static; margin: 10px auto; display: inline-block; }
            .animated-image {
                font-size: 5rem;
            }
            .animation-text {
                font-size: 2rem;
            }
            .offline-options {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 480px) {
            h1 { font-size: 1.8rem; }
            .container { padding: 20px 15px; margin: 10px; }
            .logo { width: 80px; height: 80px; }
            .balance-display { font-size: 1.2rem; min-width: 200px; }
            .welcome-section h2 { font-size: 1.5rem; }
            .welcome-section h3 { font-size: 1.3rem; }
        }
    </style>
</head>  
<body>
    <!-- Game Animation Elements -->
    <audio id="gameStartSound" preload="auto">
        <source src="{{ url_for('static', filename='sounds/game_start.mp3') }}" type="audio/mpeg">
    </audio>

    <audio id="gameEndSound" preload="auto">
        <source src="{{ url_for('static', filename='sounds/game_end.mp3') }}" type="audio/mpeg">
    </audio>

    <div id="gameAnimation" class="game-animation" style="display: none;">
        <div class="animation-content">
            <div class="animated-image" id="animatedImage">
                🎮
            </div>
            <div class="animation-text" id="animationText"></div>
        </div>
    </div>

    <div class="container">  
        <button id="install-btn">📱 Install App</button>
        
        <div class="logo-container">
            <img src="{{ url_for('static', filename='piclog.png') }}" alt="Harambee Cash Logo" class="logo" />  
            <div class="badge">LIVE</div>
        </div>
        
        <p id="timestamp-display">Loading time...</p>  
        <h1>HARAMBEE CASH!</h1>
        <p class="subtitle">Play. Win. Grow. Together!</p>
        
        <!-- OFFLINE BANNER - Only shows when offline -->
        <div id="offlineBanner" class="offline-banner" style="display: none;">
            <h3>📶 You're Offline - But the Fun Continues!</h3>
            <p>Try these activities while you reconnect:</p>
        </div>
        
        {% if error %}<p class="error">{{ error }}</p>{% endif %}  
        {% if message %}<p class="message">{{ message }}</p>{% endif %}

        {% if not session.get('user_id') %}
            <p>Ready to play and win? <a href="/register">Create your account now!</a></p> 
            <p>Already registered? <a href="/login">Login to play</a></p>
            
            <!-- OFFLINE CONTENT for logged out users -->
            <div id="offlineEntertainment" style="display: none;">
                <div class="game-window">
                    <h2>🎮 Offline Fun Zone</h2>
                    <div class="offline-options">
                        <button class="offline-btn" onclick="startTriviaGame()">
                            🧠 Trivia Challenge
                        </button>
                        <button class="offline-btn" onclick="showGamingTips()">
                            📚 Gaming Tips
                        </button>
                        <button class="offline-btn" onclick="showPracticeMode()">
                            💪 Practice Strategies
                        </button>
                    </div>
                    <div id="offlineContent"></div>
                </div>
            </div>
            
            <div class="welcome-section">
              <h2>🎉 Welcome to Harambee Cash</h2>
              <p style="text-align: center; font-size: 1.3rem; margin-bottom: 30px;">The Future of Community Gaming is Here.</p>

              <h3>🚀 Join Thrilling Cash Games</h3>
              <p>Every 30 seconds, new opportunities to win! Enter with just <strong>Ksh. 5.00</strong> and experience our fair, secure system with transparent rules and active oversight.</p>

              <h3>🔐 Safe & Accountable</h3>
              <ul>
                <li>Advanced password security with bcrypt hashing</li>
                <li>30-minute session timeout protection</li>
                <li>Robust input validation against attacks</li>
                <li>Secure admin wallet management</li>
              </ul>

              <h3>📈 Built for Growth</h3>
              <ul>
                <li>Real-time game logs and results</li>
                <li>Full wallet system with deposits & withdrawals</li>
                <li>Comprehensive admin dashboard</li>
              </ul>

              <h3>🎯 Our Vision</h3>
              <p>Empowering youth, creating jobs, and supporting innovation through exciting features:</p>
              <ul>
                <li>Referral rewards program</li>
                <li>Email verification & 2FA for admins</li>
                <li>Achievement badges & leaderboards</li>
                <li>Real-time chatbot support</li>
                <li>Multi-language access</li>
                <li>Advanced analytics</li>
              </ul>

              <p style="margin-top: 30px; font-size: 1.2rem; text-align: center;"><strong>Ready for the next big thing in digital gaming?</strong></p>
              <div style="text-align: center; margin-top: 20px;">
                <p style="margin-top: 8px;">— Fast, Free & Secure!</p>
              </div>
            </div>
        {% else %}
            <p style="font-size: 1.3rem; color: var(--primary); font-weight: 700;">Welcome back, {{ session.get('username') }}! 👋</p>  
            <div class="balance-display">
                💰 Wallet Balance: Ksh. {{ wallet_balance | default(0.0) | float | round(2) }}
            </div>
            <form method="POST" action="/play">  
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />  
                <button type="submit">🎮 PLAY NOW & WIN BIG!</button>  
            </form>  
            <a href="/logout" style="display: inline-block; margin-top: 15px;">Logout</a>  
            
            <!-- OFFLINE CONTENT for logged in users -->
            <div id="offlineEntertainment" style="display: none;">
                <div class="game-window">
                    <h2>🎮 Offline Training Zone</h2>
                    <p>Practice makes perfect! Use this time to sharpen your skills.</p>
                    <div class="offline-options">
                        <button class="offline-btn" onclick="startTriviaGame()">
                            🧠 Harambee Trivia
                        </button>
                        <button class="offline-btn" onclick="showGamingTips()">
                            📚 Winning Strategies
                        </button>
                        <button class="offline-btn" onclick="showPracticeMode()">
                            💪 Practice Games
                        </button>
                        <button class="offline-btn" onclick="viewAchievements()">
                            🏆 My Achievements
                        </button>
                    </div>
                    <div id="offlineContent"></div>
                </div>
            </div>
            
            <div class="game-window">  
                <h2>Game Status</h2>  
                <p><strong>Next Game:</strong> <span id="next-game">Loading...</span></p>  
                <h2>Recent Results (Last 50 Games)</h2>  
                <div id="game-results">Loading recent games...</div>  
            </div>  
            
            <!-- Google Ad -->
            <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
            crossorigin="anonymous"></script>
            <ins class="adsbygoogle"
                style="display:block"
                data-ad-client="ca-pub-5190046541953794"
                data-ad-slot="2953235853"
                data-ad-format="auto"
                data-full-width-responsive="true"></ins>
                
            <div class="welcome-section">
              <h2>🎉 Welcome to Harambee Cash</h2>
              <p style="text-align: center; font-size: 1.3rem; margin-bottom: 30px;">The Future of Community Gaming is Here.</p>

              <h3>🚀 Join Thrilling Cash Games</h3>
              <p>Every 30 seconds, new opportunities to win! Enter with just <strong>Ksh. 5.00</strong> and experience our fair, secure system with transparent rules and active oversight.</p>

              <h3>🔐 Safe & Accountable</h3>
              <ul>
                <li>Advanced password security with bcrypt hashing</li>
                <li>30-minute session timeout protection</li>
                <li>Robust input validation against attacks</li>
                <li>Secure admin wallet management</li>
              </ul>

              <h3>📈 Built for Growth</h3>
              <ul>
                <li>Real-time game logs and results</li>
                <li>Full wallet system with deposits & withdrawals</li>
                <li>Comprehensive admin dashboard</li>
              </ul>

              <h3>🎯 Our Vision</h3>
              <p>Empowering youth, creating jobs, and supporting innovation through exciting features:</p>
              <ul>
                <li>Referral rewards program</li>
                <li>Email verification & 2FA for admins</li>
                <li>Achievement badges & leaderboards</li>
                <li>Real-time chatbot support</li>
                <li>Multi-language access</li>
                <li>Advanced analytics</li>
              </ul>

              <p style="margin-top: 30px; font-size: 1.2rem; text-align: center;"><strong>Ready for the next big thing in digital gaming?</strong></p>
              <div style="text-align: center; margin-top: 20px;">
                <p style="margin-top: 8px;">— Fast, Free & Secure!</p>
              </div>
            </div>
        {% endif %}  

        <div class="footer">  
            <p>
                <a href="/terms">Terms & Conditions</a> | 
                <a href="/privacy">Privacy Policy</a> | 
                <a href="/docs">Documentation</a>
            </p>  
            <div class="socials">  
                <a href="https://m.facebook.com/jamesboyid.ochuna" target="_blank" title="Facebook">  
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg" alt="Facebook" />  
                </a>  
                <a href="https://wa.me/254701207062" target="_blank" title="WhatsApp">  
                    <img src="https://upload.wikimedia.org/wikipedia/commons/6/6b/WhatsApp.svg" alt="WhatsApp" />  
                </a>  
                <a href="tel:+254701207062" title="Call Us">  
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/8c/Phone_font_awesome.svg" alt="Phone" />  
                </a>  
            </div>
            <p style="text-align: center; font-size: 0.9rem; margin-top: 30px; color: var(--gray);">
                © 2025 Pigasimu. All rights reserved.
            </p>
        </div>  
    </div>  

    <script>  
        // Service Worker Registration
        if ('serviceWorker' in navigator) {  
            navigator.serviceWorker.register('{{ url_for("static", filename="service-worker.js") }}')  
                .then(reg => console.log('✅ Service Worker registered:', reg))  
                .catch(err => console.log('❌ Service Worker registration failed:', err));  
        }

        // ========== OFFLINE FEATURES IMPLEMENTATION ==========
        
        // 1. OFFLINE DETECTION & BANNER
        function updateOnlineStatus() {
            const offlineBanner = document.getElementById('offlineBanner');
            const offlineEntertainment = document.getElementById('offlineEntertainment');
            
            if (!navigator.onLine) {
                // User is offline - show entertainment options
                offlineBanner.style.display = 'block';
                offlineEntertainment.style.display = 'block';
                unlockAchievement('offline_explorer');
            } else {
                // User is online - hide offline features
                offlineBanner.style.display = 'none';
                offlineEntertainment.style.display = 'none';
            }
        }

        // 2. TRIVIA GAME SYSTEM
        const triviaQuestions = [
            {
                question: "What is the minimum play amount in Harambee Cash?",
                options: ["Ksh. 5", "Ksh. 10", "Ksh. 20", "Ksh. 50"],
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
                // Play success sound if available
                try { document.getElementById('gameStartSound').play(); } catch(e) {}
            }

            setTimeout(() => {
                currentTriviaQuestion++;
                showTriviaQuestion();
            }, 2000);
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

        // 3. GAMING TIPS SYSTEM
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

        // 4. PRACTICE MODE
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

        // 5. ACHIEVEMENT SYSTEM
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
            }
        };

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
                setTimeout(() => notification.remove(), 500);
            }, 3000);
        }

        function viewAchievements() {
            let html = '<h3>🏆 My Achievements</h3><div style="text-align: left;">';
            
            Object.keys(achievements).forEach(achievementId => {
                const achievement = achievements[achievementId];
                html += `
                    <div style="padding: 15px; margin: 10px 0; background: ${achievement.unlocked ? 'var(--success)' : 'var(--gray)'}; color: white; border-radius: 10px;">
                        <strong>${achievement.unlocked ? '✅' : '🔒'} ${achievement.name}</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9rem;">${achievement.description}</p>
                    </div>
                `;
            });
            
            html += '</div>';
            document.getElementById('offlineContent').innerHTML = html;
        }

        // 6. SAVE/LOAD PROGRESS
        function saveAchievements() {
            localStorage.setItem('harambeeAchievements', JSON.stringify(achievements));
        }

        function loadAchievements() {
            const saved = localStorage.getItem('harambeeAchievements');
            if (saved) {
                const loaded = JSON.parse(saved);
                Object.keys(loaded).forEach(key => {
                    if (achievements[key]) {
                        achievements[key].unlocked = loaded[key].unlocked;
                    }
                });
            }
        }

        // Initialize offline features
        window.addEventListener('online', updateOnlineStatus);
        window.addEventListener('offline', updateOnlineStatus);
        document.addEventListener('DOMContentLoaded', function() {
            updateOnlineStatus(); // Check initial status
            loadAchievements(); // Load saved achievements
            
            // Time display function
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

            // Install button logic
            let deferredPrompt;
            const installBtn = document.getElementById('install-btn');
            
            window.addEventListener('beforeinstallprompt', (e) => {
                e.preventDefault();
                deferredPrompt = e;
                installBtn.style.display = 'block';
                console.log('📱 PWA install prompt available');
            });

            installBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    const { outcome } = await deferredPrompt.userChoice;
                    console.log(`User response: ${outcome}`);
                    
                    if (outcome === 'accepted') {
                        installBtn.style.display = 'none';
                    }
                    deferredPrompt = null;
                }
            });
            
            // Hide install button if app is already installed
            window.addEventListener('appinstalled', () => {
                installBtn.style.display = 'none';
                console.log('🎉 PWA installed successfully');
            });

            // Initialize time display
            updateLocalTime();  
            setInterval(updateLocalTime, 1000);  

            // Game data fetching (if logged in)
            {% if session.get('user_id') %}
            function fetchGameData() {
                fetch("/game_data")
                    .then(response => response.json())
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
                    })
                    .catch(error => console.error("Error fetching game data:", error));
            }

            fetchGameData();  
            setInterval(fetchGameData, 30000);
            {% endif %}  

            // Initialize game animator
            const gameAnimator = new GameAnimator();
            gameAnimator.monitorGameStatus();
            
            // Make it globally available for manual triggering if needed
            window.gameAnimator = gameAnimator;
        });

        // Game animation and sound controller
        class GameAnimator {
            constructor() {
                this.startSound = document.getElementById('gameStartSound');
                this.endSound = document.getElementById('gameEndSound');
                this.animation = document.getElementById('gameAnimation');
                this.animatedImage = document.getElementById('animatedImage');
                this.animationText = document.getElementById('animationText');
                this.lastGameStatus = null;
            }

            // Play game start animation and sound
            playGameStart(gameCode) {
                this.startSound.play().catch(e => console.log('Audio play failed:', e));
                
                this.animatedImage.innerHTML = '🚀';
                this.animationText.textContent = `GAME ${gameCode} STARTED!`;
                this.animation.className = 'game-animation game-start';
                this.animation.style.display = 'flex';
                
                this.createRocketEffect();
                
                setTimeout(() => {
                    this.hideAnimation();
                }, 3000);
            }

            // Play game end animation and sound
            playGameEnd(gameCode, winner, amount) {
                this.endSound.play().catch(e => console.log('Audio play failed:', e));
                
                this.animatedImage.innerHTML = '🎉';
                this.animationText.textContent = `WINNER: ${winner} 🏆 Ksh.${amount}`;
                this.animation.className = 'game-animation game-end';
                this.animation.style.display = 'flex';
                
                this.createConfettiEffect();
                
                setTimeout(() => {
                    this.hideAnimation();
                }, 4000);
            }

            // Create rocket launch effect for game start
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

            // Create confetti effect for game end
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
                // Clean up any remaining effects
                const effects = this.animation.querySelectorAll('.confetti, .rocket');
                effects.forEach(effect => {
                    if (effect.parentNode) {
                        effect.parentNode.removeChild(effect);
                    }
                });
            }

            // Monitor game status changes
            monitorGameStatus() {
                setInterval(() => {
                    fetch('/public_stats')
                        .then(response => response.json())
                        .then(data => {
                            if (data.current_game) {
                                const currentGame = data.current_game;
                                
                                // Detect game start
                                if (currentGame.status === 'in progress' && 
                                    (!this.lastGameStatus || this.lastGameStatus.status !== 'in progress')) {
                                    this.playGameStart(currentGame.game_code);
                                }
                                
                                // Detect game end (completed)
                                if (currentGame.status === 'completed' && 
                                    this.lastGameStatus && this.lastGameStatus.status === 'in progress') {
                                    this.playGameEnd(currentGame.game_code, currentGame.winner, currentGame.winner_amount);
                                }
                                
                                this.lastGameStatus = {...currentGame};
                            }
                        })
                        .catch(error => console.error('Error monitoring game status:', error));
                }, 2000); // Check every 2 seconds
            }
        }
    </script>
</body>  
</html
"""


# ==============================
# Static Content: Terms, Privacy, Documentation
# ==============================

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
        
        <!-- Google Ad -->
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
        <p>Welcome to <strong>Harambee Cash</strong> — your platform for exciting gameplay and rewards! Before getting started, please read through our Terms and Conditions carefully. By using our platform, you agree to these terms.</p>

        <h3>1. Acceptance of Terms</h3>
        <p>By accessing or using Harambee Cash, you agree to comply with these Terms and Conditions. If you do not agree with any part, please do not use the platform.</p>

        <h3>2. Eligibility</h3>
        <ul>
            <li>You must be at least 18 years old to participate.</li>
            <li>You are responsible for providing accurate and updated information during registration.</li>
        </ul>

        <h3>3. Account Registration</h3>
        <ul>
            <li>An account is required to access the platform’s features.</li>
            <li>Keep your login credentials secure—you are accountable for all activity under your account.</li>
        </ul>

        <h3>4. Game Rules</h3>
        <ul>
            <li>A minimum wallet balance of Ksh. 5.00 is required to participate.</li>
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
        <p>Harambee Cash is provided “as is.” We do not guarantee uninterrupted service and are not responsible for any losses or damages incurred through platform use.</p>

        <h3>8. Amendments</h3>
        <p>We may update these terms from time to time. Continued use of the platform indicates your acceptance of any changes.</p>

        <footer>
            <p>&copy; 2025 Pigasimu. All rights reserved.</p>
        </footer>
        <a href="/">← Back to Home</a>
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
        
        <!-- Google Ad -->
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
        <a href="/">← Back to Home</a>
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
        
        <!-- Google Ad -->
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
            <li><strong>Game Logic:</strong> A game runs every 30 seconds. Users with at least Ksh. 5.00 can enroll. A 10% fee is deducted from the pool; the winner gets the rest.</li>
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
            <li><strong>GET /</strong> – Homepage</li>
            <li><strong>POST /register</strong> – Register a new user</li>
            <li><strong>POST /login</strong> – User login</li>
            <li><strong>GET /logout</strong> – User logout</li>
            <li><strong>POST /play</strong> – Enroll in next game</li>
            <li><strong>GET /admin/login</strong> – Admin login</li>
            <li><strong>GET /admin/dashboard</strong> – Admin panel</li>
            <li><strong>GET /admin/logout</strong> – Admin logout</li>
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
        <a href="/">← Back to Home</a>
    </div>   
</body>
</html>
"""
register_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Register – Harambee Cash</title>
    <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}" />
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #a8edea, #fed6e3);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            color: #333;
        }
        .register-container {
            background: #ffffffee;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.2);
            max-width: 400px;
            width: 90%;
        }
        h2 {
            color: #4caf50;
            margin-bottom: 20px;
            font-size: 1.8rem;
            text-align: center;
        }
        .error { color: #e53935; text-align: center; margin-bottom: 10px; }
        .message { color: #43a047; text-align: center; margin-bottom: 10px; }
        label {
            display: block;
            margin-bottom: 5px;
            color: #4caf50;
        }
        input {
            width: 100%;
            padding: 12px;
            margin-bottom: 15px;
            border: 2px solid #4caf50;
            border-radius: 8px;
            background: #f9fff9;
        }
        input:focus {
            border-color: #388e3c;
            background: #e8f5e9;
            outline: none;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #4caf50;
            border: none;
            color: white;
            font-weight: bold;
            border-radius: 10px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        button:hover {
            background: #388e3c;
        }
        .back-link {
            text-align: center;
            margin-top: 15px;
        }
        .back-link a {
            color: #4caf50;
            text-decoration: none;
            font-weight: bold;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h2>Create Account</h2>

        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if message %}<p class="message">{{ message }}</p>{% endif %}

        <form method="POST" action="/register">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
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
            <p><a href="/">← Back to Home</a></p>
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
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-5190046541953794"
     crossorigin="anonymous"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(to right, #ff7e5f, #feb47b);
            color: white;
        }
        .container {
            width: 90%;
            max-width: 400px;
            padding: 20px;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 15px;
            text-align: center;
            box-sizing: border-box;
        }
        h1 {
            font-size: 1.8rem;
            margin-bottom: 15px;
            color: #ffcc00;
        }
        p {
            font-weight: bold;
            margin: 10px 0;
            color: #ddd;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        label {
            font-size: 1rem;
            text-align: left;
            color: #ffcccb;
        }
        input, button {
            padding: 10px;
            font-size: 1rem;
            border-radius: 5px;
            width: 100%;
            box-sizing: border-box;
        }
        input {
            border: 1px solid #ccc;
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        input:focus {
            border-color: #ff9900;
            outline: none;
            background: rgba(255, 255, 255, 0.2);
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
            transform: translateY(-2px);
        }
        .error {
            color: #ffcccb;
            font-weight: bold;
            margin-bottom: 10px;
            background: rgba(255, 0, 0, 0.2);
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ff4444;
        }
        .message {
            color: #4CAF50;
            font-weight: bold;
            margin-bottom: 10px;
            background: rgba(76, 175, 80, 0.2);
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #4CAF50;
        }
        a {
            color: #4CAF50;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            color: #45a049;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        {% if message %}<div class="message">{{ message }}</div>{% endif %}
        
        <form method="POST" action="/login" id="loginForm" autocomplete="on">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <label for="username">Username:</label>
            <input type="text" 
                   id="username" 
                   name="username" 
                   required
                   autocomplete="username"
                   placeholder="Enter your username">
                   
            <label for="password">Password:</label>
            <input type="password" 
                   id="password" 
                   name="password" 
                   required
                   autocomplete="current-password" 
                   placeholder="Enter your password">
                   
            <button type="submit">Login</button>
        </form>
        
        <p>Don't have an account? <a href="/register">Register</a></p>
        <p><a href="/">← Back to Home</a></p>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function() {
            setTimeout(function() {
                console.log('Login form submitted');
            }, 100);
        });

        // Focus on username field when page loads
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('username').focus();
        });
    </script>
</body>
</html>
"""

admin_login = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - HARAMBEE CASH!</title>
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
            max-width: 400px;
            padding: 20px;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 15px;
            text-align: center;
            box-sizing: border-box;
        }
        h1 {
            font-size: 1.8rem;
            margin-bottom: 15px;
            color: #ffcc00;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        label {
            font-size: 1rem;
            text-align: left;
            color: #ffcccb;
        }
        input, button {
            padding: 10px;
            font-size: 1rem;
            border-radius: 5px;
            width: 100%;
            box-sizing: border-box;
        }
        input {
            border: 1px solid #ccc;
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        input:focus {
            border-color: #ff9900;
            outline: none;
            background: rgba(255, 255, 255, 0.2);
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
            transform: translateY(-2px);
        }
        .error {
            color: #ffcccb;
            font-weight: bold;
            margin-bottom: 10px;
            background: rgba(255, 0, 0, 0.2);
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ff4444;
        }
        a {
            color: #4CAF50;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            color: #45a049;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Login</h1>
        
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/admin/login" id="adminLoginForm" autocomplete="on">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            
            <label for="adminUsername">Username:</label>
            <input type="text" 
                   id="adminUsername" 
                   name="username" 
                   required
                   autocomplete="username"
                   placeholder="Admin username">
                   
            <label for="adminPassword">Password:</label>
            <input type="password" 
                   id="adminPassword" 
                   name="password" 
                   required
                   autocomplete="current-password"
                   placeholder="Admin password">
                   
            <button type="submit">Login</button>
        </form>
        
        <div style="margin-top: 20px;">
            <a href="/">← Back to Home</a>
        </div>
    </div>

    <script>
        document.getElementById('adminLoginForm').addEventListener('submit', function() {
            console.log('Admin login form submitted');
        });
        
        // Focus on username field when page loads
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('adminUsername').focus();
        });
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
        /* General Styles */
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
        /* Table Styles */
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
        /* Form Styles */
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

        <a href="/admin/logout">Logout</a>
    </div>
</body>
</html>
"""
@app.before_request
def log_user_activity():
    if request.path.startswith("/static"):
        return

    ip = request.remote_addr
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

@app.before_request
def log_visitor():
    if request.endpoint != 'static':  
        try:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            agent = request.headers.get('User-Agent', 'unknown')
            ref = request.referrer or 'direct'
            path = request.path
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO visit_logs (ip_address, user_agent, referrer, path, timestamp)
                    VALUES (%s, %s, %s, %s, %s) 
                    """, (ip, agent, ref, path, ts))
                conn.commit()
        except Exception as e:
            print("Visitor log error:", e)

@app.before_first_request
def start_background_game_loop():
    """Start the game loop when the app starts"""
    logging.info("Starting game loop...")
    start_game_loop()

def graceful_shutdown():
    """Stop the game loop when the app shuts down"""
    logging.info("Stopping game loop...")
    stop_game_loop()

# Register shutdown handler
import atexit
atexit.register(graceful_shutdown)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
