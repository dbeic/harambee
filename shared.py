# shared.py - FIXED VERSION
import os
import logging
from urllib.parse import urlparse
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")  # Reduced to INFO

# Load database configuration from environment
ADMIN_DATABASE = os.getenv('ADMIN_DATABASE')
if not ADMIN_DATABASE:
    raise ValueError("ADMIN_DATABASE environment variable not set")

# Create connection pool with error handling
db_pool = None

try:
    db_pool = pool.SimpleConnectionPool(
        minconn=1,
        maxconn=20,  # Increased max connections
        dsn=ADMIN_DATABASE
    )
    logging.info("Database connection pool created successfully")
except Exception as e:
    logging.error(f"Failed to create connection pool: {e}")
    raise

# Get a database connection using context manager
@contextmanager
def get_db_connection():
    conn = None
    try:
        if db_pool:
            conn = db_pool.getconn()
            yield conn
        else:
            raise Exception("Database pool not initialized")
    except Exception as e:
        logging.error(f"Error getting database connection: {e}")
        raise
    finally:
        if conn and db_pool:
            db_pool.putconn(conn)

# Helper Functions
def get_timestamp():
    """Returns the current timestamp in the format '%Y-%m-%d %H:%M:%S.%f' (no 'T')."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

# Notify clients placeholder
def notify_clients(event_type, data):
    """Placeholder for client notifications"""
    logging.info(f"Game Event: {event_type} - {data}")
