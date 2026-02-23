"""
Database connection and table management.
Uses mysql-connector-python with parameterized queries to prevent SQL injection.
"""

import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager

from config import DB_CONFIG, DEFAULT_ROTATION_INTERVAL_HOURS, KEY_VERSION_FILE


@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Ensures proper connection cleanup.
    """
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        yield conn
    except Error as e:
        raise Exception(f"Database connection error: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()


def init_database():
    """
    Create database and tables if they don't exist.
    Auto-creates secure_storage database and all tables.
    """
    config_no_db = {k: v for k, v in DB_CONFIG.items() if k != 'database'}

    try:
        conn = mysql.connector.connect(**config_no_db)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}`")
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Failed to create database: {e}")

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin','user') NOT NULL DEFAULT 'user'
            )
        """)

        # Files table (with uploaded_by for user association)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                stored_filename VARCHAR(255),
                encrypted_dek BLOB NOT NULL,
                iv BLOB NOT NULL,
                master_key_version INT NOT NULL,
                uploaded_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Migration: add stored_filename and uploaded_by if upgrading from old schema
        for col_def in [
            ("stored_filename", "VARCHAR(255)"),
            ("uploaded_by", "INT NULL"),
        ]:
            try:
                cursor.execute(f"ALTER TABLE files ADD COLUMN {col_def[0]} {col_def[1]}")
            except Error:
                pass
        try:
            cursor.execute("UPDATE files SET stored_filename = CONCAT(id, '.enc') WHERE stored_filename IS NULL OR stored_filename = ''")
        except Error:
            pass

        # Key metadata - single row config (id=1)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_metadata (
                id INT PRIMARY KEY DEFAULT 1,
                current_version INT NOT NULL DEFAULT 1,
                rotation_interval_hours INT NOT NULL DEFAULT 24
            )
        """)
        cursor.execute("""
            INSERT IGNORE INTO key_metadata (id, current_version, rotation_interval_hours)
            VALUES (1, 1, %s)
        """, (DEFAULT_ROTATION_INTERVAL_HOURS,))

        # Migration: sync from file-based version if exists (upgrade from old schema)
        import os
        if os.path.exists(KEY_VERSION_FILE):
            with open(KEY_VERSION_FILE, 'r') as f:
                file_version = int(f.read().strip())
            cursor.execute(
                "UPDATE key_metadata SET current_version = %s WHERE id = 1 AND current_version < %s",
                (file_version, file_version)
            )

        # Rotation logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rotation_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                old_version INT NOT NULL,
                new_version INT NOT NULL,
                rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Access logs - zero-trust: log ALL download attempts (allowed + denied)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                file_id INT NULL,
                action VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        cursor.close()


# --- User operations ---

def get_user_by_id(user_id):
    """Fetch user by ID. Returns dict or None."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def get_user_by_username(username):
    """Fetch user by username. Returns dict or None."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE username = %s",
            (username,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def get_user_by_email(email):
    """Fetch user by email. Returns dict or None."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, password_hash, role FROM users WHERE email = %s",
            (email,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def create_user(username, email, password_hash, role='user'):
    """Create new user. Returns user ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            """,
            (username, email, password_hash, role)
        )
        conn.commit()
        user_id = cursor.lastrowid
        cursor.close()
        return user_id


# --- Key metadata operations ---

def get_key_metadata():
    """Get key_metadata row. Returns dict with current_version and rotation_interval_hours."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, current_version, rotation_interval_hours FROM key_metadata WHERE id = 1"
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def update_key_version(new_version):
    """Update current master key version in DB."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE key_metadata SET current_version = %s WHERE id = 1",
            (new_version,)
        )
        conn.commit()
        cursor.close()


def update_rotation_interval(interval_hours):
    """Update rotation interval in DB."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE key_metadata SET rotation_interval_hours = %s WHERE id = 1",
            (interval_hours,)
        )
        conn.commit()
        cursor.close()


def add_rotation_log(old_version, new_version):
    """Add rotation log entry."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO rotation_logs (old_version, new_version) VALUES (%s, %s)",
            (old_version, new_version)
        )
        conn.commit()
        cursor.close()


def get_rotation_logs(limit=50):
    """Fetch recent rotation logs."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, old_version, new_version, rotated_at
            FROM rotation_logs ORDER BY rotated_at DESC LIMIT %s
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


# --- File operations ---

def insert_file(filename, stored_filename, encrypted_dek, iv, master_key_version, uploaded_by=None):
    """Insert file metadata. Returns file ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO files (filename, stored_filename, encrypted_dek, iv, master_key_version, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (filename, stored_filename, encrypted_dek, iv, master_key_version, uploaded_by)
        )
        conn.commit()
        file_id = cursor.lastrowid
        cursor.close()
        return file_id


def get_file_by_id(file_id):
    """Fetch file metadata by ID. Returns dict or None."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, filename, stored_filename, encrypted_dek, iv, master_key_version, uploaded_by
            FROM files WHERE id = %s
            """,
            (file_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row


def get_files_by_user(user_id):
    """Fetch files uploaded by user."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, filename, stored_filename, master_key_version, created_at, uploaded_by
            FROM files WHERE uploaded_by = %s ORDER BY created_at DESC
            """,
            (user_id,)
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def get_all_files():
    """Fetch all files (admin view)."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT f.id, f.filename, f.stored_filename, f.master_key_version, f.created_at, f.uploaded_by, u.username
            FROM files f LEFT JOIN users u ON f.uploaded_by = u.id
            ORDER BY f.created_at DESC
            """
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


def update_file_stored_filename(file_id, stored_filename):
    """Update stored_filename for a file."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE files SET stored_filename = %s WHERE id = %s", (stored_filename, file_id))
        conn.commit()
        cursor.close()


def update_file_dek(file_id, encrypted_dek, master_key_version):
    """Update encrypted DEK and master key version for a file."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE files SET encrypted_dek = %s, master_key_version = %s WHERE id = %s
            """,
            (encrypted_dek, master_key_version, file_id)
        )
        conn.commit()
        cursor.close()


def get_all_files_for_rotation():
    """Fetch all files with encrypted DEK for key rotation."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, filename, stored_filename, encrypted_dek, iv, master_key_version FROM files"
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


# --- Access logging (zero-trust audit trail) ---

def log_access(user_id, file_id, action, status):
    """
    Log access attempt for audit trail.
    Zero-trust design: log BOTH allowed and denied attempts.
    status: 'ALLOWED' | 'DENIED'
    action: 'DOWNLOAD_ATTEMPT' (extensible for future actions)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO access_logs (user_id, file_id, action, status)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, file_id, action, status)
        )
        conn.commit()
        cursor.close()


def get_access_logs(limit=100):
    """Fetch recent access logs for admin audit view."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT al.id, al.user_id, al.file_id, al.action, al.status, al.timestamp,
                   u.username, f.filename
            FROM access_logs al
            LEFT JOIN users u ON al.user_id = u.id
            LEFT JOIN files f ON al.file_id = f.id
            ORDER BY al.timestamp DESC LIMIT %s
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


# --- User management (admin) ---

def get_all_users():
    """Fetch all users."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, email, role FROM users ORDER BY id"
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows
