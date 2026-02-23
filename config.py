"""
Database and application configuration.
Store sensitive config in environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# MySQL Database Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'secure_storage'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'autocommit': True,
}

# Application paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

KEYS_DIR = os.getenv('KEYS_DIR', os.path.join(BASE_DIR, 'keys'))
STORAGE_DIR = os.getenv('STORAGE_DIR', os.path.join(BASE_DIR, 'storage'))

# Master key version file
KEY_VERSION_FILE = os.path.join(KEYS_DIR, 'current_version.txt')

# Flask configuration
SECRET_KEY = os.getenv('FLASK_SECRET_KEY')

MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))

# Default rotation interval (hours)
DEFAULT_ROTATION_INTERVAL_HOURS = int(
    os.getenv('DEFAULT_ROTATION_INTERVAL_HOURS', 24)
)