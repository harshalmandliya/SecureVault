# SecureVault – Secure File Storage with Automatic Key Rotation

A production-style full-stack application for securely storing files with AES-256 encryption, RSA key management, user authentication, and automatic key rotation.

## Tech Stack

- **Backend:** Python Flask
- **Database:** MySQL
- **Encryption:** AES-256-GCM (files) + RSA-2048 (DEK encryption)
- **Authentication:** Flask-Login
- **Password Hashing:** Werkzeug (scrypt)
- **Scheduler:** APScheduler (automatic key rotation)
- **Frontend:** HTML + Bootstrap 5

## Features

- **User Authentication:** Signup, login, logout with session management
- **Role-Based Access:** USER and ADMIN roles
- **File Encryption:** AES-256-GCM for files, RSA for DEK protection
- **Key Rotation:** Manual (admin) and automatic (scheduled)
- **Admin Dashboard:** Rotate keys, configure interval, view rotation logs, user list

## Project Structure

```
SecureVault/
├── app.py              # Flask application
├── config.py           # Configuration
├── db.py               # Database layer
├── models.py           # User model (Flask-Login)
├── auth.py             # Authentication routes
├── admin.py            # Admin routes
├── crypto_utils.py     # Encryption helpers
├── scheduler.py        # APScheduler for auto rotation
├── rotate_keys.py      # Key rotation logic
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── files.html
│   └── admin_dashboard.html
├── storage/            # Encrypted files
└── keys/               # RSA key pairs
```

## Database Schema (MySQL)

**Database:** `secure_storage`

- **users:** id, username, email, password_hash, role (admin/user)
- **files:** id, filename, stored_filename, encrypted_dek, iv, master_key_version, uploaded_by
- **key_metadata:** id, current_version, rotation_interval_hours
- **rotation_logs:** id, old_version, new_version, rotated_at

Tables are auto-created on first run.

## MySQL Setup

### 1. Install MySQL (8.0+ recommended)

### 2. Create Database and User

```sql
CREATE DATABASE secure_storage;
CREATE USER 'secure_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON secure_storage.* TO 'secure_user'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Configure Connection

```powershell
# Windows PowerShell
$env:DB_HOST="localhost"
$env:DB_USER="root"
$env:DB_PASSWORD="your_password"
$env:DB_NAME="secure_storage"
```

## Installation

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

## Running the Application

```bash
python app.py
```

Open http://127.0.0.1:5000

**Default admin account** (created on first run if no users exist):
- Username: `admin`
- Password: `admin123`

**Change this immediately in production.**

## Routes

| Method | Route | Description | Access |
|--------|-------|-------------|--------|
| GET | `/signup` | Signup form | Public |
| POST | `/signup` | Create account | Public |
| GET | `/login` | Login form | Public |
| POST | `/login` | Authenticate | Public |
| GET | `/logout` | Log out | User |
| GET | `/` | Dashboard | User |
| GET | `/upload` | Upload form | User |
| POST | `/upload` | Upload file | User |
| GET | `/files` | List files | User |
| GET | `/download/<id>` | Download file | User (own) / Admin (all) |
| GET | `/admin` | Admin dashboard | Admin |
| POST | `/admin/rotate-keys` | Manual rotation | Admin |
| POST | `/admin/update-interval` | Set rotation interval | Admin |

## Key Rotation

- **Manual:** Admin → Rotate Keys Now
- **Automatic:** APScheduler checks every hour; rotates when interval has elapsed
- **CLI:** `python rotate_keys.py` (for cron)

Rotation re-encrypts only DEKs, not file data.

## Security Notes

- Change `FLASK_SECRET_KEY` in production
- Change default admin password
- Use strong MySQL password
- Backup `keys/` directory
- Use HTTPS in production

## License

MIT

