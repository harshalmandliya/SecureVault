"""
SecureVault - Secure File Storage with Automatic Key Rotation.
Flask application with auth, file encryption, and admin dashboard.
"""

import os
from io import BytesIO
from flask import Flask, request, render_template, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, login_required, current_user
from werkzeug.utils import secure_filename

from config import KEYS_DIR, STORAGE_DIR, MAX_CONTENT_LENGTH
from db import (
    init_database,
    insert_file,
    get_file_by_id,
    get_files_by_user,
    get_key_metadata,
    update_file_stored_filename,
    log_access,
)
from crypto_utils import (
    ensure_dirs,
    generate_rsa_keys,
    load_rsa_public_key,
    load_rsa_private_key,
    generate_dek,
    encrypt_file_aes,
    decrypt_file_aes,
    encrypt_dek_rsa,
    decrypt_dek_rsa,
)
from models import User
from auth import auth_bp, admin_required, file_owner_required
from admin import admin_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)


@app.context_processor
def inject_template_vars():
    """Make common vars available in all templates."""
    try:
        meta = get_key_metadata()
        return {
            'master_key_version': meta['current_version'] if meta else 0,
            'current_user': current_user,
        }
    except Exception:
        return {'master_key_version': 0, 'current_user': current_user}


def get_current_master_key_version():
    """Get current master key version, ensure keys exist."""
    ensure_dirs(KEYS_DIR, STORAGE_DIR)
    meta = get_key_metadata()
    version = meta['current_version'] if meta else 1
    # Ensure keys exist on disk
    private_path = os.path.join(KEYS_DIR, f'private_v{version}.pem')
    if not os.path.exists(private_path):
        generate_rsa_keys(version, KEYS_DIR)
    return version


def get_storage_path(file_record):
    """Get path for encrypted file. Uses stored_filename or id.enc."""
    stored = file_record.get('stored_filename')
    file_id = file_record['id']
    if stored:
        return os.path.join(STORAGE_DIR, stored)
    return os.path.join(STORAGE_DIR, f'{file_id}.enc')


@app.before_request
def setup():
    ensure_dirs(KEYS_DIR, STORAGE_DIR)


@app.errorhandler(403)
def forbidden(e):
    """403 Forbidden - unauthorized download attempt (zero-trust)."""
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    """404 Not Found - file or resource missing."""
    return render_template('errors/404.html'), 404


@app.route('/')
def index():
    """Dashboard - redirect to files or upload."""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return redirect(url_for('list_files'))


@app.route('/upload', methods=['GET'])
@login_required
def upload_page():
    """Display file upload form."""
    try:
        get_current_master_key_version()
        return render_template('dashboard.html')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return render_template('dashboard.html')


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """
    Upload and encrypt file.
    Flow: Generate DEK -> Encrypt file with AES -> Encrypt DEK with RSA -> Store
    """
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('upload_page'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('upload_page'))

    try:
        filename = secure_filename(file.filename)
        if not filename:
            filename = 'unnamed_file'

        file_bytes = file.read()
        if len(file_bytes) == 0:
            flash('Cannot upload empty file', 'danger')
            return redirect(url_for('upload_page'))

        master_key_version = get_current_master_key_version()
        dek = generate_dek()
        ciphertext, nonce = encrypt_file_aes(file_bytes, dek)
        public_key = load_rsa_public_key(master_key_version, KEYS_DIR)
        encrypted_dek = encrypt_dek_rsa(dek, public_key)

        file_id = insert_file(
            filename, 'temp.enc', encrypted_dek, nonce,
            master_key_version, current_user.id
        )
        stored_filename = f'{file_id}.enc'
        update_file_stored_filename(file_id, stored_filename)

        storage_path = os.path.join(STORAGE_DIR, stored_filename)
        with open(storage_path, 'wb') as f:
            f.write(ciphertext)

        flash(f'File "{filename}" uploaded and encrypted successfully!', 'success')
        return redirect(url_for('list_files'))

    except FileNotFoundError as e:
        flash(f'Key error: {str(e)}', 'danger')
        return redirect(url_for('upload_page'))
    except Exception as e:
        flash(f'Upload failed: {str(e)}', 'danger')
        return redirect(url_for('upload_page'))


@app.route('/files')
@login_required
def list_files():
    """List files for current user (or all for admin)."""
    try:
        get_current_master_key_version()
        if current_user.is_admin:
            from db import get_all_files
            files = get_all_files()
        else:
            files = get_files_by_user(current_user.id)
        return render_template('files.html', files=files)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return render_template('files.html', files=[])


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """
    Download decrypted file.
    ZERO-TRUST: Only file owner can download. Admin cannot bypass.
    Privacy-preserving: Admin manages infrastructure but cannot read user content.
    All attempts (allowed + denied) are logged for audit.
    """
    file_meta = get_file_by_id(file_id)

    # 404: File not found
    if not file_meta:
        log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'DENIED')
        abort(404)

    # Ownership enforcement: ONLY owner can download (no admin bypass)
    # file_owner_required enforces zero-trust; admin cannot bypass
    file_owner_required(file_meta, file_id=file_id)

    # 404: Encrypted file missing from storage
    storage_path = get_storage_path(file_meta)
    if not os.path.exists(storage_path):
        log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'DENIED')
        abort(404)

    try:
        # Log allowed attempt before decryption (audit trail)
        log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'ALLOWED')

        with open(storage_path, 'rb') as f:
            ciphertext = f.read()

        master_key_version = file_meta['master_key_version']
        private_key = load_rsa_private_key(master_key_version, KEYS_DIR)
        dek = decrypt_dek_rsa(bytes(file_meta['encrypted_dek']), private_key)
        nonce = bytes(file_meta['iv'])
        plaintext = decrypt_file_aes(ciphertext, dek, nonce)

        return send_file(
            BytesIO(plaintext),
            as_attachment=True,
            download_name=file_meta['filename'],
            mimetype='application/octet-stream'
        )

    except FileNotFoundError as e:
        log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'DENIED')
        abort(404)
    except Exception as e:
        log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'DENIED')
        raise


def main():
    """Initialize and run Flask app."""
    init_database()
    get_current_master_key_version()

    # Create default admin if no users exist
    from db import get_user_by_username
    if not get_user_by_username('admin'):
        from werkzeug.security import generate_password_hash
        from db import create_user
        create_user('admin', 'admin@securevault.local', generate_password_hash('admin123', method='scrypt'), role='admin')
        print("Default admin created: username=admin, password=admin123")

    # Start scheduler for automatic key rotation
    from scheduler import start_scheduler
    start_scheduler(app)

    print("SecureVault running at http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()
