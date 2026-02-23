"""
Authentication module - signup, login, logout.
Uses Flask-Login and Werkzeug for password hashing.
"""

from functools import wraps
from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from models import User
from db import get_user_by_username, get_user_by_email, create_user

auth_bp = Blueprint('auth', __name__)


def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_view


def file_owner_required(file_record, file_id=None, log_denied=True):
    """
    Zero-trust: Enforce that only file owner can access.
    Admin cannot bypass - infrastructure role only.
    Logs denied attempt and raises 403 if current_user is not the owner.
    """
    if file_record.get('uploaded_by') != current_user.id:
        if log_denied and file_id is not None:
            from db import log_access
            log_access(current_user.id, file_id, 'DOWNLOAD_ATTEMPT', 'DENIED')
        abort(403)


@auth_bp.route('/signup', methods=['GET'])
def signup_page():
    """Display signup form."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('signup.html')


@auth_bp.route('/signup', methods=['POST'])
def signup():
    """
    Create new user account.
    Validates username/email uniqueness, hashes password.
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')

    # Validation
    if not username or not email or not password:
        flash('All fields are required.', 'danger')
        return render_template('signup.html')

    if len(username) < 3:
        flash('Username must be at least 3 characters.', 'danger')
        return render_template('signup.html')

    if password != confirm:
        flash('Passwords do not match.', 'danger')
        return render_template('signup.html')

    if len(password) < 6:
        flash('Password must be at least 6 characters.', 'danger')
        return render_template('signup.html')

    if get_user_by_username(username):
        flash('Username already taken.', 'danger')
        return render_template('signup.html')

    if get_user_by_email(email):
        flash('Email already registered.', 'danger')
        return render_template('signup.html')

    try:
        password_hash = generate_password_hash(password, method='scrypt')
        create_user(username, email, password_hash, role='user')
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    except Exception as e:
        flash(f'Signup failed: {str(e)}', 'danger')
        return render_template('signup.html')


@auth_bp.route('/login', methods=['GET'])
def login_page():
    """Display login form."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html')


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user.
    Checks password hash, creates session via Flask-Login.
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password required.', 'danger')
        return render_template('login.html')

    user_row = get_user_by_username(username)
    if not user_row:
        flash('Invalid username or password.', 'danger')
        return render_template('login.html')

    if not check_password_hash(user_row['password_hash'], password):
        flash('Invalid username or password.', 'danger')
        return render_template('login.html')

    user = User(
        user_id=user_row['id'],
        username=user_row['username'],
        email=user_row['email'],
        role=user_row['role']
    )
    login_user(user, remember=request.form.get('remember', False))
    flash(f'Welcome back, {user.username}!', 'success')
    next_page = request.args.get('next') or url_for('index')
    return redirect(next_page)


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
