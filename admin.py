"""
Admin module - key rotation, interval config, rotation logs.
Admin-only routes.
"""

from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from auth import admin_required
from db import (
    get_key_metadata,
    get_rotation_logs,
    update_rotation_interval,
    get_all_users,
    get_all_files,
    get_access_logs,
)
from config import KEYS_DIR, STORAGE_DIR

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def get_current_master_key_version():
    """Get current master key version from DB."""
    meta = get_key_metadata()
    return meta['current_version'] if meta else 1


@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    """
    Admin dashboard - infrastructure management only.
    Zero-trust: Admin sees metadata only (filename, owner, key version, upload time).
    Admin CANNOT download or decrypt user files.
    """
    try:
        meta = get_key_metadata()
        rotation_logs = get_rotation_logs(limit=20)
        users = get_all_users()
        files = get_all_files()  # Metadata only - no encrypted_dek, no download
        access_logs = get_access_logs(limit=50)
        return render_template(
            'admin_dashboard.html',
            current_version=meta['current_version'] if meta else 1,
            rotation_interval=meta['rotation_interval_hours'] if meta else 24,
            rotation_logs=rotation_logs,
            users=users,
            files=files,
            access_logs=access_logs,
            total_files=len(files),
        )
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('index'))


@admin_bp.route('/rotate-keys', methods=['POST'])
@login_required
@admin_required
def rotate_keys():
    """Manually trigger key rotation."""
    try:
        from rotate_keys import perform_rotation
        perform_rotation()
        flash('Key rotation completed successfully!', 'success')
    except Exception as e:
        flash(f'Key rotation failed: {str(e)}', 'danger')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/update-interval', methods=['POST'])
@login_required
@admin_required
def update_interval():
    """Update rotation interval (hours)."""
    try:
        interval = request.form.get('interval_hours', type=int)
        if interval is None or interval < 1 or interval > 8760:  # max 1 year
            flash('Invalid interval. Use 1-8760 hours.', 'danger')
            return redirect(url_for('admin.dashboard'))
        update_rotation_interval(interval)
        flash(f'Rotation interval set to {interval} hours.', 'success')
    except Exception as e:
        flash(f'Failed to update interval: {str(e)}', 'danger')
    return redirect(url_for('admin.dashboard'))
