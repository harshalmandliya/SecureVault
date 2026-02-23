"""
User model for Flask-Login.
Provides user object with required methods for session management.
"""

from flask_login import UserMixin

from db import get_user_by_id


class User(UserMixin):
    """
    User model compatible with Flask-Login.
    Loaded from database by user_id.
    """

    def __init__(self, user_id, username, email, role):
        self.id = user_id
        self.username = username
        self.email = email
        self.role = role

    @property
    def is_admin(self):
        """Check if user has admin role."""
        return self.role == 'admin'

    @staticmethod
    def get(user_id):
        """
        Load user from database by ID.
        Returns User instance or None.
        """
        if user_id is None:
            return None
        row = get_user_by_id(int(user_id))
        if not row:
            return None
        return User(
            user_id=row['id'],
            username=row['username'],
            email=row['email'],
            role=row['role']
        )
