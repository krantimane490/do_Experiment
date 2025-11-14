"""
User model representing a user entity in the system.
"""
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class User:
    """
    Represents a user in the authentication system.
    
    Attributes:
        user_id: Unique identifier for the user
        email: User's email address (used for login)
        password_hash: Hashed password with salt
        role: User's role (admin, user, viewer)
        is_locked: Whether the account is locked due to failed attempts
        locked_until: Timestamp until which the account is locked
        mfa_enabled: Whether MFA is enabled for this user
        mfa_secret: Secret key for OTP generation (if MFA enabled)
        created_at: Account creation timestamp
        last_login: Last successful login timestamp
    """
    user_id: str
    email: str
    password_hash: str
    role: str
    is_locked: bool = False
    locked_until: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class UserRole:
    """Constants for user roles in RBAC."""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    
    @staticmethod
    def is_valid(role: str) -> bool:
        """Check if a role is valid."""
        return role in [UserRole.ADMIN, UserRole.USER, UserRole.VIEWER]
