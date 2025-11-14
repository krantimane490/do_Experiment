"""
Session model for managing authenticated user sessions.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Session:
    """
    Represents an authenticated user session.
    
    Attributes:
        session_id: Unique session identifier (token)
        user_id: ID of the authenticated user
        role: User's role (cached from User)
        created_at: When the session was created
        expires_at: When the session expires
        last_activity: Last activity timestamp
        ip_address: IP address of the client (for security)
        is_mfa_verified: Whether MFA has been completed
        is_revoked: Whether the session has been manually revoked
    """
    session_id: str
    user_id: str
    role: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    is_mfa_verified: bool = False
    is_revoked: bool = False
    
    def is_expired(self, current_time: datetime) -> bool:
        """Check if the session has expired."""
        return current_time >= self.expires_at
    
    def is_valid(self, current_time: datetime) -> bool:
        """Check if the session is valid (not expired and not revoked)."""
        return not self.is_revoked and not self.is_expired(current_time)
