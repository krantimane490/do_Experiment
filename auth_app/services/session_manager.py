"""
Session management service for creating, validating, and managing user sessions.
"""
from typing import Optional
from datetime import datetime
from models.session import Session
from repositories.session_repository import SessionRepository
from services.password_hasher import PasswordHasher
from utils.time_utils import TimeUtils


class SessionExpiredError(Exception):
    """Raised when session has expired."""
    pass


class SessionInvalidError(Exception):
    """Raised when session is invalid or revoked."""
    pass


class SessionManager:
    """
    Manages user sessions including creation, validation, refresh, and revocation.
    """
    
    # Session configuration
    SESSION_DURATION_MINUTES = 60      # Default session duration
    REFRESH_THRESHOLD_MINUTES = 10     # Refresh if less than this remaining
    MAX_IDLE_MINUTES = 30              # Max idle time before invalidation
    
    def __init__(self, session_repository: SessionRepository):
        """
        Initialize session manager.
        
        Args:
            session_repository: Repository for session storage
        """
        self._repository = session_repository
        self._token_generator = PasswordHasher()
    
    def create_session(
        self,
        user_id: str,
        role: str,
        ip_address: Optional[str] = None,
        duration_minutes: Optional[int] = None
    ) -> Session:
        """
        Create a new session for a user.
        
        Args:
            user_id: User ID
            role: User's role
            ip_address: Client IP address
            duration_minutes: Session duration (default: SESSION_DURATION_MINUTES)
            
        Returns:
            New Session object
        """
        # Generate secure session ID
        session_id = self._token_generator.generate_secret(32)
        
        now = TimeUtils.now()
        duration = duration_minutes or self.SESSION_DURATION_MINUTES
        expires_at = TimeUtils.add_minutes(now, duration)
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            role=role,
            created_at=now,
            expires_at=expires_at,
            last_activity=now,
            ip_address=ip_address,
            is_mfa_verified=False,
            is_revoked=False
        )
        
        self._repository.save_session(session)
        return session
    
    def validate_session(self, session_id: str) -> Session:
        """
        Validate a session and check if it's still active.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            Valid Session object
            
        Raises:
            SessionInvalidError: If session doesn't exist or is revoked
            SessionExpiredError: If session has expired
        """
        session = self._repository.find_by_session_id(session_id)
        
        if not session:
            raise SessionInvalidError("Session not found")
        
        if session.is_revoked:
            raise SessionInvalidError("Session has been revoked")
        
        current_time = TimeUtils.now()
        
        if session.is_expired(current_time):
            raise SessionExpiredError("Session has expired")
        
        # Check idle timeout
        idle_time = (current_time - session.last_activity).total_seconds() / 60
        if idle_time > self.MAX_IDLE_MINUTES:
            session.is_revoked = True
            self._repository.update_session(session)
            raise SessionExpiredError("Session expired due to inactivity")
        
        # Update last activity
        session.last_activity = current_time
        self._repository.update_session(session)
        
        return session
    
    def mark_mfa_verified(self, session_id: str) -> None:
        """
        Mark a session as MFA verified.
        
        Args:
            session_id: Session ID
            
        Raises:
            SessionInvalidError: If session doesn't exist
        """
        session = self._repository.find_by_session_id(session_id)
        if not session:
            raise SessionInvalidError("Session not found")
        
        session.is_mfa_verified = True
        self._repository.update_session(session)
    
    def refresh_session(self, session_id: str) -> Session:
        """
        Refresh a session by extending its expiration time.
        
        Args:
            session_id: Session ID to refresh
            
        Returns:
            Updated Session object
            
        Raises:
            SessionInvalidError: If session doesn't exist or is revoked
        """
        session = self.validate_session(session_id)
        
        # Check if refresh is needed
        current_time = TimeUtils.now()
        time_remaining = (session.expires_at - current_time).total_seconds() / 60
        
        if time_remaining < self.REFRESH_THRESHOLD_MINUTES:
            session.expires_at = TimeUtils.add_minutes(
                current_time,
                self.SESSION_DURATION_MINUTES
            )
            self._repository.update_session(session)
        
        return session
    
    def revoke_session(self, session_id: str) -> None:
        """
        Revoke a session (logout).
        
        Args:
            session_id: Session ID to revoke
        """
        try:
            self._repository.revoke_session(session_id)
        except Exception:
            # Session might not exist - that's okay
            pass
    
    def revoke_all_user_sessions(self, user_id: str) -> None:
        """
        Revoke all sessions for a user (logout from all devices).
        
        Args:
            user_id: User ID
        """
        self._repository.revoke_all_user_sessions(user_id)
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from storage.
        
        Returns:
            Number of sessions cleaned up
        """
        return self._repository.cleanup_expired_sessions()
