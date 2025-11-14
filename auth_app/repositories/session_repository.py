"""
In-memory repository for session storage and management.
"""
from typing import Dict, Optional, List
from datetime import datetime
from models.session import Session
from utils.time_utils import TimeUtils


class SessionNotFoundError(Exception):
    """Raised when a session is not found."""
    pass


class SessionRepository:
    """
    In-memory repository for session storage.
    Supports session creation, retrieval, expiration, and revocation.
    """
    
    def __init__(self):
        """Initialize empty session storage."""
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]
    
    def save_session(self, session: Session) -> None:
        """
        Save a session to the repository.
        
        Args:
            session: Session object to save
        """
        self._sessions[session.session_id] = session
        
        # Track by user
        if session.user_id not in self._user_sessions:
            self._user_sessions[session.user_id] = []
        if session.session_id not in self._user_sessions[session.user_id]:
            self._user_sessions[session.user_id].append(session.session_id)
    
    def find_by_session_id(self, session_id: str) -> Optional[Session]:
        """
        Find a session by its ID.
        
        Args:
            session_id: Session ID to search
            
        Returns:
            Session object if found, None otherwise
        """
        return self._sessions.get(session_id)
    
    def find_by_user_id(self, user_id: str) -> List[Session]:
        """
        Find all sessions for a user.
        
        Args:
            user_id: User ID to search
            
        Returns:
            List of Session objects
        """
        session_ids = self._user_sessions.get(user_id, [])
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]
    
    def update_session(self, session: Session) -> None:
        """
        Update an existing session.
        
        Args:
            session: Updated session object
            
        Raises:
            SessionNotFoundError: If session doesn't exist
        """
        if session.session_id not in self._sessions:
            raise SessionNotFoundError(f"Session {session.session_id} not found")
        
        self._sessions[session.session_id] = session
    
    def revoke_session(self, session_id: str) -> None:
        """
        Revoke a session (mark as invalid).
        
        Args:
            session_id: Session ID to revoke
            
        Raises:
            SessionNotFoundError: If session doesn't exist
        """
        session = self.find_by_session_id(session_id)
        if not session:
            raise SessionNotFoundError(f"Session {session_id} not found")
        
        session.is_revoked = True
        self.update_session(session)
    
    def revoke_all_user_sessions(self, user_id: str) -> None:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: User ID whose sessions to revoke
        """
        sessions = self.find_by_user_id(user_id)
        for session in sessions:
            session.is_revoked = True
            self.update_session(session)
    
    def delete_session(self, session_id: str) -> None:
        """
        Permanently delete a session.
        
        Args:
            session_id: Session ID to delete
        """
        session = self._sessions.get(session_id)
        if session:
            del self._sessions[session_id]
            
            # Remove from user index
            if session.user_id in self._user_sessions:
                self._user_sessions[session.user_id] = [
                    sid for sid in self._user_sessions[session.user_id]
                    if sid != session_id
                ]
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions from storage.
        
        Returns:
            Number of sessions cleaned up
        """
        current_time = TimeUtils.now()
        expired_ids = [
            sid for sid, session in self._sessions.items()
            if session.is_expired(current_time)
        ]
        
        for session_id in expired_ids:
            self.delete_session(session_id)
        
        return len(expired_ids)
