"""
Audit logging service for tracking authentication events.
"""
import logging
from typing import List, Optional
from datetime import datetime
from dataclasses import dataclass
from utils.time_utils import TimeUtils


@dataclass
class AuditLogEntry:
    """Represents a single audit log entry."""
    timestamp: datetime
    event_type: str
    user_id: Optional[str]
    email: Optional[str]
    ip_address: Optional[str]
    success: bool
    reason: Optional[str]
    metadata: Optional[dict]


class AuditEventType:
    """Constants for audit event types."""
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    MFA_SENT = "mfa_sent"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SESSION_CREATED = "session_created"
    SESSION_REFRESHED = "session_refreshed"
    SESSION_REVOKED = "session_revoked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class AuditLogger:
    """
    Logs authentication and security events for auditing purposes.
    In production, this would write to a persistent log store.
    """
    
    def __init__(self, logger_name: str = "auth_audit"):
        """Initialize in-memory log storage."""
        self._logs: List[AuditLogEntry] = []
        self.logger = logging.getLogger(logger_name)
        # Prevent logs from propagating to the root logger if it's configured elsewhere
        self.logger.propagate = False
    
    def log_event(
        self,
        event_type: str,
        success: bool,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> None:
        """
        Log an authentication event.
        
        Args:
            event_type: Type of event (use AuditEventType constants)
            success: Whether the event was successful
            user_id: User ID if applicable
            email: Email address if applicable
            ip_address: IP address if applicable
            reason: Reason for failure if applicable
            metadata: Additional metadata
        """
        entry = AuditLogEntry(
            timestamp=TimeUtils.now(),
            event_type=event_type,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            success=success,
            reason=reason,
            metadata=metadata or {}
        )
        
        self._logs.append(entry)
        self._log_to_handler(entry)
    
    def _log_to_handler(self, entry: AuditLogEntry) -> None:
        """Formats and sends the log entry to the configured logger."""
        status = "SUCCESS" if entry.success else "FAILURE"
        message = f"type={entry.event_type} status={status}"
        if entry.user_id:
            message += f" user_id={entry.user_id}"
        if entry.email:
            message += f" email={entry.email}"
        if entry.ip_address:
            message += f" ip={entry.ip_address}"
        if entry.reason:
            message += f" reason='{entry.reason}'"
        if entry.metadata:
            message += f" metadata={entry.metadata}"
        
        self.logger.info(message)
    
    def get_logs_by_user(self, user_id: str) -> List[AuditLogEntry]:
        """
        Get all logs for a specific user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of audit log entries
        """
        return [log for log in self._logs if log.user_id == user_id]
    
    def get_logs_by_email(self, email: str) -> List[AuditLogEntry]:
        """
        Get all logs for a specific email.
        
        Args:
            email: Email address
            
        Returns:
            List of audit log entries
        """
        return [log for log in self._logs if log.email == email]
    
    def get_logs_by_ip(self, ip_address: str) -> List[AuditLogEntry]:
        """
        Get all logs for a specific IP address.
        
        Args:
            ip_address: IP address
            
        Returns:
            List of audit log entries
        """
        return [log for log in self._logs if log.ip_address == ip_address]
    
    def get_failed_attempts(self, minutes: int = 60) -> List[AuditLogEntry]:
        """
        Get all failed attempts within a time window.
        
        Args:
            minutes: Time window in minutes
            
        Returns:
            List of failed audit log entries
        """
        cutoff = TimeUtils.add_minutes(TimeUtils.now(), -minutes)
        return [
            log for log in self._logs
            if not log.success and log.timestamp >= cutoff
        ]
    
    def get_all_logs(self) -> List[AuditLogEntry]:
        """
        Get all audit logs.
        
        Returns:
            List of all audit log entries
        """
        return self._logs.copy()
