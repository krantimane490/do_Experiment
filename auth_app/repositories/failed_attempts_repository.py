"""
In-memory repository for tracking failed login attempts.
"""
from typing import Dict, List
from datetime import datetime
from dataclasses import dataclass
from utils.time_utils import TimeUtils


@dataclass
class FailedAttempt:
    """Represents a single failed login attempt."""
    email: str
    ip_address: str
    timestamp: datetime
    reason: str


class FailedAttemptsRepository:
    """
    Tracks failed login attempts per user and per IP.
    Used for brute-force protection and account locking.
    """
    
    def __init__(self):
        """Initialize empty tracking structures."""
        # Track attempts per email
        self._attempts_by_email: Dict[str, List[FailedAttempt]] = {}
        # Track attempts per IP
        self._attempts_by_ip: Dict[str, List[FailedAttempt]] = {}
    
    def record_failure(
        self,
        email: str,
        ip_address: str,
        reason: str
    ) -> None:
        """
        Record a failed login attempt.
        
        Args:
            email: Email address of the attempted login
            ip_address: IP address of the client
            reason: Reason for failure
        """
        attempt = FailedAttempt(
            email=email.lower(),
            ip_address=ip_address,
            timestamp=TimeUtils.now(),
            reason=reason
        )
        
        # Track by email
        if attempt.email not in self._attempts_by_email:
            self._attempts_by_email[attempt.email] = []
        self._attempts_by_email[attempt.email].append(attempt)
        
        # Track by IP
        if ip_address not in self._attempts_by_ip:
            self._attempts_by_ip[ip_address] = []
        self._attempts_by_ip[ip_address].append(attempt)
    
    def get_recent_failures_by_email(
        self,
        email: str,
        window_minutes: int = 15
    ) -> List[FailedAttempt]:
        """
        Get recent failed attempts for an email within a time window.
        
        Args:
            email: Email address to check
            window_minutes: Time window in minutes
            
        Returns:
            List of recent failed attempts
        """
        email_lower = email.lower()
        if email_lower not in self._attempts_by_email:
            return []
        
        cutoff_time = TimeUtils.add_minutes(TimeUtils.now(), -window_minutes)
        attempts = self._attempts_by_email[email_lower]
        
        # Filter to recent attempts
        recent = [a for a in attempts if a.timestamp >= cutoff_time]
        return recent
    
    def get_recent_failures_by_ip(
        self,
        ip_address: str,
        window_minutes: int = 15
    ) -> List[FailedAttempt]:
        """
        Get recent failed attempts from an IP within a time window.
        
        Args:
            ip_address: IP address to check
            window_minutes: Time window in minutes
            
        Returns:
            List of recent failed attempts
        """
        if ip_address not in self._attempts_by_ip:
            return []
        
        cutoff_time = TimeUtils.add_minutes(TimeUtils.now(), -window_minutes)
        attempts = self._attempts_by_ip[ip_address]
        
        # Filter to recent attempts
        recent = [a for a in attempts if a.timestamp >= cutoff_time]
        return recent
    
    def count_recent_failures_by_email(
        self,
        email: str,
        window_minutes: int = 15
    ) -> int:
        """
        Count recent failed attempts for an email.
        
        Args:
            email: Email address to check
            window_minutes: Time window in minutes
            
        Returns:
            Number of recent failures
        """
        return len(self.get_recent_failures_by_email(email, window_minutes))
    
    def count_recent_failures_by_ip(
        self,
        ip_address: str,
        window_minutes: int = 15
    ) -> int:
        """
        Count recent failed attempts from an IP.
        
        Args:
            ip_address: IP address to check
            window_minutes: Time window in minutes
            
        Returns:
            Number of recent failures
        """
        return len(self.get_recent_failures_by_ip(ip_address, window_minutes))
    
    def clear_failures_for_email(self, email: str) -> None:
        """
        Clear all failed attempts for an email (after successful login).
        
        Args:
            email: Email address to clear
        """
        email_lower = email.lower()
        if email_lower in self._attempts_by_email:
            self._attempts_by_email[email_lower] = []
    
    def clear_failures_for_ip(self, ip_address: str) -> None:
        """
        Clear all failed attempts for an IP.
        
        Args:
            ip_address: IP address to clear
        """
        if ip_address in self._attempts_by_ip:
            self._attempts_by_ip[ip_address] = []
