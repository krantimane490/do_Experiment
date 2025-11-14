"""
Rate limiter service for brute-force protection.
Implements sliding window rate limiting per IP and per user.
"""
from typing import Dict, List
from datetime import datetime
from dataclasses import dataclass
from utils.time_utils import TimeUtils


@dataclass
class RateLimitAttempt:
    """Represents a single rate limit attempt."""
    timestamp: datetime


class RateLimitExceededError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class RateLimiter:
    """
    Implements rate limiting using sliding window algorithm.
    Tracks attempts per IP and per user email.
    """
    
    # Rate limit constants
    MAX_ATTEMPTS_PER_IP = 10        # Max attempts per IP in window
    MAX_ATTEMPTS_PER_EMAIL = 5      # Max attempts per email in window
    WINDOW_MINUTES = 15             # Time window in minutes
    
    def __init__(self):
        """Initialize rate limiter with empty tracking."""
        self._attempts_by_ip: Dict[str, List[RateLimitAttempt]] = {}
        self._attempts_by_email: Dict[str, List[RateLimitAttempt]] = {}
    
    def _cleanup_old_attempts(
        self,
        attempts: List[RateLimitAttempt],
        window_minutes: int
    ) -> List[RateLimitAttempt]:
        """
        Remove attempts older than the window.
        
        Args:
            attempts: List of attempts
            window_minutes: Window size in minutes
            
        Returns:
            Filtered list of recent attempts
        """
        cutoff_time = TimeUtils.add_minutes(TimeUtils.now(), -window_minutes)
        return [a for a in attempts if a.timestamp >= cutoff_time]
    
    def check_ip_limit(self, ip_address: str) -> None:
        """
        Check if IP address has exceeded rate limit.
        
        Args:
            ip_address: IP address to check
            
        Raises:
            RateLimitExceededError: If limit exceeded
        """
        # Initialize if not tracked
        if ip_address not in self._attempts_by_ip:
            self._attempts_by_ip[ip_address] = []
        
        # Clean up old attempts
        self._attempts_by_ip[ip_address] = self._cleanup_old_attempts(
            self._attempts_by_ip[ip_address],
            self.WINDOW_MINUTES
        )
        
        # Check limit
        if len(self._attempts_by_ip[ip_address]) >= self.MAX_ATTEMPTS_PER_IP:
            raise RateLimitExceededError(
                f"Too many attempts from IP {ip_address}. "
                f"Try again in {self.WINDOW_MINUTES} minutes."
            )
    
    def check_email_limit(self, email: str) -> None:
        """
        Check if email has exceeded rate limit.
        
        Args:
            email: Email address to check
            
        Raises:
            RateLimitExceededError: If limit exceeded
        """
        email_lower = email.lower()
        
        # Initialize if not tracked
        if email_lower not in self._attempts_by_email:
            self._attempts_by_email[email_lower] = []
        
        # Clean up old attempts
        self._attempts_by_email[email_lower] = self._cleanup_old_attempts(
            self._attempts_by_email[email_lower],
            self.WINDOW_MINUTES
        )
        
        # Check limit
        if len(self._attempts_by_email[email_lower]) >= self.MAX_ATTEMPTS_PER_EMAIL:
            raise RateLimitExceededError(
                f"Too many login attempts for {email}. "
                f"Try again in {self.WINDOW_MINUTES} minutes."
            )
    
    def record_attempt_for_ip(self, ip_address: str) -> None:
        """
        Record an attempt for an IP address.
        
        Args:
            ip_address: IP address to record
        """
        if ip_address not in self._attempts_by_ip:
            self._attempts_by_ip[ip_address] = []
        
        attempt = RateLimitAttempt(timestamp=TimeUtils.now())
        self._attempts_by_ip[ip_address].append(attempt)
    
    def record_attempt_for_email(self, email: str) -> None:
        """
        Record an attempt for an email.
        
        Args:
            email: Email address to record
        """
        email_lower = email.lower()
        
        if email_lower not in self._attempts_by_email:
            self._attempts_by_email[email_lower] = []
        
        attempt = RateLimitAttempt(timestamp=TimeUtils.now())
        self._attempts_by_email[email_lower].append(attempt)
    
    def reset_for_email(self, email: str) -> None:
        """
        Reset rate limit counter for an email (after successful login).
        
        Args:
            email: Email address to reset
        """
        email_lower = email.lower()
        if email_lower in self._attempts_by_email:
            self._attempts_by_email[email_lower] = []
    
    def reset_for_ip(self, ip_address: str) -> None:
        """
        Reset rate limit counter for an IP.
        
        Args:
            ip_address: IP address to reset
        """
        if ip_address in self._attempts_by_ip:
            self._attempts_by_ip[ip_address] = []
