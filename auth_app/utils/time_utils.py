"""
Time utilities for session management and expiration handling.
"""
from datetime import datetime, timedelta
from typing import Optional


class TimeUtils:
    """Utility functions for time operations."""
    
    @staticmethod
    def now() -> datetime:
        """Get current UTC datetime."""
        return datetime.utcnow()
    
    @staticmethod
    def add_minutes(dt: datetime, minutes: int) -> datetime:
        """Add minutes to a datetime."""
        return dt + timedelta(minutes=minutes)
    
    @staticmethod
    def add_seconds(dt: datetime, seconds: int) -> datetime:
        """Add seconds to a datetime."""
        return dt + timedelta(seconds=seconds)
    
    @staticmethod
    def is_expired(expiry_time: datetime, current_time: Optional[datetime] = None) -> bool:
        """
        Check if a given expiry time has passed.
        
        Args:
            expiry_time: The expiration datetime
            current_time: Current time (defaults to now)
            
        Returns:
            True if expired, False otherwise
        """
        if current_time is None:
            current_time = TimeUtils.now()
        return current_time >= expiry_time
    
    @staticmethod
    def time_until(target_time: datetime, current_time: Optional[datetime] = None) -> timedelta:
        """
        Calculate time remaining until target time.
        
        Args:
            target_time: Target datetime
            current_time: Current time (defaults to now)
            
        Returns:
            Timedelta representing time remaining (can be negative if past)
        """
        if current_time is None:
            current_time = TimeUtils.now()
        return target_time - current_time
    
    @staticmethod
    def is_within_window(
        timestamp: datetime,
        window_seconds: int,
        current_time: Optional[datetime] = None
    ) -> bool:
        """
        Check if a timestamp is within a time window from now.
        
        Args:
            timestamp: The timestamp to check
            window_seconds: Window size in seconds
            current_time: Current time (defaults to now)
            
        Returns:
            True if within window, False otherwise
        """
        if current_time is None:
            current_time = TimeUtils.now()
        
        time_diff = (current_time - timestamp).total_seconds()
        return 0 <= time_diff <= window_seconds
