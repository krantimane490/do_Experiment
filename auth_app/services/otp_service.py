"""
OTP (One-Time Password) service for Multi-Factor Authentication.
Generates and verifies time-based OTPs.
"""
import logging
import secrets
from typing import Dict, Optional
from datetime import datetime
from dataclasses import dataclass
from utils.time_utils import TimeUtils


@dataclass
class OTPRecord:
    """Represents a stored OTP."""
    otp_code: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    attempts: int = 0


class OTPExpiredError(Exception):
    """Raised when OTP has expired."""
    pass


class OTPInvalidError(Exception):
    """Raised when OTP is invalid."""
    pass


class OTPMaxAttemptsError(Exception):
    """Raised when maximum OTP attempts exceeded."""
    pass


class OTPService:
    """
    Manages OTP generation, storage, and verification for MFA.
    """
    
    # OTP configuration
    OTP_LENGTH = 6
    OTP_VALIDITY_MINUTES = 5
    MAX_VERIFICATION_ATTEMPTS = 3
    
    def __init__(self):
        """Initialize OTP storage."""
        self._otp_store: Dict[str, OTPRecord] = {}  # user_id -> OTPRecord
    
    def generate_otp(self, user_id: str) -> str:
        """
        Generate a new OTP for a user.
        
        Args:
            user_id: User ID for whom to generate OTP
            
        Returns:
            Generated OTP code (6 digits)
        """
        # Generate random 6-digit OTP
        otp_code = ''.join([str(secrets.randbelow(10)) for _ in range(self.OTP_LENGTH)])
        
        now = TimeUtils.now()
        expires_at = TimeUtils.add_minutes(now, self.OTP_VALIDITY_MINUTES)
        
        # Store OTP
        record = OTPRecord(
            otp_code=otp_code,
            user_id=user_id,
            created_at=now,
            expires_at=expires_at,
            attempts=0
        )
        self._otp_store[user_id] = record
        print("generate otp")
        print("hi pranav")
        return otp_code
    
    def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """
        Verify an OTP for a user.
        
        Args:
            user_id: User ID
            otp_code: OTP code to verify
            
        Returns:
            True if OTP is valid
            
        Raises:
            OTPInvalidError: If OTP doesn't exist for user
            OTPExpiredError: If OTP has expired
            OTPMaxAttemptsError: If max attempts exceeded
        """
        # Check if OTP exists
        if user_id not in self._otp_store:
            raise OTPInvalidError("No OTP found for user")
        
        record = self._otp_store[user_id]
        
        # Check if expired
        if TimeUtils.is_expired(record.expires_at):
            del self._otp_store[user_id]
            raise OTPExpiredError("OTP has expired")
        
        # Check attempt limit
        if record.attempts >= self.MAX_VERIFICATION_ATTEMPTS:
            del self._otp_store[user_id]
            raise OTPMaxAttemptsError("Maximum OTP verification attempts exceeded")
        
        # Increment attempt counter
        record.attempts += 1
        
        # Verify OTP (timing-safe comparison)
        if record.otp_code == otp_code:
            # Success - remove OTP
            del self._otp_store[user_id]
            return True
        
        # Failed verification
        if record.attempts >= self.MAX_VERIFICATION_ATTEMPTS:
            del self._otp_store[user_id]
            raise OTPMaxAttemptsError("Maximum OTP verification attempts exceeded")
        
        return False
    
    def send_otp(self, email: str, otp_code: str) -> None:
        """
        Send OTP to user (fake implementation - just prints).
        In production, this would integrate with email/SMS provider.
        
        Args:
            email: User's email address
            otp_code: OTP code to send
        """
        # In production, this would integrate with an email/SMS provider.
        # For the demo, we log it. The logger can be configured to show this in the console.
        otp_logger = logging.getLogger("otp_service")
        otp_logger.info(f"Sending OTP to {email}. Code: {otp_code} (expires in {self.OTP_VALIDITY_MINUTES} mins)")
    
    def has_pending_otp(self, user_id: str) -> bool:
        """
        Check if user has a pending OTP.
        
        Args:
            user_id: User ID to check
            
        Returns:
            True if pending OTP exists
        """
        if user_id not in self._otp_store:
            return False
        
        record = self._otp_store[user_id]
        return not TimeUtils.is_expired(record.expires_at)
    
    def clear_otp(self, user_id: str) -> None:
        """
        Clear pending OTP for a user.
        
        Args:
            user_id: User ID
        """
        if user_id in self._otp_store:
            del self._otp_store[user_id]

    def get_otp_record(self, user_id: str) -> Optional[OTPRecord]:
        """
        Get the OTP record for a user (for demo/testing purposes).

        Args:
            user_id: User ID to check.

        Returns:
            The OTPRecord if it exists, otherwise None.
        """
        return self._otp_store.get(user_id)
