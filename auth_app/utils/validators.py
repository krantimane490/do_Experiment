"""
Validators for email, password, and other input formats.
"""
import re
from typing import Tuple


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class EmailValidator:
    """Validates email addresses according to RFC 5322 simplified pattern."""
    
    # Simplified but robust email regex
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$'
    )
    
    @staticmethod
    def validate(email: str) -> Tuple[bool, str]:
        """
        Validate email format.
        
        Args:
            email: Email string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email is required"
        
        if len(email) > 254:
            return False, "Email is too long (max 254 characters)"
        
        if not EmailValidator.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        
        return True, ""


class PasswordValidator:
    """Validates password strength and format."""
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """
        Validate password format and strength.
        
        Requirements:
        - At least 8 characters
        - At most 128 characters
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter
        - Contains at least one digit
        - Contains at least one special character
        
        Args:
            password: Password string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < PasswordValidator.MIN_LENGTH:
            return False, f"Password must be at least {PasswordValidator.MIN_LENGTH} characters"
        
        if len(password) > PasswordValidator.MAX_LENGTH:
            return False, f"Password must not exceed {PasswordValidator.MAX_LENGTH} characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, ""


class OTPValidator:
    """Validates OTP codes."""
    
    OTP_LENGTH = 6
    
    @staticmethod
    def validate(otp: str) -> Tuple[bool, str]:
        """
        Validate OTP format.
        
        Args:
            otp: OTP string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not otp:
            return False, "OTP is required"
        
        if len(otp) != OTPValidator.OTP_LENGTH:
            return False, f"OTP must be {OTPValidator.OTP_LENGTH} digits"
        
        if not otp.isdigit():
            return False, "OTP must contain only digits"
        
        return True, ""
