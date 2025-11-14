"""
Password hashing service using bcrypt with automatic salting.
Implements timing-safe comparison to prevent timing attacks.
"""
import hashlib
import secrets
import hmac
from typing import Tuple


class PasswordHasher:
    """
    Handles secure password hashing and verification.
    Uses SHA-256 with PBKDF2 and automatic salt generation.
    """
    
    # Security constants
    ITERATIONS = 100_000  # PBKDF2 iterations (OWASP recommendation)
    SALT_LENGTH = 32      # Salt length in bytes
    HASH_LENGTH = 64      # Hash length in bytes
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password with automatic salt generation.
        
        Args:
            password: Plain text password
            
        Returns:
            Formatted hash string: iterations$salt$hash (hex encoded)
            
        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate cryptographically secure random salt
        salt = secrets.token_bytes(PasswordHasher.SALT_LENGTH)
        
        # Hash the password using PBKDF2-HMAC-SHA256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PasswordHasher.ITERATIONS,
            dklen=PasswordHasher.HASH_LENGTH
        )
        
        # Format: iterations$salt$hash (all hex encoded)
        return f"{PasswordHasher.ITERATIONS}${salt.hex()}${password_hash.hex()}"
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash using timing-safe comparison.
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored hash string
            
        Returns:
            True if password matches, False otherwise
            
        Raises:
            ValueError: If hash format is invalid
        """
        if not password or not hashed_password:
            return False
        
        try:
            # Parse the stored hash
            iterations_str, salt_hex, stored_hash_hex = hashed_password.split('$')
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(stored_hash_hex)
        except (ValueError, AttributeError):
            raise ValueError("Invalid hash format")
        
        # Hash the provided password with the same salt
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=len(stored_hash)
        )
        
        # Timing-safe comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, stored_hash)
    
    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """
        Generate a cryptographically secure random secret.
        Useful for MFA secrets, session tokens, etc.
        
        Args:
            length: Length in bytes
            
        Returns:
            Hex encoded secret string
        """
        return secrets.token_hex(length)
