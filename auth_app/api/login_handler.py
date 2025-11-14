"""
Login API handler (presentation layer).
Handles login requests and responses.
"""
from typing import Dict, Any, Optional
from services.auth_service import (
    AuthService,
    AuthenticationError,
    InvalidCredentialsError,
    AccountLockedError
)
from services.rate_limiter import RateLimitExceededError
from utils.validators import ValidationError


class LoginRequest:
    """Represents a login request."""
    
    def __init__(self, email: str, password: str, ip_address: Optional[str] = None):
        """
        Initialize login request.
        
        Args:
            email: User's email
            password: User's password
            ip_address: Client IP address
        """
        self.email = email
        self.password = password
        self.ip_address = ip_address


class LoginResponse:
    """Represents a login response."""
    
    def __init__(
        self,
        success: bool,
        message: str,
        session_id: Optional[str] = None,
        mfa_required: bool = False,
        error_code: Optional[str] = None
    ):
        """
        Initialize login response.
        
        Args:
            success: Whether login was successful
            message: Response message
            session_id: Session ID if successful
            mfa_required: Whether MFA verification is needed
            error_code: Error code if failed
        """
        self.success = success
        self.message = message
        self.session_id = session_id
        self.mfa_required = mfa_required
        self.error_code = error_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary."""
        return {
            "success": self.success,
            "message": self.message,
            "session_id": self.session_id,
            "mfa_required": self.mfa_required,
            "error_code": self.error_code
        }


class LoginHandler:
    """
    Handles login API requests.
    No business logic - delegates to AuthService.
    """
    
    def __init__(self, auth_service: AuthService):
        """
        Initialize login handler.
        
        Args:
            auth_service: Authentication service
        """
        self._auth_service = auth_service
    
    def handle_login(self, request: LoginRequest) -> LoginResponse:
        """
        Handle a login request.
        
        Args:
            request: LoginRequest object
            
        Returns:
            LoginResponse object
        """
        try:
            session, mfa_required = self._auth_service.login(
                email=request.email,
                password=request.password,
                ip_address=request.ip_address
            )
            
            if mfa_required:
                return LoginResponse(
                    success=True,
                    message="MFA verification required. Check your email for OTP.",
                    mfa_required=True
                )
            
            return LoginResponse(
                success=True,
                message="Login successful",
                session_id=session.session_id if session else None
            )
            
        except ValidationError as e:
            return LoginResponse(
                success=False,
                message=str(e),
                error_code="VALIDATION_ERROR"
            )
            
        except RateLimitExceededError as e:
            return LoginResponse(
                success=False,
                message=str(e),
                error_code="RATE_LIMIT_EXCEEDED"
            )
            
        except AccountLockedError as e:
            return LoginResponse(
                success=False,
                message=str(e),
                error_code="ACCOUNT_LOCKED"
            )
            
        except InvalidCredentialsError as e:
            return LoginResponse(
                success=False,
                message=str(e),
                error_code="INVALID_CREDENTIALS"
            )
            
        except AuthenticationError as e:
            return LoginResponse(
                success=False,
                message=str(e),
                error_code="AUTHENTICATION_ERROR"
            )
            
        except Exception as e:
            return LoginResponse(
                success=False,
                message="An unexpected error occurred",
                error_code="INTERNAL_ERROR"
            )
    
    def handle_logout(self, session_id: str) -> Dict[str, Any]:
        """
        Handle a logout request.
        
        Args:
            session_id: Session ID to logout
            
        Returns:
            Response dictionary
        """
        try:
            self._auth_service.logout(session_id)
            return {
                "success": True,
                "message": "Logout successful"
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "error_code": "LOGOUT_ERROR"
            }
