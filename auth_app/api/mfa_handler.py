"""
MFA API handler (presentation layer).
Handles MFA verification requests.
"""
from typing import Dict, Any, Optional
from services.auth_service import AuthService, InvalidCredentialsError
from services.otp_service import (
    OTPExpiredError,
    OTPInvalidError,
    OTPMaxAttemptsError
)


class MFAVerifyRequest:
    """Represents an MFA verification request."""
    
    def __init__(self, email: str, otp_code: str, ip_address: Optional[str] = None):
        """
        Initialize MFA verification request.
        
        Args:
            email: User's email
            otp_code: OTP code to verify
            ip_address: Client IP address
        """
        self.email = email
        self.otp_code = otp_code
        self.ip_address = ip_address


class MFAVerifyResponse:
    """Represents an MFA verification response."""
    
    def __init__(
        self,
        success: bool,
        message: str,
        session_id: Optional[str] = None,
        error_code: Optional[str] = None
    ):
        """
        Initialize MFA verification response.
        
        Args:
            success: Whether verification was successful
            message: Response message
            session_id: Session ID if successful
            error_code: Error code if failed
        """
        self.success = success
        self.message = message
        self.session_id = session_id
        self.error_code = error_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary."""
        return {
            "success": self.success,
            "message": self.message,
            "session_id": self.session_id,
            "error_code": self.error_code
        }


class MFAHandler:
    """
    Handles MFA verification API requests.
    No business logic - delegates to AuthService.
    """
    
    def __init__(self, auth_service: AuthService):
        """
        Initialize MFA handler.
        
        Args:
            auth_service: Authentication service
        """
        self._auth_service = auth_service
    
    def handle_verify_otp(self, request: MFAVerifyRequest) -> MFAVerifyResponse:
        """
        Handle an OTP verification request.
        
        Args:
            request: MFAVerifyRequest object
            
        Returns:
            MFAVerifyResponse object
        """
        try:
            session = self._auth_service.verify_mfa(
                email=request.email,
                otp_code=request.otp_code,
                ip_address=request.ip_address
            )
            
            return MFAVerifyResponse(
                success=True,
                message="MFA verification successful",
                session_id=session.session_id
            )
            
        except OTPExpiredError as e:
            return MFAVerifyResponse(
                success=False,
                message=str(e),
                error_code="OTP_EXPIRED"
            )
            
        except OTPInvalidError as e:
            return MFAVerifyResponse(
                success=False,
                message=str(e),
                error_code="OTP_INVALID"
            )
            
        except OTPMaxAttemptsError as e:
            return MFAVerifyResponse(
                success=False,
                message=str(e),
                error_code="OTP_MAX_ATTEMPTS"
            )
            
        except InvalidCredentialsError as e:
            return MFAVerifyResponse(
                success=False,
                message=str(e),
                error_code="INVALID_OTP"
            )
            
        except Exception as e:
            return MFAVerifyResponse(
                success=False,
                message="An unexpected error occurred during MFA verification",
                error_code="INTERNAL_ERROR"
            )
