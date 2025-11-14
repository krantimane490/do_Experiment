"""
Example usage demonstrating the authentication module.
Shows complete login flows including MFA.
"""
import logging
from typing import Tuple
from repositories.user_repository import UserRepository
from repositories.failed_attempts_repository import FailedAttemptsRepository
from repositories.session_repository import SessionRepository
from services.password_hasher import PasswordHasher
from services.rate_limiter import RateLimiter
from services.session_manager import SessionManager
from services.otp_service import OTPService
from services.audit_logger import AuditLogger
from services.auth_service import AuthService
from api.login_handler import LoginHandler, LoginRequest
from api.mfa_handler import MFAHandler, MFAVerifyRequest


def setup_logging():
    """Configures logging for the demo application."""
    # Configure the root logger for general script output
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s', # Simple format for demo prints
        force=True # Override any existing config
    )
    
    # Configure a specific handler for audit logs for cleaner output
    audit_logger = logging.getLogger("auth_audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.addHandler(logging.StreamHandler()) # Ensures it prints to console

def print_separator():
    """Print a separator line."""
    print("\n" + "=" * 70 + "\n")


def setup_auth_components() -> Tuple[LoginHandler, MFAHandler, OTPService, UserRepository]:
    """
    Initializes and returns all necessary components for the auth demos.
    This avoids repetitive setup in each demo function.
    """
    # Initialize all components
    user_repo = UserRepository()
    failed_attempts_repo = FailedAttemptsRepository()
    session_repo = SessionRepository()
    hasher = PasswordHasher()
    rate_limiter = RateLimiter()
    session_manager = SessionManager(session_repo)
    otp_service = OTPService()
    audit_logger = AuditLogger()

    auth_service = AuthService(
        user_repo,
        failed_attempts_repo,
        hasher,
        rate_limiter,
        session_manager,
        otp_service,
        audit_logger
    )

    login_handler = LoginHandler(auth_service)
    mfa_handler = MFAHandler(auth_service)

    return login_handler, mfa_handler, otp_service, user_repo


def demo_successful_login_without_mfa():
    """Demo: Successful login for user without MFA."""
    print("DEMO 1: Successful Login (No MFA)")
    print_separator()

    login_handler, _, _, _ = setup_auth_components()

    # Attempt login
    request = LoginRequest(
        email="user@example.com",
        password="User@456",
        ip_address="192.168.1.100"
    )
    
    response = login_handler.handle_login(request)
    
    print(f"Login Response: {response.to_dict()}")
    print_separator()


def demo_successful_login_with_mfa():
    """Demo: Successful login with MFA verification."""
    print("DEMO 2: Successful Login (With MFA)")
    print_separator()

    login_handler, mfa_handler, otp_service, user_repo = setup_auth_components()

    # Step 1: Login (will require MFA)
    print("Step 1: Initial login...")
    request = LoginRequest(
        email="admin@example.com",
        password="Admin@123",
        ip_address="192.168.1.101"
    )
    
    response = login_handler.handle_login(request)
    print(f"Login Response: {response.to_dict()}")
    
    if response.mfa_required:
        print("\nStep 2: Verify MFA...")
        print("(In production, user receives OTP via email/SMS)")

        # In a real app, the user would provide the OTP they received.
        # For this demo, we'll retrieve the OTP directly from the OTP service
        # to simulate the user entering the correct code.
        admin_user = user_repo.find_by_email("admin@example.com")
        otp_record = otp_service.get_otp_record(admin_user.user_id)
        if not otp_record:
            print("\nError: No pending OTP found for user.")
            return
        otp_code = otp_record.otp_code

        mfa_request = MFAVerifyRequest(
            email="admin@example.com",
            otp_code=otp_code,
            ip_address="192.168.1.101"
        )
        
        mfa_response = mfa_handler.handle_verify_otp(mfa_request)
        print(f"\nMFA Response: {mfa_response.to_dict()}")
    
    print_separator()


def demo_failed_login_invalid_password():
    """Demo: Failed login with invalid password."""
    print("DEMO 3: Failed Login (Invalid Password)")
    print_separator()

    login_handler, _, _, _ = setup_auth_components()

    # Attempt login with wrong password
    request = LoginRequest(
        email="user@example.com",
        password="WrongPassword@123",
        ip_address="192.168.1.102"
    )
    
    response = login_handler.handle_login(request)
    print(f"Login Response: {response.to_dict()}")
    print_separator()


def demo_account_lockout():
    """Demo: Account lockout after multiple failed attempts."""
    print("DEMO 4: Account Lockout (Multiple Failed Attempts)")
    print_separator()

    login_handler, _, _, _ = setup_auth_components()

    # Attempt login 5 times with wrong password
    for i in range(6):
        print(f"\nAttempt {i + 1}:")
        request = LoginRequest(
            email="user@example.com",
            password="WrongPassword@123",
            ip_address="192.168.1.103"
        )
        
        response = login_handler.handle_login(request)
        print(f"Response: {response.to_dict()}")
        
        if response.error_code == "ACCOUNT_LOCKED":
            print("\n✗ Account has been locked!")
            break
    
    print_separator()


def demo_rate_limiting():
    """Demo: Rate limiting in action."""
    print("DEMO 5: Rate Limiting")
    print_separator()

    login_handler, _, _, _ = setup_auth_components()

    # Rapid attempts from same email
    for i in range(7):
        print(f"\nAttempt {i + 1}:")
        request = LoginRequest(
            email="nonexistent@example.com",
            password="Test@123",
            ip_address="192.168.1.104"
        )
        
        response = login_handler.handle_login(request)
        print(f"Response: {response.to_dict()}")
        
        if response.error_code == "RATE_LIMIT_EXCEEDED":
            print("\n✗ Rate limit exceeded!")
            break
    
    print_separator()


def main():
    """Run all demos."""
    # Set up a clean, unified logging system first
    setup_logging()

    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 10 + "PRODUCTION-GRADE AUTHENTICATION MODULE DEMO" + " " * 15 + "║")
    print("╚" + "=" * 68 + "╝")
    
    demos = [
        demo_successful_login_without_mfa,
        demo_successful_login_with_mfa,
        demo_failed_login_invalid_password,
        demo_account_lockout,
        demo_rate_limiting
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"Demo failed with error: {e}")
            print_separator()
    
    print("\n✓ All demos completed!\n")


if __name__ == "__main__":
    main()
