"""
Main authentication service orchestrating login, MFA, and session management.
"""
from typing import Optional, Tuple
from models.user import User
from models.session import Session
from repositories.user_repository import UserRepository, UserNotFoundError
from repositories.failed_attempts_repository import FailedAttemptsRepository
from services.password_hasher import PasswordHasher
from services.rate_limiter import RateLimiter, RateLimitExceededError
from services.session_manager import SessionManager
from services.otp_service import OTPService
from services.audit_logger import AuditLogger, AuditEventType
from utils.validators import EmailValidator, PasswordValidator, ValidationError
from utils.time_utils import TimeUtils


class AuthenticationError(Exception):
    """Base exception for authentication errors."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked."""
    pass


class MFARequiredError(AuthenticationError):
    """Raised when MFA verification is required."""
    pass


class AuthService:
    """
    Main authentication service coordinating all auth operations.
    Implements complete login flow with security features.
    """
    
    # Security constants
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    
    def __init__(
        self,
        user_repository: UserRepository,
        failed_attempts_repository: FailedAttemptsRepository,
        password_hasher: PasswordHasher,
        rate_limiter: RateLimiter,
        session_manager: SessionManager,
        otp_service: OTPService,
        audit_logger: AuditLogger
    ):
        """
        Initialize authentication service with dependencies.
        
        Args:
            user_repository: User data repository
            failed_attempts_repository: Failed attempts tracker
            password_hasher: Password hashing service
            rate_limiter: Rate limiting service
            session_manager: Session management service
            otp_service: OTP service for MFA
            audit_logger: Audit logging service
        """
        self._user_repo = user_repository
        self._failed_attempts_repo = failed_attempts_repository
        self._hasher = password_hasher
        self._rate_limiter = rate_limiter
        self._session_manager = session_manager
        self._otp_service = otp_service
        self._audit_logger = audit_logger
    
    def login(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None
    ) -> Tuple[Optional[Session], bool]:
        """
        Authenticate user with email and password.
        
        Full login flow:
        1. Validate input formats
        2. Check rate limits
        3. Fetch user
        4. Check if account is locked
        5. Verify password
        6. Handle MFA if enabled
        7. Create session on success
        8. Log audit events
        
        Args:
            email: User's email address
            password: User's password
            ip_address: Client IP address
            
        Returns:
            Tuple of (Session or None, mfa_required)
            - If MFA not required: (Session, False)
            - If MFA required: (None, True)
            
        Raises:
            ValidationError: If input validation fails
            RateLimitExceededError: If rate limit exceeded
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
        """
        # Step 1: Validate email format
        is_valid, error_msg = EmailValidator.validate(email)
        if not is_valid:
            self._audit_logger.log_event(
                AuditEventType.LOGIN_FAILURE,
                success=False,
                email=email,
                ip_address=ip_address,
                reason=error_msg
            )
            raise ValidationError(error_msg)
        
        # Step 2: Validate password format
        is_valid, error_msg = PasswordValidator.validate(password)
        if not is_valid:
            self._audit_logger.log_event(
                AuditEventType.LOGIN_FAILURE,
                success=False,
                email=email,
                ip_address=ip_address,
                reason=error_msg
            )
            raise ValidationError(error_msg)
        
        # Step 3: Check rate limits (IP and email)
        try:
            if ip_address:
                self._rate_limiter.check_ip_limit(ip_address)
            self._rate_limiter.check_email_limit(email)
        except RateLimitExceededError as e:
            self._audit_logger.log_event(
                AuditEventType.RATE_LIMIT_EXCEEDED,
                success=False,
                email=email,
                ip_address=ip_address,
                reason=str(e)
            )
            raise
        
        # Record attempt for rate limiting
        if ip_address:
            self._rate_limiter.record_attempt_for_ip(ip_address)
        self._rate_limiter.record_attempt_for_email(email)
        
        # Step 4: Fetch user from repository
        user = self._user_repo.find_by_email(email)
        if not user:
            self._handle_failed_login(email, ip_address, "User not found")
            raise InvalidCredentialsError("Invalid email or password")
        
        # Step 5: Check if account is locked
        if user.is_locked:
            if user.locked_until and not TimeUtils.is_expired(user.locked_until):
                time_remaining = TimeUtils.time_until(user.locked_until)
                minutes_remaining = int(time_remaining.total_seconds() / 60)
                
                self._audit_logger.log_event(
                    AuditEventType.LOGIN_FAILURE,
                    success=False,
                    user_id=user.user_id,
                    email=email,
                    ip_address=ip_address,
                    reason="Account locked"
                )
                
                raise AccountLockedError(
                    f"Account is locked. Try again in {minutes_remaining} minutes."
                )
            else:
                # Lock expired - unlock account
                self._user_repo.unlock_user(user.user_id)
                user.is_locked = False
        
        # Step 6: Verify password hash
        try:
            is_valid_password = self._hasher.verify_password(password, user.password_hash)
        except Exception as e:
            self._handle_failed_login(email, ip_address, f"Password verification error: {str(e)}")
            raise InvalidCredentialsError("Invalid email or password")
        
        if not is_valid_password:
            self._handle_failed_login(email, ip_address, "Invalid password")
            
            # Check if should lock account
            failed_count = self._failed_attempts_repo.count_recent_failures_by_email(
                email,
                self.LOCKOUT_DURATION_MINUTES
            )
            
            if failed_count >= self.MAX_FAILED_ATTEMPTS:
                self._user_repo.lock_user(user.user_id, self.LOCKOUT_DURATION_MINUTES)
                self._audit_logger.log_event(
                    AuditEventType.ACCOUNT_LOCKED,
                    success=True,
                    user_id=user.user_id,
                    email=email,
                    ip_address=ip_address,
                    reason=f"Exceeded {self.MAX_FAILED_ATTEMPTS} failed attempts"
                )
                raise AccountLockedError(
                    f"Account locked due to {self.MAX_FAILED_ATTEMPTS} failed attempts. "
                    f"Try again in {self.LOCKOUT_DURATION_MINUTES} minutes."
                )
            
            raise InvalidCredentialsError("Invalid email or password")
        
        # Password is valid - clear failed attempts
        self._failed_attempts_repo.clear_failures_for_email(email)
        if ip_address:
            self._rate_limiter.reset_for_ip(ip_address)
        self._rate_limiter.reset_for_email(email)
        
        # Step 7: Check if MFA is enabled
        if user.mfa_enabled:
            # Generate and send OTP
            otp_code = self._otp_service.generate_otp(user.user_id)
            self._otp_service.send_otp(email, otp_code)
            
            self._audit_logger.log_event(
                AuditEventType.MFA_SENT,
                success=True,
                user_id=user.user_id,
                email=email,
                ip_address=ip_address
            )
            
            # Return None session, MFA required
            return None, True
        
        # Step 8: Create session (no MFA required)
        session = self._create_session_for_user(user, ip_address)
        
        # Update last login
        self._user_repo.update_last_login(user.user_id)
        
        self._audit_logger.log_event(
            AuditEventType.LOGIN_SUCCESS,
            success=True,
            user_id=user.user_id,
            email=email,
            ip_address=ip_address
        )
        
        return session, False
    
    def verify_mfa(
        self,
        email: str,
        otp_code: str,
        ip_address: Optional[str] = None
    ) -> Session:
        """
        Verify MFA OTP and complete login.
        
        Args:
            email: User's email address
            otp_code: OTP code to verify
            ip_address: Client IP address
            
        Returns:
            Authenticated Session object
            
        Raises:
            InvalidCredentialsError: If user not found
            Various OTP errors from OTPService
        """
        # Fetch user
        user = self._user_repo.find_by_email(email)
        if not user:
            raise InvalidCredentialsError("User not found")
        
        # Verify OTP
        try:
            is_valid = self._otp_service.verify_otp(user.user_id, otp_code)
            
            if not is_valid:
                self._audit_logger.log_event(
                    AuditEventType.MFA_FAILED,
                    success=False,
                    user_id=user.user_id,
                    email=email,
                    ip_address=ip_address,
                    reason="Invalid OTP"
                )
                raise InvalidCredentialsError("Invalid OTP code")
            
            # OTP verified - create session
            session = self._create_session_for_user(user, ip_address)
            session.is_mfa_verified = True
            
            # Update last login
            self._user_repo.update_last_login(user.user_id)
            
            self._audit_logger.log_event(
                AuditEventType.MFA_VERIFIED,
                success=True,
                user_id=user.user_id,
                email=email,
                ip_address=ip_address
            )
            
            self._audit_logger.log_event(
                AuditEventType.LOGIN_SUCCESS,
                success=True,
                user_id=user.user_id,
                email=email,
                ip_address=ip_address,
                metadata={"mfa": True}
            )
            
            return session
            
        except Exception as e:
            self._audit_logger.log_event(
                AuditEventType.MFA_FAILED,
                success=False,
                user_id=user.user_id,
                email=email,
                ip_address=ip_address,
                reason=str(e)
            )
            raise
    
    def _create_session_for_user(
        self,
        user: User,
        ip_address: Optional[str] = None
    ) -> Session:
        """
        Create a session for an authenticated user.
        
        Args:
            user: User object
            ip_address: Client IP address
            
        Returns:
            New Session object
        """
        session = self._session_manager.create_session(
            user_id=user.user_id,
            role=user.role,
            ip_address=ip_address
        )
        
        self._audit_logger.log_event(
            AuditEventType.SESSION_CREATED,
            success=True,
            user_id=user.user_id,
            email=user.email,
            ip_address=ip_address,
            metadata={"session_id": session.session_id}
        )
        
        return session
    
    def _handle_failed_login(
        self,
        email: str,
        ip_address: Optional[str],
        reason: str
    ) -> None:
        """
        Handle a failed login attempt.
        
        Args:
            email: Email that failed
            ip_address: IP address
            reason: Reason for failure
        """
        self._failed_attempts_repo.record_failure(
            email=email,
            ip_address=ip_address or "unknown",
            reason=reason
        )
        
        self._audit_logger.log_event(
            AuditEventType.LOGIN_FAILURE,
            success=False,
            email=email,
            ip_address=ip_address,
            reason=reason
        )
    
    def logout(self, session_id: str) -> None:
        """
        Logout user by revoking session.
        
        Args:
            session_id: Session ID to revoke
        """
        self._session_manager.revoke_session(session_id)
        
        self._audit_logger.log_event(
            AuditEventType.LOGOUT,
            success=True,
            metadata={"session_id": session_id}
        )
