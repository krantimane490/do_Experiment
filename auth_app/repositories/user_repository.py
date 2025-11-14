"""
In-memory user repository with pre-populated sample users.
"""
from typing import Optional, Dict
from datetime import datetime
from models.user import User, UserRole
from services.password_hasher import PasswordHasher
from utils.time_utils import TimeUtils


class UserNotFoundError(Exception):
    """Raised when a user is not found."""
    pass


class UserRepository:
    """
    In-memory repository for user storage and retrieval.
    Initialized with sample users for testing.
    """
    
    def __init__(self):
        """Initialize repository with sample users."""
        self._users: Dict[str, User] = {}
        self._email_index: Dict[str, str] = {}  # email -> user_id mapping
        self._hasher = PasswordHasher()
        self._initialize_sample_users()
    
    def _initialize_sample_users(self) -> None:
        """Create sample users with hashed passwords."""
        now = TimeUtils.now()
        
        # Sample user 1: Admin user (premium)
        admin_user = User(
            user_id="usr_001",
            email="admin@example.com",
            password_hash=self._hasher.hash_password("Admin@123"),
            role=UserRole.ADMIN,
            is_locked=False,
            locked_until=None,
            mfa_enabled=True,
            mfa_secret=self._hasher.generate_secret(16),
            created_at=now,
            last_login=None
        )
        
        # Sample user 2: Normal user
        normal_user = User(
            user_id="usr_002",
            email="user@example.com",
            password_hash=self._hasher.hash_password("User@456"),
            role=UserRole.USER,
            is_locked=False,
            locked_until=None,
            mfa_enabled=False,
            mfa_secret=None,
            created_at=now,
            last_login=None
        )
        
        # Sample user 3: Locked user
        locked_user = User(
            user_id="usr_003",
            email="locked@example.com",
            password_hash=self._hasher.hash_password("Locked@789"),
            role=UserRole.VIEWER,
            is_locked=True,
            locked_until=TimeUtils.add_minutes(now, 15),
            mfa_enabled=False,
            mfa_secret=None,
            created_at=now,
            last_login=None
        )
        
        # Add users to repository
        self._add_user(admin_user)
        self._add_user(normal_user)
        self._add_user(locked_user)
    
    def _add_user(self, user: User) -> None:
        """Internal method to add a user to the repository."""
        self._users[user.user_id] = user
        self._email_index[user.email.lower()] = user.user_id
    
    def find_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by email address.
        
        Args:
            email: Email address to search
            
        Returns:
            User object if found, None otherwise
        """
        email_lower = email.lower()
        user_id = self._email_index.get(email_lower)
        if user_id:
            return self._users.get(user_id)
        return None
    
    def find_by_id(self, user_id: str) -> Optional[User]:
        """
        Find a user by user ID.
        
        Args:
            user_id: User ID to search
            
        Returns:
            User object if found, None otherwise
        """
        return self._users.get(user_id)
    
    def update_user(self, user: User) -> None:
        """
        Update a user in the repository.
        
        Args:
            user: User object with updated fields
            
        Raises:
            UserNotFoundError: If user doesn't exist
        """
        if user.user_id not in self._users:
            raise UserNotFoundError(f"User {user.user_id} not found")
        
        self._users[user.user_id] = user
        self._email_index[user.email.lower()] = user.user_id
    
    def lock_user(self, user_id: str, lock_duration_minutes: int) -> None:
        """
        Lock a user account for a specified duration.
        
        Args:
            user_id: ID of user to lock
            lock_duration_minutes: Duration in minutes
            
        Raises:
            UserNotFoundError: If user doesn't exist
        """
        user = self.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        
        user.is_locked = True
        user.locked_until = TimeUtils.add_minutes(TimeUtils.now(), lock_duration_minutes)
        self.update_user(user)
    
    def unlock_user(self, user_id: str) -> None:
        """
        Unlock a user account.
        
        Args:
            user_id: ID of user to unlock
            
        Raises:
            UserNotFoundError: If user doesn't exist
        """
        user = self.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        
        user.is_locked = False
        user.locked_until = None
        self.update_user(user)
    
    def update_last_login(self, user_id: str) -> None:
        """
        Update the last login timestamp for a user.
        
        Args:
            user_id: ID of user to update
            
        Raises:
            UserNotFoundError: If user doesn't exist
        """
        user = self.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        
        user.last_login = TimeUtils.now()
        self.update_user(user)
