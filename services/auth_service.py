from models.user import User
from utils.password_utils import hash_password, verify_password

class AuthService:
    def __init__(self, user_repo):
        self.user_repo = user_repo

    def register(self, email: str, password: str):
        print(f"Attempting to register user: {email}")
        if self.user_repo.get_by_email(email):
            print(f"Registration failed: User {email} already exists.")
            raise ValueError("User already exists.")

        if not email or "@" not in email:
            print(f"Registration failed: Invalid email format for {email}.")
            raise ValueError("Invalid email.")

        if not password or len(password) < 6:
            print(f"Registration failed: Weak password for {email}.")
            raise ValueError("Weak password.")

        user = User(
            id=0,
            email=email,
            password_hash=hash_password(password)
        )
        self.user_repo.save(user)
        print(f"User {email} registered successfully with ID: {user.id}")
        return user

    def login(self, email: str, password: str):
        print(f"Attempting to log in user: {email}")
        user = self.user_repo.get_by_email(email)
        if not user:
            print(f"Login failed: User {email} not found.")
            raise ValueError("Invalid credentials.")

        if not verify_password(password, user.password_hash):
            print(f"Login failed: Incorrect password for {email}.")
            raise ValueError("Invalid credentials.")

        print(f"User {email} logged in successfully.")
        return {"message": "Login successful", "user_id": user.id}
