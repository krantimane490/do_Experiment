class UserRepository:
    def __init__(self):
        self.users = {}
        self.counter = 1

    def save(self, user):
        user.id = self.counter
        self.users[self.counter] = user
        self.counter += 1
        return user

    def get_by_email(self, email: str):
        for u in self.users.values():
            if u.email == email:
                return u
        return None
