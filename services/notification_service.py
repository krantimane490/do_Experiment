class NotificationService:
    # external service to mock during tests
    def send_due_soon_email(self, task):
        # Imagine an external email API here
        return f"Email sent for task {task.id}"
