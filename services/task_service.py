from datetime import datetime, timedelta
from utils.validators import validate_title

class TaskService:
    def __init__(self, repo, notifier):
        self.repo = repo
        self.notifier = notifier

    def create_task(self, title, description, due_date=None):
        print(f"Attempting to create task: {title}")
        validate_title(title)

        if due_date:
            try:
                due_date = datetime.fromisoformat(due_date)
            except:
                print(f"Task creation failed for '{title}': Invalid date format.")
                raise ValueError("Invalid date format.")

        from models.task import Task
        new_task = Task(id=0, title=title, description=description, due_date=due_date)
        self.repo.save(new_task)
        print(f"Task '{title}' created successfully with ID: {new_task.id}")
        return new_task

    def get_all_tasks(self):
        print("Fetching all tasks.")
        return self.repo.get_all()

    def get_task_by_id(self, task_id):
        print(f"Fetching task with ID: {task_id}")
        return self.repo.get(task_id)

    def mark_completed(self, task_id):
        print(f"Attempting to mark task {task_id} as completed.")
        task = self.repo.get(task_id)
        if not task:
            print(f"Mark completed failed: Task {task_id} not found.")
            raise KeyError("Task not found.")

        task.is_completed = True
        self.repo.update(task)
        print(f"Task {task_id} marked as completed successfully.")
        return task

    def check_due_soon(self, task_id):
        print(f"Checking if task {task_id} is due soon.")
        task = self.repo.get(task_id)
        if not task:
            print(f"Check due soon failed: Task {task_id} not found.")
            raise KeyError("Task not found.")

        if task.due_date and task.due_date - datetime.now() < timedelta(days=1):
            return self.notifier.send_due_soon_email(task)

        return None

    def delete_task(self, task_id):
        print(f"Attempting to delete task {task_id}.")
        task = self.repo.get(task_id)
        if not task:
            print(f"Delete failed: Task {task_id} not found.")
            raise KeyError("Task not found.")
        self.repo.delete(task_id)
        print(f"Task {task_id} deleted successfully.")
        return {"message": "Task deleted successfully"}
