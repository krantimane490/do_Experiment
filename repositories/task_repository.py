class TaskRepository:
    def __init__(self):
        self.tasks = {}
        self.counter = 1

    def save(self, task):
        task.id = self.counter
        self.tasks[self.counter] = task
        self.counter += 1
        return task

    def get(self, task_id: int):
        return self.tasks.get(task_id)

    def get_all(self):
        return list(self.tasks.values())

    def update(self, task):
        if task.id not in self.tasks:
            raise KeyError("Task not found.")
        self.tasks[task.id] = task
        return task

    def delete(self, task_id: int):
        if task_id not in self.tasks:
            raise KeyError("Task not found.")
        del self.tasks[task_id]
