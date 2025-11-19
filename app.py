from flask import Flask, jsonify, render_template
from repositories.task_repository import TaskRepository
from repositories.user_repository import UserRepository
from services.task_service import TaskService
from services.notification_service import NotificationService
from services.auth_service import AuthService
from controllers.task_controller import create_task_controller
from controllers.auth_controller import create_auth_controller

def create_app():
    app = Flask(__name__)

    # Repositories
    task_repo = TaskRepository()
    user_repo = UserRepository()

    # Services
    notifier = NotificationService()
    task_service = TaskService(task_repo, notifier)
    auth_service = AuthService(user_repo)

    # Controllers
    task_controller = create_task_controller(task_service)
    auth_controller = create_auth_controller(auth_service)

    # Register routes
    app.register_blueprint(task_controller)
    app.register_blueprint(auth_controller)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
