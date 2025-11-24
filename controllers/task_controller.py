from flask import Blueprint, request, jsonify, render_template

def create_task_controller(task_service):
    bp = Blueprint("tasks", __name__)

    @bp.route("/tasks", methods=["GET"])
    def get_tasks():
        print("getting the task")
        tasks = task_service.get_all_tasks()
        return jsonify([vars(task) for task in tasks]), 200

    @bp.route("/tasks/<int:task_id>", methods=["GET"])
    def get_task(task_id):
        task = task_service.get_task_by_id(task_id)
        if task:
            return render_template("task.html", task=task)
        return "Task not found", 404

    @bp.route("/tasks", methods=["POST"])
    def create_task():
        data = request.json
        task = task_service.create_task(
            data.get("title"),
            data.get("description"),
            data.get("due_date")
        )
        return jsonify(vars(task)), 201

    @bp.route("/tasks/<int:task_id>", methods=["PUT"])
    def update_task(task_id):
        """Update an existing task"""
        data = request.json
        try:
            task = task_service.update_task(
                task_id,
                data.get("title"),
                data.get("description"),
                data.get("due_date")
            )
            return jsonify(vars(task)), 200
        except KeyError as e:
            return jsonify({"message": str(e)}), 404
        except ValueError as e:
            return jsonify({"message": str(e)}), 400

    @bp.route("/tasks/<int:task_id>", methods=["DELETE"])
    def delete_task(task_id):
        try:
            result = task_service.delete_task(task_id)
            return jsonify(result), 200
        except KeyError as e:
            return jsonify({"message": str(e)}), 404

    @bp.route("/tasks/<int:task_id>/complete", methods=["POST"])
    def complete_task(task_id):
        task = task_service.mark_completed(task_id)
        return jsonify(vars(task)), 200

    @bp.route("/tasks/<int:task_id>/notify", methods=["POST"])
    def notify_due(task_id):
        result = task_service.check_due_soon(task_id)
        return jsonify({"message": result}), 200

    return bp