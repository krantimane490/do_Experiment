from flask import Blueprint, request, jsonify

def create_auth_controller(auth_service):
    bp = Blueprint("auth", __name__)

    @bp.route("/register", methods=["POST"])
    def register():
        data = request.json
        user = auth_service.register(
            data.get("email"),
            data.get("password")
        )
        return jsonify({"id": user.id, "email": user.email}), 201

    @bp.route("/login", methods=["POST"])
    def login():
        data = request.json
        result = auth_service.login(
            data.get("email"),
            data.get("password")
        )
        return jsonify(result), 200

    return bp
