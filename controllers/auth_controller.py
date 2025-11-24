from flask import Blueprint, request, jsonify

def create_auth_controller(auth_service):
    bp = Blueprint("auth", __name__)

    @bp.route("/register", methods=["POST"])
    def register():
        try:
            data = request.json
            if not data:
                return jsonify({"error": "No data provided"}), 400
            
            user = auth_service.register(
                data.get("email"),
                data.get("password")
            )
            return jsonify({"id": user.id, "email": user.email}), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return jsonify({"error": "Registration failed"}), 500

    @bp.route("/login", methods=["POST"])
    def login():
        try:
            data = request.json
            if not data:
                return jsonify({"error": "No data provided"}), 400
            
            result = auth_service.login(
                data.get("email"),
                data.get("password")
            )
            return jsonify(result), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 401
        except Exception as e:
            print(f"Login error: {str(e)}")
            return jsonify({"error": "Login failed"}), 500

    return bp