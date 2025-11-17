from flask import Flask, render_template, request, redirect, session
from database import init_db
from models import (
    create_user, authenticate,
    get_all_blogs, add_blog, create_sample_blogs
)

app = Flask(__name__)
app.secret_key = "weaksecret"  # 🔥 Vulnerability: Weak secret key

init_db()
create_sample_blogs()  # Auto seed data (dependency)


@app.route("/")
def home():
    blogs = get_all_blogs()
    return render_template("home.html", blogs=blogs, user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        create_user(request.form["username"], request.form["password"])
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = authenticate(request.form["username"], request.form["password"])
        if user:
            session["user"] = request.form["username"]
            return redirect("/")
        return "Login Failed! (Try SQL injection 👀)"

    return render_template("login.html")


@app.route("/add", methods=["GET", "POST"])
def add_blog_page():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        add_blog(
            request.form["title"],
            request.form["content"],
            session["user"]
        )
        return redirect("/")

    return render_template("add_blog.html")


# 🔥 Vulnerable Admin Page (No Authentication)
@app.route("/admin")
def admin():
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=True)
