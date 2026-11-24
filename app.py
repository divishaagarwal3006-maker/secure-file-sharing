import os
from dotenv import load_dotenv
from flask import Flask
import db


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ["SECRET_KEY"],
        DATABASE=os.path.join(app.instance_path, "app.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=1800,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)

    from auth import bp, login_required, get_current_user
    app.register_blueprint(bp)

    @app.route("/", endpoint="files.index")
    @login_required
    def home():
        return (f"<h1>Hello {get_current_user()['username']}</h1>"
                "<form method='post' action='/logout'><button>Logout</button></form>")

    return app