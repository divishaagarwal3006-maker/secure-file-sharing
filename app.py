import os
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, url_for
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
    with app.app_context():
        db.init_db()

    from auth import bp, login_required, get_current_user
    from logger import log_event
    app.register_blueprint(bp)

    storage_dir = os.path.join(app.instance_path, "private_uploads")
    key_file = os.path.join(app.instance_path, "file-encryption.key")

    def permission_checker(user_id, file_id, action):
        row = db.get_db().execute(
            "SELECT owner_id FROM secure_files WHERE file_id = ?", (file_id,)
        ).fetchone()
        if not row:
            return False
        if str(row["owner_id"]) == str(user_id):
            return True
        permission = db.get_db().execute(
            "SELECT can_read, can_write, can_delete, can_share FROM permissions "
            "WHERE file_id = ? AND user_id = ?", (file_id, user_id)
        ).fetchone()
        return bool(permission and permission[{"read": "can_read", "write": "can_write", "delete": "can_delete", "share": "can_share"}[action]])

    from secure_file_manager import create_file_blueprint
    app.register_blueprint(create_file_blueprint(
        database_path=app.config["DATABASE"], storage_dir=storage_dir,
        key_file=key_file, public_dir=app.static_folder,
        user_id_provider=lambda: g.user["id"] if g.user else None,
        permission_checker=permission_checker, activity_logger=log_event,
    ))

    @app.route("/", endpoint="files.index")
    @login_required
    def home():
        user_id = g.user["id"]
        connection = db.get_db()
        owned = connection.execute(
            "SELECT * FROM secure_files WHERE owner_id = ? AND storage_status = 'stored' "
            "ORDER BY upload_date DESC", (str(user_id),)
        ).fetchall()
        shared = connection.execute(
            "SELECT f.*, u.username AS owner_username FROM secure_files f "
            "JOIN permissions p ON p.file_id = f.file_id "
            "JOIN users u ON CAST(u.id AS TEXT) = f.owner_id "
            "WHERE p.user_id = ? AND f.storage_status = 'stored' ORDER BY f.upload_date DESC",
            (user_id,),
        ).fetchall()
        activity = connection.execute(
            "SELECT action, status, timestamp, file_id FROM activity_logs "
            "WHERE user_id = ? ORDER BY id DESC LIMIT 10", (user_id,)
        ).fetchall()
        total = len(owned) + len(shared)
        return render_template("dashboard.html", user=g.user, owned=owned,
                               shared=shared, activity=activity, total=total)

    @app.post("/files/<file_id>/share", endpoint="files.share")
    @login_required
    def share(file_id):
        target = request.form.get("username", "").strip()
        recipient = db.get_db().execute("SELECT id FROM users WHERE username = ?", (target,)).fetchone()
        file_row = db.get_db().execute("SELECT owner_id FROM secure_files WHERE file_id = ?", (file_id,)).fetchone()
        if not file_row or str(file_row["owner_id"]) != str(g.user["id"]):
            flash("Only the file owner can share this file.", "error")
            return redirect(url_for("files.index"))
        if not recipient or recipient["id"] == g.user["id"]:
            flash("Choose another registered user.", "error")
            return redirect(url_for("files.index"))
        db.get_db().execute(
            "INSERT INTO permissions (file_id, user_id, can_read) VALUES (?, ?, 1) "
            "ON CONFLICT(file_id, user_id) DO UPDATE SET can_read = 1",
            (file_id, recipient["id"]),
        )
        db.get_db().commit()
        log_event(g.user["id"], "share", file_id, "success")
        flash(f"Shared with {target}.", "success")
        return redirect(url_for("files.index"))

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
