import functools
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import (Blueprint, flash, g, redirect, render_template,
                   request, session, url_for)

from db import get_db
from logger import log_event
from validators import validate_password, validate_username

bp = Blueprint("auth", __name__)

LANDING_ENDPOINT = "files.index"
MAX_ATTEMPTS = 5
LOCK_SECONDS = 300      # 5 minutes
IDLE_TIMEOUT = 1800     # 30 minutes

ph = PasswordHasher()                    # Argon2id, random salt per hash
DUMMY_HASH = ph.hash("dummy-password")   # equalises timing for unknown usernames


@bp.before_app_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid is None:
        return
    now = int(time.time())
    if now - session.get("last_seen", 0) > IDLE_TIMEOUT:
        session.clear()
        return
    session["last_seen"] = now
    user = get_db().execute(
        "SELECT id, username, role FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if user is None:
        session.clear()
        return
    g.user = user


def get_current_user():
    return g.get("user")


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if get_current_user() is None:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_username(username):
            flash("Username must be 3-30 letters, digits or underscores.")
            return render_template("register.html"), 400
        if not validate_password(password):
            flash("Password needs 12+ characters with upper, lower and a digit.")
            return render_template("register.html"), 400

        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, ph.hash(password)),   # role never comes from the form
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is not available.")
            return render_template("register.html"), 400

        log_event(cur.lastrowid, "register", None, "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        now = int(time.time())

        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and user["locked_until"] > now:
            log_event(user["id"], "login", None, "locked")
            flash("Too many failed attempts. Try again later.")
            return render_template("login.html"), 429

        stored = user["password_hash"] if user else DUMMY_HASH
        try:
            ph.verify(stored, password)
            ok = user is not None
        except (VerifyMismatchError, InvalidHashError):
            ok = False

        if not ok:
            if user:
                attempts = user["failed_attempts"] + 1
                locked = now + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
                db.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (0 if locked else attempts, locked, user["id"]),
                )
                db.commit()
            log_event(user["id"] if user else None, "login", None, "failed")
            flash("Invalid username or password.")
            return render_template("login.html"), 401

        if ph.check_needs_rehash(user["password_hash"]):
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (ph.hash(password), user["id"]))
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                   (user["id"],))
        db.commit()

        session.clear()                      # prevents session fixation
        session["user_id"] = user["id"]
        session["last_seen"] = now
        session.permanent = True
        log_event(user["id"], "login", None, "success")
        return redirect(url_for(LANDING_ENDPOINT))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(g.user["id"], "logout", None, "success")
    session.clear()
    return redirect(url_for("auth.login"))