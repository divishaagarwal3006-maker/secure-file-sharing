from db import get_db


def log_event(user_id, action, file_id=None, status="success"):
    """Never raises: a logging failure must not break a request."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO logs (user_id, action, file_id, status) VALUES (?, ?, ?, ?)",
            (user_id, action, file_id, status),
        )
        db.execute(
            "INSERT INTO activity_logs (user_id, action, file_id, status) VALUES (?, ?, ?, ?)",
            (user_id, action, file_id, status),
        )
        db.commit()
    except Exception:
        pass


def log_activity(user_id, action, file_id=None, status="success", details=None):
    log_event(user_id, action, file_id, status)
