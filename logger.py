from db import get_db


def log_event(user_id, action, file_id=None, status="success"):
    """Never raises: a logging failure must not break a request."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO logs (user_id, action, file_id, status) VALUES (?, ?, ?, ?)",
            (user_id, action, file_id, status),
        )
        db.commit()
    except Exception:
        pass