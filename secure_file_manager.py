"""Private encrypted file-management routes for an existing Flask application.

The host app supplies its authentication provider, Member 2 permission check,
database location, private storage, and optional Member 4 activity logger.
"""
from __future__ import annotations

import io
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from flask import (Blueprint, abort, current_app, make_response, redirect,
                   render_template_string, request, send_file, url_for)
from werkzeug.exceptions import HTTPException

from secure_file_crypto import (FileCryptoError, calculate_checksum, decrypt_file,
                                encrypt_file, load_encryption_key, verify_checksum)
from secure_file_validation import (MAX_UPLOAD_BYTES,
                                    FileValidationError, validate_renamed_filename,
                                    validate_upload)

_PAGE = """<!doctype html><html lang=en><meta charset=utf-8><title>My files</title>
<h1>My files</h1><p role=status>{{ message }}</p>
<form method=post action='{{ url_for(endpoint + ".upload") }}' enctype=multipart/form-data>
  <label>Choose PDF, TXT, JPG, or PNG (up to 5 MB)
  <input type=file name=file required accept='.pdf,.txt,.jpg,.jpeg,.png,application/pdf,text/plain,image/jpeg,image/png'></label>
  <button>Upload</button></form>
{% if files %}<table><thead><tr><th>Filename</th><th>Owner</th><th>Size</th><th>Type</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>
{% for f in files %}<tr><td>{{ f['original_filename'] }}</td><td>{{ f['owner_id'] }}</td><td>{{ f['file_size'] }} bytes</td>
<td>{{ f['mime_type'] }}</td><td>{{ f['upload_date'] }}</td><td>
<a href='{{ url_for(endpoint + ".download", file_id=f["file_id"]) }}'>Download</a>
<form style='display:inline' method=post action='{{ url_for(endpoint + ".rename", file_id=f["file_id"]) }}'>
<label>New filename <input name=filename required></label><button>Rename</button></form>
<form style='display:inline' method=post action='{{ url_for(endpoint + ".delete", file_id=f["file_id"]) }}'>
<button>Delete</button></form></td></tr>{% endfor %}</tbody></table>
{% else %}<p>No files have been uploaded.</p>{% endif %}</html>"""


def _default_user_id():
    """Use Flask-Login when installed; other apps should pass a provider."""
    try:
        from flask_login import current_user
        return current_user.get_id() if current_user.is_authenticated else None
    except (ImportError, AttributeError):
        return None


def create_file_blueprint(*, database_path: str | os.PathLike,
                          storage_dir: str | os.PathLike,
                          key_file: str | os.PathLike,
                          public_dir: str | os.PathLike | None = None,
                          user_id_provider: Callable = _default_user_id,
                          permission_checker: Callable | None = None,
                          activity_logger: Callable | None = None,
                          name: str = "secure_files",
                          url_prefix: str = "/files") -> Blueprint:
    """Create file routes.

    Permission checker signature: ``(user_id, file_id, action)`` where action
    is ``read``, ``write``, or ``delete``. It must authorize owners and any
    permitted shared access. Logger signature: ``(user_id, action, file_id)``.
    """
    db_path = Path(database_path).resolve()
    root = Path(storage_dir).resolve()
    key_path = Path(key_file).resolve()
    source_dir = Path(__file__).resolve().parent
    public_root = Path(public_dir).resolve() if public_dir else (source_dir / "static").resolve()
    if permission_checker is None:
        raise ValueError("A permission_checker from the authorization module is required")
    if any(p == public_root or public_root in p.parents for p in (root, key_path, db_path)):
        raise ValueError("File data and encryption key must be outside the public directory")
    root.mkdir(parents=True, exist_ok=True)

    def connect():
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("""CREATE TABLE IF NOT EXISTS secure_files (
            file_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
            original_filename TEXT NOT NULL, stored_filename TEXT NOT NULL UNIQUE,
            file_extension TEXT NOT NULL, mime_type TEXT NOT NULL,
            file_size INTEGER NOT NULL, upload_date TEXT NOT NULL,
            checksum TEXT NOT NULL, encryption_nonce BLOB NOT NULL,
            storage_status TEXT NOT NULL DEFAULT 'stored')""")
        # Add fields when upgrading the earlier module version in this workspace.
        columns = {row["name"] for row in con.execute("PRAGMA table_info(secure_files)")}
        additions = {
            "file_id": "TEXT", "owner_id": "TEXT", "original_filename": "TEXT",
            "stored_filename": "TEXT", "file_extension": "TEXT", "mime_type": "TEXT",
            "file_size": "INTEGER", "upload_date": "TEXT", "checksum": "TEXT",
            "encryption_nonce": "BLOB", "storage_status": "TEXT NOT NULL DEFAULT 'stored'",
        }
        for column, declaration in additions.items():
            if column not in columns:
                con.execute(f"ALTER TABLE secure_files ADD COLUMN {column} {declaration}")
        con.commit()
        return con

    def emit(uid, action, file_id=None, outcome="success"):
        current_app.logger.info("file_event user=%s action=%s file=%s outcome=%s", uid, action, file_id, outcome)
        if activity_logger:
            try:
                activity_logger(uid, action if outcome == "success" else f"{action}_{outcome}", file_id)
            except Exception:
                current_app.logger.exception("Activity logger failed")

    def authenticated_user():
        try:
            value = user_id_provider()
        except Exception:
            current_app.logger.exception("Could not identify authenticated user")
            value = None
        if value is None:
            abort(401, "Please sign in to access files.")
        return str(value)

    def parse_id(file_id):
        try:
            return str(uuid.UUID(file_id))
        except (ValueError, TypeError, AttributeError):
            abort(404, "File not found.")

    def permitted(uid, file_id, action):
        file_id = parse_id(file_id)
        try:
            allowed = bool(permission_checker(uid, file_id, action))
        except Exception:
            current_app.logger.exception("Permission check failed")
            allowed = False
        if not allowed:
            emit(uid, action, file_id, "denied")
            abort(403, "You do not have permission to access this file.")
        return file_id

    def get_record(file_id):
        con = connect()
        try:
            return con.execute("SELECT * FROM secure_files WHERE file_id=? AND storage_status='stored'", (file_id,)).fetchone()
        finally:
            con.close()

    def redirect_message(message):
        return redirect(url_for(f"{name}.index", message=message))

    bp = Blueprint(name, __name__, url_prefix=url_prefix)

    @bp.get("/")
    def index():
        uid = authenticated_user()
        con = connect()
        try:
            files = con.execute("""SELECT file_id,owner_id,original_filename,file_size,mime_type,upload_date
                FROM secure_files WHERE owner_id=? AND storage_status='stored' ORDER BY upload_date DESC""", (uid,)).fetchall()
        finally:
            con.close()
        return render_template_string(_PAGE, files=files, message=request.args.get("message", ""), endpoint=name)

    @bp.post("/upload")
    def upload():
        uid = authenticated_user()
        # Bound multipart parsing too, before Flask reads uploaded fields into memory/temp files.
        request.max_content_length = MAX_UPLOAD_BYTES + 64 * 1024
        file_id = None
        stored_path = None
        phase = "validation"
        try:
            incoming = request.files.get("file")
            if incoming is None or not incoming.filename:
                raise FileValidationError("Choose a file to upload.")
            data = incoming.stream.read(MAX_UPLOAD_BYTES + 1)
            display_name, mime_type = validate_upload(incoming.filename, incoming.mimetype, data)
            extension = Path(display_name).suffix.lower()
            file_id = str(uuid.uuid4())
            stored_name = f"{uuid.uuid4()}.enc"
            stored_path = root / stored_name
            phase = "encryption"
            key = load_encryption_key(key_path)
            nonce, ciphertext = encrypt_file(data, key, file_id.encode("ascii"))
            # Write a temporary ciphertext file and atomically publish it.
            fd, temporary = tempfile.mkstemp(dir=root, prefix=".upload-")
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Hard-linking publishes atomically and fails if a UUID already exists.
                os.link(temporary, stored_path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            con = connect()
            try:
                uploaded_at = datetime.now(timezone.utc).isoformat()
                checksum = calculate_checksum(data)
                values = {
                    "file_id": file_id, "owner_id": uid, "original_filename": display_name,
                    "stored_filename": stored_name, "file_extension": extension,
                    "mime_type": mime_type, "file_size": len(data), "upload_date": uploaded_at,
                    "checksum": checksum, "encryption_nonce": nonce, "storage_status": "stored",
                    # Keep columns from the earlier module version populated during a transition.
                    "id": file_id, "original_name": display_name, "size": len(data),
                    "uploaded_at": uploaded_at, "sha256": checksum, "stored_name": stored_name,
                }
                columns = {row["name"] for row in con.execute("PRAGMA table_info(secure_files)")}
                insert_columns = [column for column in values if column in columns]
                placeholders = ",".join("?" for _ in insert_columns)
                column_sql = ",".join(insert_columns)  # Fixed names only, never user input.
                con.execute(f"INSERT INTO secure_files ({column_sql}) VALUES ({placeholders})",
                            tuple(values[column] for column in insert_columns))
                con.commit()
            finally:
                con.close()
        except FileValidationError as exc:
            emit(uid, "upload", file_id, "failed")
            abort(400 if "exceed" not in str(exc) else 413, str(exc))
        except HTTPException:
            emit(uid, "upload", file_id, "failed")
            raise
        except Exception:
            if stored_path:
                try:
                    stored_path.unlink(missing_ok=True)
                except OSError:
                    current_app.logger.exception("Failed to clean up incomplete upload")
            if phase == "encryption":
                emit(uid, "encryption", file_id, "failed")
            emit(uid, "upload", file_id, "failed")
            current_app.logger.exception("Secure file upload failed")
            abort(500, "The file could not be stored securely.")
        emit(uid, "upload", file_id)
        return redirect_message("File uploaded.")

    @bp.get("/<file_id>/download")
    def download(file_id):
        uid = authenticated_user()
        file_id = permitted(uid, file_id, "read")
        record = get_record(file_id)
        if record is None:
            emit(uid, "download", file_id, "failed")
            abort(404, "File not found.")
        path = root / record["stored_filename"]
        try:
            # Keep paths rooted at the storage folder even if metadata is altered.
            if path.parent != root or not path.name.endswith(".enc"):
                raise FileCryptoError("Invalid private storage reference")
            ciphertext = path.read_bytes()
            key = load_encryption_key(key_path)
            plaintext = decrypt_file(ciphertext, record["encryption_nonce"], key, file_id.encode("ascii"))
        except FileNotFoundError:
            emit(uid, "download", file_id, "failed")
            abort(404, "File not found.")
        except HTTPException:
            raise
        except Exception:
            current_app.logger.exception("File decryption or integrity verification failed")
            emit(uid, "decryption", file_id, "failed")
            abort(409, "File is unavailable or failed integrity verification.")
        if not verify_checksum(plaintext, record["checksum"]):
            emit(uid, "download", file_id, "integrity_failed")
            abort(409, "File integrity verification failed.")
        emit(uid, "download", file_id)
        response = make_response(send_file(io.BytesIO(plaintext), mimetype=record["mime_type"],
                                           as_attachment=True, download_name=record["original_filename"]))
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @bp.post("/<file_id>/rename")
    def rename(file_id):
        uid = authenticated_user()
        file_id = permitted(uid, file_id, "write")
        record = get_record(file_id)
        if record is None:
            emit(uid, "rename", file_id, "failed")
            abort(404, "File not found.")
        try:
            filename = validate_renamed_filename(request.form.get("filename", ""), record["file_extension"])
        except FileValidationError as exc:
            emit(uid, "rename", file_id, "failed")
            abort(400, str(exc))
        con = connect()
        try:
            columns = {row["name"] for row in con.execute("PRAGMA table_info(secure_files)")}
            if "original_name" in columns:
                con.execute("UPDATE secure_files SET original_filename=?, original_name=? WHERE file_id=? AND storage_status='stored'", (filename, filename, file_id))
            else:
                con.execute("UPDATE secure_files SET original_filename=? WHERE file_id=? AND storage_status='stored'", (filename, file_id))
            con.commit()
        except Exception:
            current_app.logger.exception("File metadata rename failed")
            emit(uid, "rename", file_id, "failed")
            abort(500, "The filename could not be updated.")
        finally:
            con.close()
        emit(uid, "rename", file_id)
        return redirect_message("Filename updated.")

    @bp.post("/<file_id>/delete")
    def delete(file_id):
        uid = authenticated_user()
        file_id = permitted(uid, file_id, "delete")
        record = get_record(file_id)
        if record is None:
            emit(uid, "delete", file_id, "failed")
            abort(404, "File not found.")
        # Mark first so the file cannot be downloaded while deletion is in progress.
        con = connect()
        try:
            con.execute("UPDATE secure_files SET storage_status='deleting' WHERE file_id=?", (file_id,))
            con.commit()
        except Exception:
            current_app.logger.exception("Could not mark file for deletion")
            emit(uid, "delete", file_id, "failed")
            abort(500, "The file could not be deleted.")
        finally:
            con.close()
        try:
            (root / record["stored_filename"]).unlink(missing_ok=True)
            con = connect()
            try:
                con.execute("DELETE FROM secure_files WHERE file_id=?", (file_id,))
                con.commit()
            finally:
                con.close()
        except Exception:
            current_app.logger.exception("File deletion did not complete")
            emit(uid, "delete", file_id, "failed")
            abort(500, "The file could not be deleted.")
        emit(uid, "delete", file_id)
        return redirect_message("File deleted.")

    return bp
