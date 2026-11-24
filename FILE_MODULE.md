# Secure file module

The workspace had no existing application, shared database schema, authentication implementation, or Member 2/4 modules when this feature was inspected. These files provide an integration-ready Flask blueprint with explicit hooks rather than replacing missing team code.

## Register it with the app

Install the dependencies in `requirements.txt`, then register the blueprint in the existing Flask app:

```python
from pathlib import Path
from secure_file_manager import create_file_blueprint

app.register_blueprint(create_file_blueprint(
    database_path=app.config["DATABASE"],
    storage_dir=Path(app.instance_path) / "private_uploads",
    key_file=Path(app.instance_path) / "file-encryption.key",
    public_dir=app.static_folder,
    user_id_provider=lambda: current_user.get_id(),
    permission_checker=member2_can_access_file,
    activity_logger=member4_log_activity,  # optional
))
```

Replace the sample function names with the actual team interfaces. The user provider must return the authenticated user's ID or `None`. By default, Flask-Login is used if installed. The permission checker is required and accepts `(user_id, file_id, action)`, where action is `read`, `write`, or `delete`; it must check current access (including owners and valid shares) each time. The logger is optional and accepts `(user_id, action, file_id)`. Denials and failures are sent with a suffix such as `_denied`, `_failed`, or `_integrity_failed`.

The module creates the `secure_files` table in the configured SQLite database. The table stores UUID, owner, original and stored names, extension, MIME type, size, upload timestamp, checksum, nonce, and storage status. If Member 4 already has a shared metadata table, adapt the small database functions in `secure_file_manager.py` to that schema rather than creating a duplicate table.

## Security behavior

- `/files/` lists the current user's files; upload and management controls are included.
- Upload accepts PDF, TXT, JPG, and PNG only. The server checks the filename extension, declared MIME type, file signature/content, non-empty data, and 5 MiB limit.
- Each file is encrypted with AES-256-GCM using a new 96-bit nonce. Ciphertext is stored under a random UUID name, and the nonce and SHA-256 digest are stored in metadata.
- The key is read from the base64-encoded `SECURE_FILE_ENCRYPTION_KEY` environment variable or generated in `key_file` on first use. Keep the key and encrypted storage outside the public directory, restrict filesystem access, and include the key in secure backups. Losing the key makes stored files unrecoverable.
- Downloads re-check authorization, authenticate/decrypt the ciphertext, verify the SHA-256 digest, and only then return the plaintext as a no-cache attachment with its original filename.
- Rename and delete require `write` and `delete` authorization respectively. UUIDs are parsed before use and storage paths are checked against the private root.
- Plaintext is held only while processing a request and in the authorized download response; no plaintext file is written to storage.

## Run the tests

```shell
python -m unittest discover -s tests -v
```
