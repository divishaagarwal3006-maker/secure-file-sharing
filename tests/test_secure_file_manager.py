"""Integration and security tests for the encrypted file routes."""
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask

from secure_file_crypto import (FileCryptoError, calculate_checksum, decrypt_file,
                                encrypt_file, generate_encryption_key, verify_checksum)
from secure_file_manager import create_file_blueprint


class SecureFileManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.db = base / "data" / "files.sqlite3"
        self.storage = base / "private" / "uploads"
        self.key_file = base / "secrets" / "encryption.key"
        self.user = "alice"
        self.grants = set()
        self.events = []
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test-only")
        app.register_blueprint(create_file_blueprint(
            database_path=self.db, storage_dir=self.storage, key_file=self.key_file,
            public_dir=base / "public", user_id_provider=lambda: self.user,
            permission_checker=self._permission, activity_logger=self._log))
        self.client = app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def _permission(self, user_id, file_id, action):
        if (user_id, file_id, action) in self.grants:
            return True
        con = sqlite3.connect(self.db)
        try:
            row = con.execute("SELECT owner_id FROM secure_files WHERE file_id=?", (file_id,)).fetchone()
        finally:
            con.close()
        return bool(row and row[0] == user_id)

    def _log(self, user_id, action, file_id):
        self.events.append((user_id, action, file_id))

    def upload(self, filename="sample.pdf", data=b"%PDF-1.7\nexample", mime="application/pdf"):
        return self.client.post("/files/upload", data={"file": (io.BytesIO(data), filename, mime)},
                                content_type="multipart/form-data", follow_redirects=False)

    def rows(self):
        con = sqlite3.connect(self.db)
        con.row_factory = sqlite3.Row
        try:
            return con.execute("SELECT * FROM secure_files").fetchall()
        finally:
            con.close()

    def test_upload_valid_pdf_txt_and_complete_metadata(self):
        self.assertEqual(self.upload().status_code, 302)
        self.assertEqual(self.upload("notes.txt", b"hello", "text/plain").status_code, 302)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(len(row["file_id"]), 36)
            self.assertNotEqual(row["stored_filename"], row["original_filename"])
            self.assertEqual(len(row["checksum"]), 64)
            self.assertEqual(len(row["encryption_nonce"]), 12)
            self.assertEqual(row["storage_status"], "stored")

    def test_rejects_unsupported_empty_oversized_and_misleading_uploads(self):
        self.assertIn(self.upload("run.exe", b"MZ", "application/octet-stream").status_code, (400, 413))
        self.assertIn(self.upload("empty.txt", b"", "text/plain").status_code, (400, 413))
        self.assertEqual(self.upload("large.txt", b"a" * (5 * 1024 * 1024 + 1), "text/plain").status_code, 413)
        self.assertEqual(self.upload("fake.pdf", b"hello", "application/pdf").status_code, 400)

    def test_rejects_mime_mismatch_and_invalid_text(self):
        self.assertEqual(self.upload("fake.pdf", b"%PDF-1.5", "text/plain").status_code, 400)
        self.assertEqual(self.upload("binary.txt", b"\xff\xfe", "text/plain").status_code, 400)

    def test_accepts_jpg_and_png_signatures(self):
        self.assertEqual(self.upload("photo.jpg", b"\xff\xd8\xffdata", "image/jpeg").status_code, 302)
        self.assertEqual(self.upload("image.png", b"\x89PNG\r\n\x1a\ndata", "image/png").status_code, 302)

    def test_duplicate_original_names_get_unique_storage_names(self):
        self.upload()
        self.upload()
        rows = self.rows()
        self.assertEqual(rows[0]["original_filename"], rows[1]["original_filename"])
        self.assertNotEqual(rows[0]["stored_filename"], rows[1]["stored_filename"])

    def test_authorized_download_returns_original_filename(self):
        self.upload("document.pdf")
        row = self.rows()[0]
        response = self.client.get(f"/files/{row['file_id']}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"%PDF-1.7\nexample")
        self.assertIn("document.pdf", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_authorized_shared_user_can_download_after_permission_check(self):
        self.upload()
        row = self.rows()[0]
        self.user = "bob"
        self.grants.add(("bob", row["file_id"], "read"))
        response = self.client.get(f"/files/{row['file_id']}/download")
        self.assertEqual(response.status_code, 200)

    def test_other_user_without_permission_cannot_download(self):
        self.upload()
        row = self.rows()[0]
        self.user = "mallory"
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 403)
        self.assertIn(("mallory", "read_denied", row["file_id"]), self.events)

    def test_rename_requires_write_permission_and_keeps_storage_uuid(self):
        self.upload("document.pdf")
        row = self.rows()[0]
        self.assertEqual(self.client.post(f"/files/{row['file_id']}/rename", data={"filename": "renamed.pdf"}).status_code, 302)
        changed = self.rows()[0]
        self.assertEqual(changed["original_filename"], "renamed.pdf")
        self.assertEqual(changed["stored_filename"], row["stored_filename"])
        self.user = "bob"
        self.assertEqual(self.client.post(f"/files/{row['file_id']}/rename", data={"filename": "no.pdf"}).status_code, 403)

    def test_rename_rejects_path_and_extension_changes(self):
        self.upload("document.pdf")
        file_id = self.rows()[0]["file_id"]
        self.assertEqual(self.client.post(f"/files/{file_id}/rename", data={"filename": "../other.pdf"}).status_code, 400)
        self.assertEqual(self.client.post(f"/files/{file_id}/rename", data={"filename": "other.txt"}).status_code, 400)

    def test_delete_removes_encrypted_data_and_metadata(self):
        self.upload()
        row = self.rows()[0]
        stored = self.storage / row["stored_filename"]
        self.assertTrue(stored.exists())
        self.assertEqual(self.client.post(f"/files/{row['file_id']}/delete").status_code, 302)
        self.assertFalse(stored.exists())
        self.assertEqual(self.rows(), [])

    def test_delete_requires_permission(self):
        self.upload()
        row = self.rows()[0]
        self.user = "bob"
        self.assertEqual(self.client.post(f"/files/{row['file_id']}/delete").status_code, 403)
        self.assertTrue((self.storage / row["stored_filename"]).exists())

    def test_ciphertext_is_not_plaintext_and_tampering_is_rejected(self):
        self.upload()
        row = self.rows()[0]
        path = self.storage / row["stored_filename"]
        ciphertext = path.read_bytes()
        self.assertNotIn(b"%PDF-1.7", ciphertext)
        damaged = bytearray(ciphertext)
        damaged[-1] ^= 1
        path.write_bytes(damaged)
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 409)
        self.assertIn(("alice", "decryption_failed", row["file_id"]), self.events)

    def test_checksum_mismatch_is_rejected_after_decryption(self):
        self.upload()
        row = self.rows()[0]
        con = sqlite3.connect(self.db)
        try:
            con.execute("UPDATE secure_files SET checksum=? WHERE file_id=?", ("0" * 64, row["file_id"]))
            con.commit()
        finally:
            con.close()
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 409)

    def test_invalid_uuid_and_path_traversal_are_not_accessible(self):
        self.assertEqual(self.client.get("/files/../../secret/download").status_code, 404)
        self.assertEqual(self.client.get("/files/not-a-uuid/download").status_code, 404)

    def test_revoked_permission_blocks_later_download(self):
        self.upload()
        row = self.rows()[0]
        self.user = "bob"
        self.grants.add(("bob", row["file_id"], "read"))
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 200)
        self.grants.clear()
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 403)

    def test_dashboard_shows_metadata_and_empty_state(self):
        self.assertIn(b"No files have been uploaded", self.client.get("/files/").data)
        self.upload("notes.txt", b"hello", "text/plain")
        page = self.client.get("/files/").data
        self.assertIn(b"notes.txt", page)
        self.assertIn(b"text/plain", page)
        self.assertIn(b"alice", page)

    def test_authentication_is_required(self):
        self.user = None
        self.assertEqual(self.client.get("/files/").status_code, 401)

    def test_earlier_module_schema_is_upgraded_without_losing_compatibility(self):
        self.db.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.db)
        try:
            con.execute("""CREATE TABLE secure_files (
                id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, original_name TEXT NOT NULL,
                size INTEGER NOT NULL, mime_type TEXT NOT NULL, uploaded_at TEXT NOT NULL,
                sha256 TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE)""")
            con.commit()
        finally:
            con.close()
        self.assertEqual(self.upload("document.pdf").status_code, 302)
        con = sqlite3.connect(self.db)
        try:
            legacy = con.execute("SELECT id,original_name,stored_name FROM secure_files").fetchone()
        finally:
            con.close()
        self.assertEqual(legacy[1], "document.pdf")
        self.assertTrue((self.storage / legacy[2]).exists())

    def test_missing_ciphertext_is_reported_without_plaintext(self):
        self.upload()
        row = self.rows()[0]
        (self.storage / row["stored_filename"]).unlink()
        self.assertEqual(self.client.get(f"/files/{row['file_id']}/download").status_code, 404)

    def test_crypto_helpers_authenticate_and_verify_checksum(self):
        key = generate_encryption_key()
        nonce, ciphertext = encrypt_file(b"secret", key, b"file-id")
        self.assertEqual(decrypt_file(ciphertext, nonce, key, b"file-id"), b"secret")
        with self.assertRaises(FileCryptoError):
            decrypt_file(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), nonce, key, b"file-id")
        self.assertTrue(verify_checksum(b"secret", calculate_checksum(b"secret")))
        self.assertFalse(verify_checksum(b"altered", "0" * 64))


if __name__ == "__main__":
    unittest.main()
