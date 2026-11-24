"""AES-256-GCM and SHA-256 helpers used by the file-management blueprint."""
import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class FileCryptoError(Exception):
    """Raised when encryption, decryption, or integrity verification fails."""


def generate_encryption_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def load_encryption_key(key_file: str | os.PathLike, environment_variable: str = "SECURE_FILE_ENCRYPTION_KEY") -> bytes:
    """Load a base64-encoded 32-byte environment key or create/read a key file."""
    encoded = os.environ.get(environment_variable)
    if encoded:
        try:
            key = base64.urlsafe_b64decode(encoded.strip())
        except Exception as exc:
            raise FileCryptoError("Encryption key is unavailable.") from exc
    else:
        path = Path(key_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            new_key = generate_encryption_key()
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(base64.urlsafe_b64encode(new_key))
            except FileExistsError:
                pass
        try:
            key = base64.urlsafe_b64decode(path.read_bytes().strip())
        except Exception as exc:
            raise FileCryptoError("Encryption key is unavailable.") from exc
    if len(key) != 32:
        raise FileCryptoError("Encryption key is unavailable.")
    return key


def encrypt_file(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    try:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    except Exception as exc:
        raise FileCryptoError("File encryption failed.") from exc


def decrypt_file(ciphertext: bytes, nonce: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except (InvalidTag, ValueError) as exc:
        raise FileCryptoError("Encrypted file authentication failed.") from exc


def calculate_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, expected: str) -> bool:
    return secrets.compare_digest(calculate_checksum(data), expected)
