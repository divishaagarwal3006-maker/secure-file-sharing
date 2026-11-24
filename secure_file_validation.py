"""Server-side filename, size, MIME, and file-content validation."""
from pathlib import Path
from werkzeug.utils import secure_filename

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_MIME_TYPES = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
}


class FileValidationError(ValueError):
    """Raised when an upload or new display name is invalid."""


def sanitize_filename(filename: str) -> str:
    """Return a safe display name, rejecting empty or path-like names."""
    if not isinstance(filename, str) or not filename.strip():
        raise FileValidationError("A filename is required.")
    # Disallow supplied directory components before sanitization.
    if "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise FileValidationError("The filename is invalid.")
    cleaned = secure_filename(filename.strip())
    if not cleaned or cleaned in {".", ".."}:
        raise FileValidationError("The filename is invalid.")
    return cleaned


def validate_upload(filename: str, declared_mime: str, data: bytes) -> tuple[str, str]:
    """Validate extension, declared MIME, size, and content signature."""
    display_name = sanitize_filename(filename)
    extension = Path(display_name).suffix.lower()
    expected_mime = ALLOWED_MIME_TYPES.get(extension)
    if not expected_mime:
        raise FileValidationError("Allowed file types are PDF, TXT, JPG, and PNG.")
    if not data:
        raise FileValidationError("Empty files cannot be uploaded.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise FileValidationError("File must not exceed 5 MB.")
    if (declared_mime or "").split(";", 1)[0].strip().lower() != expected_mime:
        raise FileValidationError("The file MIME type does not match its extension.")

    valid_signature = False
    if extension == ".pdf":
        valid_signature = data.startswith(b"%PDF-")
    elif extension in {".jpg", ".jpeg"}:
        valid_signature = data.startswith(b"\xff\xd8\xff")
    elif extension == ".png":
        valid_signature = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif extension == ".txt":
        try:
            text = data.decode("utf-8")
            valid_signature = "\x00" not in text
        except UnicodeDecodeError:
            valid_signature = False
    if not valid_signature:
        raise FileValidationError("The file content does not match its type.")
    return display_name, expected_mime


def validate_renamed_filename(filename: str, original_extension: str) -> str:
    display_name = sanitize_filename(filename)
    if Path(display_name).suffix.lower() != original_extension.lower():
        raise FileValidationError("Keep the file's original extension when renaming.")
    return display_name
