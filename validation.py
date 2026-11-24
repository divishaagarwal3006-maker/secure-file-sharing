
import re

def validate_filename(filename):

    if not filename or not filename.strip():
        return False

    if len(filename) > 255:
        return False

    if "/" in filename or "\\" in filename:
        return False

    if filename in (".", ".."):
        return False

    return True


def validate_file_id(file_id):

    try:
        return int(file_id) > 0
    except (ValueError, TypeError):
        return False
