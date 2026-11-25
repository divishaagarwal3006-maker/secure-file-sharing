import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def validate_username(name):
    return bool(USERNAME_RE.match(name or ""))


def validate_password(pw):
    return (len(pw) >= 12 and any(c.islower() for c in pw)
            and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw))


def validate_email(email):
    return bool(EMAIL_RE.fullmatch(email or ""))
