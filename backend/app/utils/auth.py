from fastapi import HTTPException, status
from zxcvbn import zxcvbn

from app.core.config import settings


def validate_password_strength(
    password: str,
) -> None:
    """Validate password strength using zxcvbn, mirroring frontend rules."""
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required",
        )

    if (
        len(password) < settings.MIN_PASSWORD_LENGTH
        or len(password) > settings.MAX_PASSWORD_LENGTH
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be 8-128 characters",
        )

    requirements = {
        "uppercase letter": any(c.isupper() for c in password),
        "lowercase letter": any(c.islower() for c in password),
        "digit": any(c.isdigit() for c in password),
        "special character": any(
            c in r"!@#$%^&*()_+-=[]{};:'\",.<>?/\\|`~" for c in password
        ),
    }

    missing = [label for label, ok in requirements.items() if not ok]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must contain: {', '.join(missing)}",
        )

    analysis = zxcvbn(password)
    score = analysis.get("score", 0)
    if score <= 3:  # zxcvbn score 0-4; require 4 like frontend (score>3)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is too weak. Use a longer passphrase with mixed characters.",
        )


def validate_email_format(email: str) -> str:
    """Validate email format and return normalized email."""
    if not email or not email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required",
        )

    email = email.strip().lower()

    if len(email) > 254:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is too long",
        )

    if not settings.EMAIL_REGEX.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format",
        )

    return email


def validate_name(name: str, field_name: str = "Name") -> str:
    """Validate name format and return normalized name."""
    if not name or not name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} is required",
        )

    name = name.strip()

    if len(name) < 2 or len(name) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be 2-50 characters",
        )

    if not settings.NAME_REGEX.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} contains invalid characters",
        )

    return name
