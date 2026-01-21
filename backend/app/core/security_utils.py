"""Rate limiting and security utilities."""

import re
from datetime import datetime, timedelta, timezone

from app.core.sessions import _get_redis_client


def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Sanitize string input:
    - Strip whitespace
    - Limit length
    - Remove null bytes and control characters
    - Allow only safe characters
    """
    if not isinstance(value, str):
        return ""

    value = value.replace("\x00", "")

    value = re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]", "", value)

    value = value.strip()

    value = value[:max_length]

    return value


def sanitize_email(email: str) -> str:
    """Sanitize email address."""
    email = sanitize_string(email, max_length=254)
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise ValueError(f"Invalid email format: {email}")
    return email.lower()


def sanitize_filename(filename: str) -> str:
    """Sanitize file names to prevent path traversal attacks."""
    filename = sanitize_string(filename, max_length=255)

    filename = re.sub(r'[/\\:*?"<>|]', "", filename)

    filename = re.sub(r"^\.+", "", filename)
    return filename


def validate_attachment_metadata(attachment: dict) -> bool:
    """
    Validate attachment metadata structure and content.
    Returns True if valid, raises ValueError otherwise.
    """
    required_fields = {"filename", "size", "mimetype", "data_base64"}

    if not isinstance(attachment, dict):
        raise ValueError("Attachment must be a dictionary")

    if not all(field in attachment for field in required_fields):
        raise ValueError(f"Attachment missing required fields: {required_fields}")

    # Validate filename
    if (
        not isinstance(attachment["filename"], str)
        or not attachment["filename"].strip()
    ):
        raise ValueError("Attachment filename must be a non-empty string")

    # Validate size
    if not isinstance(attachment["size"], int) or attachment["size"] <= 0:
        raise ValueError("Attachment size must be a positive integer")

    # Limit file size - 50 MB
    MAX_FILE_SIZE = 50 * 1024 * 1024
    if attachment["size"] > MAX_FILE_SIZE:
        raise ValueError(f"Attachment size exceeds maximum of {MAX_FILE_SIZE} bytes")

    # Validate mimetype
    if not isinstance(attachment["mimetype"], str):
        raise ValueError("Attachment mimetype must be a string")

    # Validate base64 data
    if not isinstance(attachment["data_base64"], str):
        raise ValueError("Attachment data must be base64 encoded string")

    return True


class RateLimiter:
    """Redis-backed rate limiter (no in-memory fallback)."""

    @staticmethod
    def is_rate_limited(
        identifier: str,
        max_attempts: int = 5,
        window_seconds: int = 300,
    ) -> bool:
        """Check if identifier has exceeded rate limit."""
        client = _get_redis_client()
        key = f"ratelimit:{identifier}"
        current = int(client.get(key) or 0)
        return current >= max_attempts

    @staticmethod
    def record_attempt(
        identifier: str,
        window_seconds: int = 300,
    ) -> None:
        """Record a login attempt with TTL matching the window."""
        client = _get_redis_client()
        key = f"ratelimit:{identifier}"
        client.incr(key)
        # Ensure TTL is set for the window
        ttl = client.ttl(key)
        if ttl is None or ttl < 0:
            client.expire(key, window_seconds)

    @staticmethod
    def get_remaining_attempts(
        identifier: str,
        max_attempts: int = 5,
        window_seconds: int = 300,
    ) -> int:
        """Get remaining attempts before rate limit."""
        client = _get_redis_client()
        key = f"ratelimit:{identifier}"
        current = int(client.get(key) or 0)
        return max(0, max_attempts - current)

    @staticmethod
    def get_reset_time(
        identifier: str,
        window_seconds: int = 300,
    ) -> datetime | None:
        """Get when rate limit will reset."""
        client = _get_redis_client()
        key = f"ratelimit:{identifier}"
        ttl = client.ttl(key)
        if ttl is None or ttl < 0:
            return None
        return datetime.now(timezone.utc) + timedelta(seconds=ttl)
