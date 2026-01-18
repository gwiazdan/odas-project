"""Rate limiting and security utilities."""

import re
import time
from collections import defaultdict
from datetime import datetime, timezone

login_attempts: dict[str, list[float]] = defaultdict(list)


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

    # Limit file size - 25 MB
    MAX_FILE_SIZE = 25 * 1024 * 1024
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
    """Simple rate limiter for authentication attempts."""

    @staticmethod
    def is_rate_limited(
        identifier: str,
        max_attempts: int = 5,
        window_seconds: int = 300,  # 5 minutes
    ) -> bool:
        """Check if identifier has exceeded rate limit."""
        now = time.time()

        login_attempts[identifier] = [
            attempt_time
            for attempt_time in login_attempts[identifier]
            if now - attempt_time < window_seconds
        ]

        if len(login_attempts[identifier]) >= max_attempts:
            return True
        return False

    @staticmethod
    def record_attempt(identifier: str) -> None:
        """Record a login attempt."""
        login_attempts[identifier].append(time.time())

    @staticmethod
    def get_remaining_attempts(
        identifier: str,
        max_attempts: int = 5,
        window_seconds: int = 300,
    ) -> int:
        """Get remaining attempts before rate limit."""
        now = time.time()
        login_attempts[identifier] = [
            attempt_time
            for attempt_time in login_attempts[identifier]
            if now - attempt_time < window_seconds
        ]
        return max(0, max_attempts - len(login_attempts[identifier]))

    @staticmethod
    def get_reset_time(
        identifier: str,
        window_seconds: int = 300,
    ) -> datetime | None:
        """Get when rate limit will reset."""
        if not login_attempts[identifier]:
            return None
        oldest_attempt = min(login_attempts[identifier])
        reset_time = datetime.fromtimestamp(
            oldest_attempt + window_seconds, tz=timezone.utc
        )
        return reset_time
