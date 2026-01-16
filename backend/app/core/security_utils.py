"""Rate limiting and security utilities."""

import time
from collections import defaultdict
from datetime import datetime, timezone

# In-memory store for login attempts (w produkcji: Redis)
login_attempts: dict[str, list[float]] = defaultdict(list)


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
        # Remove old attempts outside the window
        login_attempts[identifier] = [
            attempt_time
            for attempt_time in login_attempts[identifier]
            if now - attempt_time < window_seconds
        ]

        # Check if limit exceeded
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
