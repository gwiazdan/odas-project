"""Session management - Redis-backed session store (no in-memory fallback)."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.core.logger import logger

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


redis_client: redis.Redis | None = None


@dataclass
class SessionData:
    """Server-side session data."""

    user_id: int
    csrf_token: str
    created_at: datetime
    last_activity: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "user_id": self.user_id,
            "csrf_token": self.csrf_token,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }

    @staticmethod
    def from_dict(data: dict) -> SessionData:
        """Create from dictionary."""
        return SessionData(
            user_id=data["user_id"],
            csrf_token=data["csrf_token"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
        )

    def is_expired(self) -> bool:
        """Check if session has expired."""
        expiry_time = self.created_at + timedelta(
            minutes=settings.SESSION_TIMEOUT_MINUTES
        )
        return datetime.now(timezone.utc) > expiry_time

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)


def _get_redis_client() -> redis.Redis:
    """
    Lazy initialization of Redis client.
    Each worker process will initialize on first use.
    """
    global redis_client

    if redis_client is not None:
        return redis_client

    if not REDIS_AVAILABLE:
        raise RuntimeError("Redis library is not installed; cannot manage sessions")

    last_error = None
    for attempt in range(1, 6):
        try:
            client = redis.from_url(settings.REDIS_URL, decode_responses=True)
            client.ping()
            redis_client = client
            logger.info(
                f"Connected to Redis for session management (attempt {attempt})"
            )
            return redis_client
        except Exception as exc:
            last_error = exc
            logger.warning(
                f"Redis connection attempt {attempt}/5 failed",
                extra={"error": str(exc)},
            )
            if attempt < 5:
                time.sleep(2.0)

    # All retries failed
    logger.critical(
        "Could not connect to Redis after 5 attempts",
        extra={"redis_url": settings.REDIS_URL, "error": str(last_error)},
    )
    raise RuntimeError(f"Redis connection failed: {last_error}")


def init_redis() -> None:
    """
    Initialize Redis connection with retry logic.
    """
    _get_redis_client()


def create_session(
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str]:
    """
    Create a new session and return session ID and CSRF token.

    Args:
        user_id: User ID
        ip_address: Client IP address
        user_agent: Client User-Agent header

    Returns:
        Tuple of (session_id, csrf_token)
    """
    client = _get_redis_client()

    session_id = secrets.token_urlsafe(settings.SESSION_ID_LENGTH)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)

    session_data = SessionData(
        user_id=user_id,
        csrf_token=csrf_token,
        created_at=now,
        last_activity=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    ttl_seconds = settings.SESSION_TIMEOUT_MINUTES * 60
    client.setex(
        settings.REDIS_SESSION_PREFIX + session_id,
        ttl_seconds,
        json.dumps(session_data.to_dict()),
    )

    return session_id, csrf_token


def get_session(session_id: str) -> SessionData | None:
    """
    Get session data by session ID.

    Returns:
        SessionData if valid and not expired, None otherwise
    """
    client = _get_redis_client()
    key = settings.REDIS_SESSION_PREFIX + session_id

    data = client.get(key)

    if data is None:
        return None

    session_data = SessionData.from_dict(json.loads(data))

    if session_data.is_expired():
        delete_session(session_id)
        return None

    session_data.update_activity()
    ttl_seconds = settings.SESSION_TIMEOUT_MINUTES * 60
    client.setex(
        key,
        ttl_seconds,
        json.dumps(session_data.to_dict()),
    )

    return session_data


def delete_session(session_id: str) -> bool:
    """
    Delete a session.

    Returns:
        True if session was deleted, False if not found
    """
    client = _get_redis_client()
    key = settings.REDIS_SESSION_PREFIX + session_id
    deleted = client.delete(key)
    return deleted > 0
