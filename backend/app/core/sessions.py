"""Session management - Redis-backed session store (no in-memory fallback)."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.logger import logger

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


redis_client: redis.Redis | None = None

SESSION_TIMEOUT_MINUTES = 60 * 24  # 24 hours
SESSION_ID_LENGTH = 32
REDIS_SESSION_PREFIX = "session:"


@dataclass
class SessionData:
    """Server-side session data."""

    user_id: int
    created_at: datetime
    last_activity: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }

    @staticmethod
    def from_dict(data: dict) -> "SessionData":
        """Create from dictionary."""
        return SessionData(
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
        )

    def is_expired(self) -> bool:
        """Check if session has expired."""
        expiry_time = self.created_at + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        return datetime.now(timezone.utc) > expiry_time

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)


def init_redis(url: str = "redis://localhost:6379/0") -> None:
    """Initialize Redis connection. App fails to start if Redis is unavailable."""
    global redis_client

    if not REDIS_AVAILABLE:
        raise RuntimeError("Redis library is not installed; cannot manage sessions")

    try:
        redis_client = redis.from_url(url, decode_responses=True)
        redis_client.ping()
        logger.info("Connected to Redis for session management")
    except Exception as exc:
        redis_client = None
        logger.critical(
            "Could not connect to Redis", extra={"redis_url": url, "error": str(exc)}
        )
        raise


def create_session(
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> str:
    """
    Create a new session and return session ID.

    Args:
        user_id: User ID
        ip_address: Client IP address
        user_agent: Client User-Agent header

    Returns:
        Session ID (to be stored in httpOnly cookie)
    """
    if not redis_client:
        raise RuntimeError("Redis is not initialized; sessions cannot be created")

    session_id = secrets.token_urlsafe(SESSION_ID_LENGTH)
    now = datetime.now(timezone.utc)

    session_data = SessionData(
        user_id=user_id,
        created_at=now,
        last_activity=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    ttl_seconds = SESSION_TIMEOUT_MINUTES * 60
    redis_client.setex(
        REDIS_SESSION_PREFIX + session_id,
        ttl_seconds,
        json.dumps(session_data.to_dict()),
    )

    return session_id


def get_session(session_id: str) -> SessionData | None:
    """
    Get session data by session ID.

    Returns:
        SessionData if valid and not expired, None otherwise
    """
    if not redis_client:
        raise RuntimeError("Redis is not initialized; sessions cannot be read")

    data = redis_client.get(REDIS_SESSION_PREFIX + session_id)

    if data is None:
        return None

    session_data = SessionData.from_dict(json.loads(data))

    if session_data.is_expired():
        delete_session(session_id)
        return None

    session_data.update_activity()
    ttl_seconds = SESSION_TIMEOUT_MINUTES * 60
    redis_client.setex(
        REDIS_SESSION_PREFIX + session_id,
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
    if not redis_client:
        raise RuntimeError("Redis is not initialized; sessions cannot be deleted")

    deleted = redis_client.delete(REDIS_SESSION_PREFIX + session_id)
    return deleted > 0


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions.
    Note: Redis handles automatic expiration via TTL, so this is mostly for manual cleanup.

    Returns:
        Number of sessions deleted
    """
    # Redis automatically expires keys via TTL
    return 0
