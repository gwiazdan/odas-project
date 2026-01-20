"""Session management - Redis-backed session store with in-memory fallback."""

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Redis client - will be initialized in init_redis()
redis_client: redis.Redis | None = None
# In-memory fallback store
_sessions: dict[str, "SessionData"] = {}
USE_REDIS = False

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
        return datetime.now(UTC) > expiry_time

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(UTC)


def init_redis(url: str = "redis://localhost:6379/0") -> None:
    """Initialize Redis connection. Falls back to in-memory if unavailable."""
    global redis_client, USE_REDIS

    if not REDIS_AVAILABLE:
        print("Redis library not installed, using in-memory session store")
        USE_REDIS = False
        return

    try:
        redis_client = redis.from_url(url, decode_responses=True)
        # Test connection
        redis_client.ping()
        USE_REDIS = True
        print("Connected to Redis for session management")
    except Exception as e:
        print(f"Could not connect to Redis ({url}): {e}")
        print("Falling back to in-memory session store")
        redis_client = None
        USE_REDIS = False


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
    session_id = secrets.token_urlsafe(SESSION_ID_LENGTH)
    now = datetime.now(UTC)

    session_data = SessionData(
        user_id=user_id,
        created_at=now,
        last_activity=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if USE_REDIS and redis_client:
        # Store in Redis with TTL
        ttl_seconds = SESSION_TIMEOUT_MINUTES * 60
        redis_client.setex(
            REDIS_SESSION_PREFIX + session_id,
            ttl_seconds,
            json.dumps(session_data.to_dict()),
        )
    else:
        # Use in-memory store
        _sessions[session_id] = session_data

    return session_id


def get_session(session_id: str) -> SessionData | None:
    """
    Get session data by session ID.

    Returns:
        SessionData if valid and not expired, None otherwise
    """
    if USE_REDIS and redis_client:
        data = redis_client.get(REDIS_SESSION_PREFIX + session_id)

        if data is None:
            return None

        session_data = SessionData.from_dict(json.loads(data))

        # Check expiration
        if session_data.is_expired():
            delete_session(session_id)
            return None

        # Update activity and refresh TTL
        session_data.update_activity()
        ttl_seconds = SESSION_TIMEOUT_MINUTES * 60
        redis_client.setex(
            REDIS_SESSION_PREFIX + session_id,
            ttl_seconds,
            json.dumps(session_data.to_dict()),
        )

        return session_data
    else:
        # Use in-memory store
        session = _sessions.get(session_id)

        if session is None:
            return None

        if session.is_expired():
            del _sessions[session_id]
            return None

        session.update_activity()
        return session


def delete_session(session_id: str) -> bool:
    """
    Delete a session.

    Returns:
        True if session was deleted, False if not found
    """
    if USE_REDIS and redis_client:
        deleted = redis_client.delete(REDIS_SESSION_PREFIX + session_id)
        return deleted > 0
    else:
        if session_id in _sessions:
            del _sessions[session_id]
            return True
        return False


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions.
    Note: Redis handles automatic expiration via TTL, so this is mostly for manual cleanup.

    Returns:
        Number of sessions deleted
    """
    if USE_REDIS:
        # Redis automatically expires keys via TTL
        return 0
    else:
        # In-memory cleanup
        expired_ids = [
            sid for sid, session in _sessions.items() if session.is_expired()
        ]
        for sid in expired_ids:
            del _sessions[sid]
        return len(expired_ids)
