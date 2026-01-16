"""Session management - server-side session store."""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# In-memory session store (w produkcji: Redis)
# Format: {session_id: SessionData}
_sessions: dict[str, "SessionData"] = {}

# Session configuration
SESSION_TIMEOUT_MINUTES = 60 * 24  # 24 hours
SESSION_ID_LENGTH = 32


@dataclass
class SessionData:
    """Server-side session data."""

    user_id: int
    created_at: datetime
    last_activity: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    def is_expired(self) -> bool:
        """Check if session has expired."""
        expiry_time = self.created_at + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        return datetime.now(UTC) > expiry_time

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(UTC)


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

    _sessions[session_id] = SessionData(
        user_id=user_id,
        created_at=now,
        last_activity=now,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return session_id


def get_session(session_id: str) -> SessionData | None:
    """
    Get session data by session ID.

    Returns:
        SessionData if valid and not expired, None otherwise
    """
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
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False


def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions.

    Returns:
        Number of sessions deleted
    """
    expired_ids = [sid for sid, session in _sessions.items() if session.is_expired()]
    for sid in expired_ids:
        del _sessions[sid]
    return len(expired_ids)
