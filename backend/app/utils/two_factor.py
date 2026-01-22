import hashlib
import json
import secrets
import time

import pyotp
from sqlmodel import Session

from app.core.config import settings
from app.models.user import User

_pending_login_tokens: dict[str, tuple[int, float]] = {}


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def generate_backup_codes(count: int) -> tuple[list[str], list[str]]:
    """Generate backup codes and their hashes."""
    plain: list[str] = []
    hashed: list[str] = []
    for _ in range(count):
        code = secrets.token_urlsafe(8)
        plain.append(code)
        hashed.append(_hash_code(code))
    return plain, hashed


def _load_backup_codes(user: User) -> list[str]:
    if not user.backup_codes:
        return []
    try:
        codes = json.loads(user.backup_codes)
        return codes if isinstance(codes, list) else []
    except json.JSONDecodeError:
        return []


def save_backup_codes(user: User, hashed_codes: list[str]) -> None:
    user.backup_codes = json.dumps(hashed_codes)


def consume_backup_code(user: User, code: str, db_session: Session) -> bool:
    hashed = _hash_code(code)
    codes = _load_backup_codes(user)
    if hashed not in codes:
        return False
    codes.remove(hashed)
    save_backup_codes(user, codes)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return True


def verify_totp_code(secret: str | None, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(
            secret,
            interval=settings.TOTP_PERIOD,
            digits=settings.TOTP_DIGITS,
        )
        return bool(totp.verify(code, valid_window=1))
    except Exception:
        return False


def _clean_expired_pending_tokens() -> None:
    now = time.time()
    expired = [
        token
        for token, (_, ts) in _pending_login_tokens.items()
        if now - ts > settings.PENDING_LOGIN_TTL_SECONDS
    ]
    for token in expired:
        _pending_login_tokens.pop(token, None)


def pop_pending_token(token: str) -> int | None:
    _clean_expired_pending_tokens()
    data = _pending_login_tokens.pop(token, None)
    if not data:
        return None
    user_id, ts = data
    if time.time() - ts > settings.PENDING_LOGIN_TTL_SECONDS:
        return None
    return user_id


def create_pending_token(user: User, pending_token) -> None:
    _pending_login_tokens[pending_token] = (user.id, time.time())
