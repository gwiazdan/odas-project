"""Authentication routes with session store and RSA keypair generation."""

# ENDPOINTS:
# POST   /auth/signup          - User registration with RSA keypair generation
# POST   /auth/login           - User login with session creation
# POST   /auth/logout          - User logout and session deletion
# GET    /auth/me              - Get current authenticated user info
# GET    /auth/users/search    - Search user by email to get public key
# GET    /auth/verify-recipient - Verify recipient existence and get public key

import asyncio
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone

import pyotp
import regex
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select
from zxcvbn import zxcvbn

from app.core.config import settings
from app.core.db import get_session as get_db_session
from app.core.security import (
    encrypt_private_key,
    generate_rsa_keypair,
    get_password_hash,
    verify_password,
)
from app.core.security_utils import RateLimiter
from app.core.sessions import create_session, delete_session, get_session
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["auth"])

EMAIL_REGEX = regex.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
NAME_REGEX = regex.compile(
    r"^[\p{L}\s\'\-\u2013]{2,50}$", regex.UNICODE | regex.IGNORECASE
)
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
PENDING_LOGIN_TTL_SECONDS = 300

_pending_login_tokens: dict[str, tuple[int, float]] = {}


class SignupRequest(BaseModel):
    """Signup request schema."""

    email: str = Field(..., min_length=1, max_length=254)
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    website: str = Field(default="")  # Honeypot field - should always be empty


class SignupResponse(BaseModel):
    """Signup response schema."""

    id: int
    email: str
    first_name: str
    last_name: str
    public_key: str
    encrypted_private_key: str
    pbkdf2_salt: str


class LoginRequest(BaseModel):
    """Login request schema."""

    email: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=500)
    website: str = Field(default="")  # Honeypot field - should always be empty


class LoginResponse(BaseModel):
    """Login response schema."""

    id: int
    email: str
    first_name: str
    last_name: str
    public_key: str
    encrypted_private_key: str  # For client-side decryption with password
    pbkdf2_salt: str  # Salt for PBKDF2 decryption
    is_2fa_enabled: bool = False
    csrf_token: str | None = None


class LogoutResponse(BaseModel):
    """Logout response schema."""

    message: str


class LoginStepOneResponse(BaseModel):
    """Login step-one response indicating whether 2FA is required."""

    requires_2fa: bool
    pending_token: str | None = None
    user: LoginResponse | None = None


class TwoFactorVerifyRequest(BaseModel):
    """Request to finalize login with 2FA code."""

    pending_token: str
    totp_code: str | None = None
    backup_code: str | None = None


class TwoFactorVerifyResponse(LoginResponse):
    """Response after successful 2FA verification."""

    requires_2fa: bool = False


class TwoFactorSetupResponse(BaseModel):
    """Response containing temporary TOTP secret and otpauth URL."""

    temp_secret: str
    otpauth_url: str


class TwoFactorActivateRequest(BaseModel):
    """Request to activate TOTP for the account."""

    temp_secret: str
    totp_code: str


class TwoFactorActivateResponse(BaseModel):
    """Response with plaintext backup codes (display once)."""

    backup_codes: list[str]


class TwoFactorDisableRequest(BaseModel):
    """Request to disable 2FA using TOTP or backup code."""

    totp_code: str | None = None
    backup_code: str | None = None


class TwoFactorStatusResponse(BaseModel):
    """Generic 2FA status response."""

    message: str


def validate_password_strength(
    password: str,
) -> None:
    """Validate password strength using zxcvbn, mirroring frontend rules."""
    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required",
        )

    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
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

    if not EMAIL_REGEX.match(email):
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

    if not NAME_REGEX.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} contains invalid characters",
        )

    return name


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _generate_backup_codes(count: int) -> tuple[list[str], list[str]]:
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


def _save_backup_codes(user: User, hashed_codes: list[str]) -> None:
    user.backup_codes = json.dumps(hashed_codes)


def _consume_backup_code(user: User, code: str, db_session: Session) -> bool:
    hashed = _hash_code(code)
    codes = _load_backup_codes(user)
    if hashed not in codes:
        return False
    codes.remove(hashed)
    _save_backup_codes(user, codes)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return True


def _verify_totp_code(secret: str | None, code: str) -> bool:
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
        if now - ts > PENDING_LOGIN_TTL_SECONDS
    ]
    for token in expired:
        _pending_login_tokens.pop(token, None)


def _pop_pending_token(token: str) -> int | None:
    _clean_expired_pending_tokens()
    data = _pending_login_tokens.pop(token, None)
    if not data:
        return None
    user_id, ts = data
    if time.time() - ts > PENDING_LOGIN_TTL_SECONDS:
        return None
    return user_id


def get_current_user(
    request: Request,
    db_session: Session = Depends(get_db_session),
) -> User:
    """
    Get current authenticated user from session cookie.

    Raises:
        HTTPException: If session is invalid or user not found
    """
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session_data = get_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    user = db_session.get(User, session_data.user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


@router.post(
    "/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED
)
def signup(
    signup_request: SignupRequest,
    db_session: Session = Depends(get_db_session),
) -> User:
    """
    Register a new user with RSA keypair generation.

    Process:
    1. Validate all inputs
    2. Check email uniqueness
    3. Hash password with Argon2id
    4. Generate RSA 4096-bit keypair
    5. Encrypt private key with PBKDF2 + AES-GCM
    6. Store user with encrypted private key
    """
    # Honeypot check - if filled, reject silently
    if signup_request.website:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account",
        )

    # Validate inputs
    email = validate_email_format(signup_request.email)
    first_name = validate_name(signup_request.first_name, "First name")
    last_name = validate_name(signup_request.last_name, "Last name")
    validate_password_strength(signup_request.password)

    # Check email uniqueness
    statement = select(User).where(User.email == email)
    existing_user = db_session.exec(statement).first()
    if existing_user:
        # Generic error to prevent email enumeration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account",
        )

    # Generate RSA keypair
    private_key_pem, public_key_pem = generate_rsa_keypair()

    # Encrypt private key with password
    encrypted_private_key, pbkdf2_salt = encrypt_private_key(
        private_key_pem,
        signup_request.password,
    )

    # Create user
    db_user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        hashed_password=get_password_hash(signup_request.password),
        public_key=public_key_pem,
        encrypted_private_key=encrypted_private_key,
        pbkdf2_salt=pbkdf2_salt,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db_session.add(db_user)
    db_session.commit()
    db_session.refresh(db_user)

    return db_user


@router.post("/login", response_model=LoginStepOneResponse)
async def login(
    login_request: LoginRequest,
    request: Request,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> LoginStepOneResponse:
    """
    Authenticate user and create session.

    Security measures:
    - Rate limiting (5 attempts per 5 minutes)
    - Constant-time password comparison
    - Generic error messages
    - Artificial delay (100-300ms) to slow brute-force
    - HttpOnly Secure session cookie
    """
    # Honeypot check - if filled, reject silently
    if login_request.website:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    email = validate_email_format(login_request.email)

    # Rate limiting check
    if RateLimiter.is_rate_limited(email, max_attempts=5, window_seconds=300):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
        )

    RateLimiter.record_attempt(email)

    # Artificial delay to slow brute-force
    await asyncio.sleep(0.1 + (hash(email) % 200) / 1000)

    # Fetch user
    user = None
    try:
        statement = select(User).where(User.email == email)
        user = db_session.exec(statement).first()
    except Exception:
        pass

    # Verify password
    password_valid = False
    if user:
        password_valid = verify_password(login_request.password, user.hashed_password)

    # Generic error to prevent user enumeration
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account inactive",
        )

    if user.is_2fa_enabled:
        pending_token = secrets.token_urlsafe(32)
        _pending_login_tokens[pending_token] = (user.id, time.time())
        return LoginStepOneResponse(
            requires_2fa=True, pending_token=pending_token, user=None
        )

    session_id, csrf_token = create_session(
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
    )

    return LoginStepOneResponse(
        requires_2fa=False,
        pending_token=None,
        user=LoginResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            public_key=user.public_key,
            encrypted_private_key=user.encrypted_private_key,
            pbkdf2_salt=user.pbkdf2_salt,
            is_2fa_enabled=user.is_2fa_enabled,
            csrf_token=csrf_token,
        ),
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    response: Response,
    _: User = Depends(get_current_user),
) -> LogoutResponse:
    """Log out user and delete session."""
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)

    if session_id:
        delete_session(session_id)

    response.delete_cookie(settings.SESSION_COOKIE_NAME)

    return LogoutResponse(message="Logged out successfully")


@router.post("/login/verify-2fa", response_model=TwoFactorVerifyResponse)
def verify_2fa_login(
    verify_request: TwoFactorVerifyRequest,
    request: Request,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> TwoFactorVerifyResponse:
    """Finalize login by verifying TOTP or backup code and issuing session."""
    user_id = _pop_pending_token(verify_request.pending_token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    user = db_session.get(User, user_id)
    if not user or not user.is_active or not user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    rate_key = f"2fa:{user.email}"
    if RateLimiter.is_rate_limited(rate_key, max_attempts=5, window_seconds=300):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )
    RateLimiter.record_attempt(rate_key)

    verified = False
    if verify_request.backup_code:
        verified = _consume_backup_code(user, verify_request.backup_code, db_session)

    if not verified and verify_request.totp_code:
        verified = _verify_totp_code(user.totp_secret, verify_request.totp_code)

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    session_id, csrf_token = create_session(
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
    )

    return TwoFactorVerifyResponse(
        requires_2fa=False,
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        public_key=user.public_key,
        encrypted_private_key=user.encrypted_private_key,
        pbkdf2_salt=user.pbkdf2_salt,
        is_2fa_enabled=user.is_2fa_enabled,
        csrf_token=csrf_token,
    )


@router.get("/me", response_model=LoginResponse)
def get_current_user_info(
    _: User = Depends(get_current_user),
) -> LoginResponse:
    """Get current authenticated user info."""
    user = _
    return LoginResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        public_key=user.public_key,
        encrypted_private_key=user.encrypted_private_key,
        pbkdf2_salt=user.pbkdf2_salt,
        is_2fa_enabled=user.is_2fa_enabled,
    )


@router.post("/2fa/initiate", response_model=TwoFactorSetupResponse)
def initiate_2fa(
    current_user: User = Depends(get_current_user),
) -> TwoFactorSetupResponse:
    """Begin 2FA enrollment by issuing a temporary secret and otpauth URI."""
    if current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to process request",
        )

    temp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(
        temp_secret, interval=settings.TOTP_PERIOD, digits=settings.TOTP_DIGITS
    )
    otpauth_url = totp.provisioning_uri(
        name=current_user.email, issuer_name=settings.TOTP_ISSUER
    )

    return TwoFactorSetupResponse(temp_secret=temp_secret, otpauth_url=otpauth_url)


@router.post("/2fa/activate", response_model=TwoFactorActivateResponse)
def activate_2fa(
    activate_request: TwoFactorActivateRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> TwoFactorActivateResponse:
    """Activate 2FA after verifying a code from the provided secret."""
    if current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to process request",
        )

    if not _verify_totp_code(activate_request.temp_secret, activate_request.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code",
        )

    plain_codes, hashed_codes = _generate_backup_codes(settings.TOTP_BACKUP_CODES_COUNT)

    current_user.totp_secret = activate_request.temp_secret
    current_user.is_2fa_enabled = True
    _save_backup_codes(current_user, hashed_codes)
    current_user.updated_at = datetime.now(timezone.utc)

    db_session.add(current_user)
    db_session.commit()
    db_session.refresh(current_user)

    return TwoFactorActivateResponse(backup_codes=plain_codes)


@router.post("/2fa/disable", response_model=TwoFactorStatusResponse)
def disable_2fa(
    disable_request: TwoFactorDisableRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> TwoFactorStatusResponse:
    """Disable 2FA after verifying TOTP or backup code."""
    if not current_user.is_2fa_enabled:
        return TwoFactorStatusResponse(message="2FA already disabled")

    verified = False
    if disable_request.backup_code:
        verified = _consume_backup_code(
            current_user, disable_request.backup_code, db_session
        )

    if not verified and disable_request.totp_code:
        verified = _verify_totp_code(
            current_user.totp_secret, disable_request.totp_code
        )

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code",
        )

    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    current_user.updated_at = datetime.now(timezone.utc)

    db_session.add(current_user)
    db_session.commit()

    return TwoFactorStatusResponse(message="2FA disabled")


class UserPublicInfo(BaseModel):
    """Public user information for finding recipients."""

    id: int
    email: str
    first_name: str
    last_name: str
    public_key: str


class PublicKeyResponse(BaseModel):
    """Minimal public key response for secure message sending."""

    id: int
    public_key: str


@router.get("/users/search", response_model=UserPublicInfo | None)
def search_user_by_email(
    email: str,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> User | None:
    """
    Search for user by email to get their public key for encryption.
    Returns None if user not found or not active.
    Rate limited to prevent enumeration attacks.
    """
    rate_limit_key = f"search:{current_user.id}"
    if RateLimiter.is_rate_limited(rate_limit_key, max_attempts=20, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many search requests",
        )

    RateLimiter.record_attempt(rate_limit_key, window_seconds=60)

    statement = select(User).where(User.email == email, User.is_active)
    user = db_session.exec(statement).first()
    return user


@router.get("/verify-recipient", response_model=PublicKeyResponse)
def verify_recipient_and_get_public_key(
    email: str,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> PublicKeyResponse:
    """
    Verify if recipient exists and return their id and public key for message sending.
    Minimal information disclosure for security. Requires authentication.
    Rate limited to prevent enumeration attacks.

    Returns id and public_key if user exists and is active.
    Returns 404 with generic message if user not found.
    """
    rate_limit_key = f"verify:{current_user.id}"
    if RateLimiter.is_rate_limited(rate_limit_key, max_attempts=30, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )

    RateLimiter.record_attempt(rate_limit_key, window_seconds=60)

    normalized_email = email.strip().lower() if email else ""

    if not normalized_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required"
        )

    statement = select(User).where(User.email == normalized_email, User.is_active)
    user = db_session.exec(statement).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found"
        )

    return PublicKeyResponse(id=user.id, public_key=user.public_key)
