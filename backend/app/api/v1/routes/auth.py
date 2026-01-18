"""Authentication routes with session store and RSA keypair generation."""

# ENDPOINTS:
# POST   /auth/signup          - User registration with RSA keypair generation
# POST   /auth/login           - User login with session creation
# POST   /auth/logout          - User logout and session deletion
# GET    /auth/me              - Get current authenticated user info
# GET    /auth/users/search    - Search user by email to get public key
# GET    /auth/verify-recipient - Verify recipient existence and get public key

import asyncio
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select

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

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
NAME_REGEX = re.compile(r"^[a-zA-Z\s'-]{2,50}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


class SignupRequest(BaseModel):
    """Signup request schema."""

    email: str = Field(..., min_length=1, max_length=254)
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


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


class LoginResponse(BaseModel):
    """Login response schema."""

    id: int
    email: str
    first_name: str
    last_name: str
    public_key: str
    encrypted_private_key: str  # For client-side decryption with password
    pbkdf2_salt: str  # Salt for PBKDF2 decryption


class LogoutResponse(BaseModel):
    """Logout response schema."""

    message: str


def validate_password_strength(
    password: str,
) -> None:  # TODO: zxcbn password strength validation
    """
    Validate password meets security requirements (negative approach).

    Requirements:
    - At least 8 characters
    - At most 128 characters (prevent DoS)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    errors = []

    if not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required",
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append("at least 8 characters")

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append("at most 128 characters")

    if not any(c.isupper() for c in password):
        errors.append("uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("digit")

    special_chars = r"!@#$%^&*()_+-=\[\]{};:'\",.<>?/\\|`~"
    if not any(c in special_chars for c in password):
        errors.append("special character")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must contain: {', '.join(errors)}",
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
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    db_session.add(db_user)
    db_session.commit()
    db_session.refresh(db_user)

    return db_user


@router.post("/login", response_model=LoginResponse)
async def login(
    login_request: LoginRequest,
    request: Request,
    response: Response,
    db_session: Session = Depends(get_db_session),
) -> LoginResponse:
    """
    Authenticate user and create session.

    Security measures:
    - Rate limiting (5 attempts per 5 minutes)
    - Constant-time password comparison
    - Generic error messages
    - Artificial delay (100-300ms) to slow brute-force
    - HttpOnly Secure session cookie
    """
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

    session_id = create_session(
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    # Set secure httpOnly cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
    )

    return LoginResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        public_key=user.public_key,
        encrypted_private_key=user.encrypted_private_key,
        pbkdf2_salt=user.pbkdf2_salt,
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
    )


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

    RateLimiter.record_attempt(rate_limit_key)

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

    RateLimiter.record_attempt(rate_limit_key)

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
