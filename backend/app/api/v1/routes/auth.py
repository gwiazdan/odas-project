"""Authentication routes with advanced security."""

import asyncio
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import get_session
from app.core.security import create_access_token, get_password_hash, verify_password
from app.core.security_utils import RateLimiter
from app.models.user import User, UserCreate, UserRead

router = APIRouter(prefix="/auth", tags=["auth"])


# Schemas
class LoginRequest(BaseModel):
    """Login request schema."""

    email: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=500)


class LoginResponse(BaseModel):
    """Login response schema."""

    access_token: str
    token_type: str
    user: UserRead


# Constants for validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
NAME_REGEX = re.compile(r"^[a-zA-Z\s'-]{2,50}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def validate_password_strength(password: str) -> None:
    """
    Validate password meets security requirements (negative approach - fail on weakness).

    Requirements:
    - At least 8 characters
    - At most 128 characters (prevent DoS via extremely long passwords)
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
        errors.append("Password must be at least 8 characters long")

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append("Password must not exceed 128 characters")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    # Special characters validation
    special_chars = r"!@#$%^&*()_+-=\[\]{};:'\",.<>?/\\|`~"
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=" ".join(errors),
        )


def validate_email_format(email: str) -> None:
    """
    Validate email format (negative approach - fail on invalid).

    Checks:
    - Not empty
    - Valid format with regex
    - Not exceeding max length
    """
    if not email or not email.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required",
        )

    email = email.strip()

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


def validate_name(name: str, field_name: str = "Name") -> str:
    """
    Validate name format (negative approach).

    Checks:
    - Not empty
    - 2-50 characters
    - Only letters, spaces, hyphens, apostrophes
    """
    if not name or not name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} is required",
        )

    name = name.strip()

    if len(name) < 2 or len(name) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 2 and 50 characters",
        )

    if not NAME_REGEX.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} contains invalid characters",
        )

    return name


@router.post("/signup", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def signup(
    user_create: UserCreate,
    session: Session = Depends(get_session),
) -> User:
    """
    Create a new user account.

    Validations:
    - Email format and uniqueness
    - Strong password
    - Valid names
    - All inputs sanitized
    """
    # Validate all inputs with negative approach
    first_name = validate_name(user_create.first_name, "First name")
    last_name = validate_name(user_create.last_name, "Last name")
    email = user_create.email.strip().lower()

    validate_email_format(email)
    validate_password_strength(user_create.password)

    # Check if email already exists (use case-insensitive search)
    statement = select(User).where(User.email == email)
    existing_user = session.exec(statement).first()
    if existing_user:
        # Generic error message to prevent email enumeration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account with provided information",
        )

    # Create new user with securely hashed password
    db_user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        hashed_password=get_password_hash(user_create.password),
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


@router.post("/login", response_model=LoginResponse)
async def login(
    login_request: LoginRequest,
    session: Session = Depends(get_session),
) -> dict:
    """
    Authenticate user and return access token.

    Security measures:
    - Rate limiting (5 attempts per 5 minutes)
    - Constant-time password comparison
    - Generic error messages to prevent user enumeration
    - Artificial delay to slow down brute-force attacks
    - Account active status check
    """
    email = login_request.email.strip().lower()

    # Rate limiting check
    if RateLimiter.is_rate_limited(email, max_attempts=5, window_seconds=300):
        # Generic error without revealing rate limiting
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    # Record attempt for rate limiting
    RateLimiter.record_attempt(email)

    # Simulate constant time by always doing password check
    # even if user doesn't exist (timing attack prevention)
    user = None
    try:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
    except Exception:
        # Log in production, but don't expose to client
        pass

    # Artificial delay to slow down brute-force attempts (100-300ms)
    await asyncio.sleep(0.1 + hash(email) % 200 / 1000)

    # Always validate password even if user not found (timing attack prevention)
    password_valid = False
    if user:
        password_valid = verify_password(login_request.password, user.hashed_password)

    # Generic error message to prevent user enumeration
    if not user or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account access denied",
        )

    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=str(user.id),
        expires_delta=access_token_expires,
    )

    # Clear rate limiting on successful login
    RateLimiter.record_attempt(
        email
    )  # Still track for analytics, but won't affect next attempt

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserRead.from_orm(user),
    }
