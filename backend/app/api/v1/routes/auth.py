"""Authentication routes"""

# ENDPOINTS:
# POST   /auth/signup           - User registration with RSA keypair generation
# POST   /auth/login            - User login with session creation
# POST   /auth/logout           - User logout and session deletion
# GET    /auth/me               - Get current authenticated user info
# GET    /auth/users/search     - Search user by email to get public key
# GET    /auth/verify-recipient - Verify recipient existence and get public key
# GET    /auth/verify-session   - Check session + CSRF for frontend

import asyncio
import secrets
from datetime import datetime, timezone

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import get_db_session
from app.core.rate_limiter import RateLimiter, get_client_ip
from app.core.security import (
    encrypt_private_key,
    generate_rsa_keypair,
    get_password_hash,
    verify_password,
)
from app.core.sessions import create_session, delete_session, get_session
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LoginStepOneResponse,
    LogoutResponse,
    PublicKeyResponse,
    SignupRequest,
    SignupResponse,
    UserPublicInfo,
)
from app.schemas.two_factor import (
    TwoFactorActivateRequest,
    TwoFactorActivateResponse,
    TwoFactorDisableRequest,
    TwoFactorSetupResponse,
    TwoFactorStatusResponse,
    TwoFactorVerifyRequest,
    TwoFactorVerifyResponse,
)
from app.utils.auth import (
    validate_email_format,
    validate_name,
    validate_password_strength,
)
from app.utils.two_factor import (
    consume_backup_code,
    create_pending_token,
    generate_backup_codes,
    pop_pending_token,
    save_backup_codes,
    verify_totp_code,
)

router = APIRouter(prefix="/auth", tags=["auth"])


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
    if RateLimiter.check("login", email)[0]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
        )

    RateLimiter.record("login", email)

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
        create_pending_token(user, pending_token)
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


@router.get("/users/search", response_model=UserPublicInfo | None)
def search_user_by_email(
    email: str,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
    ip: str = Depends(get_client_ip),
) -> User | None:
    """
    Search for user by email to get their public key for encryption.
    Returns None if user not found or not active.
    Rate limited to prevent enumeration attacks.
    """
    rate_limit_key = f"{current_user.id}:{ip}"
    if RateLimiter.check("search", rate_limit_key)[0]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many search requests",
        )

    RateLimiter.record("search", rate_limit_key)

    statement = select(User).where(User.email == email, User.is_active)
    user = db_session.exec(statement).first()
    return user


@router.get("/verify-session", response_model=dict)
def verify_session_endpoint(request: Request) -> dict:
    """
    Verify session cookie for frontend hydration.
    """
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session cookie")
    session_data = get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid/expired session")
    csrf_header = request.headers.get("X-CSRF-Token")
    if csrf_header and csrf_header != session_data.csrf_token:
        raise HTTPException(status_code=401, detail="CSRF mismatch")
    return {
        "valid": True,
        "user_id": session_data.user_id,
        "csrf_token": session_data.csrf_token,
    }


@router.get("/verify-recipient", response_model=PublicKeyResponse)
def verify_recipient_and_get_public_key(
    email: str,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
    ip: str = Depends(get_client_ip),
) -> PublicKeyResponse:
    """
    Verify if recipient exists and return their id and public key for message sending.
    Minimal information disclosure for security. Requires authentication.
    Rate limited to prevent enumeration attacks.

    Returns id and public_key if user exists and is active.
    Returns 404 with generic message if user not found.
    """

    rate_limit_key = f"{current_user.id}:{ip}"
    if RateLimiter.check("search", rate_limit_key)[0]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )

    RateLimiter.record("search", rate_limit_key)

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


@router.post("/login/verify-2fa", response_model=TwoFactorVerifyResponse)
def verify_2fa_login(
    verify_request: TwoFactorVerifyRequest,
    request: Request,
    response: Response,
    db_session: Session = Depends(get_db_session),
    ip: str = Depends(get_client_ip),
) -> TwoFactorVerifyResponse:
    """Finalize login by verifying TOTP or backup code and issuing session."""
    user_id = pop_pending_token(verify_request.pending_token)
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

    rate_key = f"{user.email}:{ip}"
    if RateLimiter.check("2fa", rate_key)[0]:
        raise HTTPException(429, "2FA rate limited")
    RateLimiter.record("2fa", rate_key)

    verified = False
    if verify_request.backup_code:
        verified = consume_backup_code(user, verify_request.backup_code, db_session)

    if not verified and verify_request.totp_code:
        verified = verify_totp_code(user.totp_secret, verify_request.totp_code)

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

    if not verify_totp_code(activate_request.temp_secret, activate_request.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code",
        )

    plain_codes, hashed_codes = generate_backup_codes(settings.TOTP_BACKUP_CODES_COUNT)

    current_user.totp_secret = activate_request.temp_secret
    current_user.is_2fa_enabled = True
    save_backup_codes(current_user, hashed_codes)
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
        verified = consume_backup_code(
            current_user, disable_request.backup_code, db_session
        )

    if not verified and disable_request.totp_code:
        verified = verify_totp_code(current_user.totp_secret, disable_request.totp_code)

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
