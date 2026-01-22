from pydantic import BaseModel, Field


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
