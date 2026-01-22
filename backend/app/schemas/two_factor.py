from pydantic import BaseModel

from app.schemas.auth import LoginResponse


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
