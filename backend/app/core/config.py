from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings"""

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_ignore_empty=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "SecureMessage"
    PROJECT_VERSION: str = "1.0.0"
    DESCRIPTION: str = "Backend API for SecureMessage application"

    DATABASE_URI: str = "sqlite:///./app.db"

    # TOTP / 2FA
    TOTP_ISSUER: str = "SecureMessage"
    TOTP_PERIOD: int = 30
    TOTP_DIGITS: int = 6
    TOTP_BACKUP_CODES_COUNT: int = 5

    # Endpoints
    API_V1_STR: str = "/api/v1"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    SESSION_COOKIE_NAME: str = "sessionId"
    SESSION_TIMEOUT_MINUTES: int = 60 * 24  # 24 hours

    # CORS Settings
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    ALLOW_CREDENTIALS: bool = True
    ALLOW_METHODS: list[str] = ["*"]
    ALLOW_HEADERS: list[str] = ["*"]


settings = Settings()
