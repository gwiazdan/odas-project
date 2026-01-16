from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings"""

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_ignore_empty=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "SecureMessage"
    PROJECT_VERSION: str = "0.1.0"
    DESCRIPTION: str = "Backend API for SecureMessage application"

    DATABASE_URI: str = "sqlite:///./app.db"

    API_V1_STR: str = "/api/v1"

    # Session configuration
    SESSION_COOKIE_NAME: str = "sessionId"
    SESSION_TIMEOUT_MINUTES: int = 60 * 24  # 24 hours


settings = Settings()
