from datetime import UTC, datetime

from pydantic import computed_field
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    """Base user fields."""

    email: str = Field(unique=True, index=True)
    first_name: str = Field(max_length=50)
    last_name: str = Field(max_length=50)
    is_active: bool = True

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()


class User(UserBase, table=True):
    """User database model with RSA key support."""

    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str

    public_key: str
    encrypted_private_key: str
    pbkdf2_salt: str

    totp_secret: str | None = None
    is_2fa_enabled: bool = False
    backup_codes: str | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UserCreate(SQLModel):
    """User creation schema."""

    email: str
    first_name: str
    last_name: str
    password: str


class UserRead(UserBase):
    """User read schema - includes public key for encryption."""

    id: int
    public_key: str
