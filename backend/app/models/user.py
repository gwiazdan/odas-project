from datetime import datetime

from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    """Base user fields."""

    email: str = Field(unique=True, index=True)
    full_name: str | None = None
    is_active: bool = True


class User(UserBase, table=True):
    """User database model."""

    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.timezone.utc.now)
    updated_at: datetime = Field(default_factory=datetime.timezone.utc.now)


class UserCreate(UserBase):
    """User creation schema."""

    password: str


class UserRead(UserBase):
    """User read schema."""

    id: int
    created_at: datetime
    updated_at: datetime
