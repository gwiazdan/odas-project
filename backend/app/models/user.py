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
    """User database model."""

    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UserCreate(SQLModel):
    """User creation schema."""

    email: str
    first_name: str
    last_name: str
    password: str


class UserRead(UserBase):
    """User read schema."""

    pass
