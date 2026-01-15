from datetime import datetime

from sqlmodel import Field, SQLModel


class MessageBase(SQLModel):
    """Base message fields."""

    subject: str
    encrypted_content: str  # Base64
    signature: str  # Signature for authenticity


class Message(MessageBase, table=True):
    """Message database model."""

    id: int | None = Field(default=None, primary_key=True)
    sender_id: int = Field(foreign_key="user.id", ondelete="CASCADE")
    recipient_id: int = Field(foreign_key="user.id", ondelete="CASCADE")
    is_read: bool = False
    created_at: datetime = Field(default_factory=datetime.timezone.utc.now)
    read_at: datetime | None = None


class MessageCreate(MessageBase):
    """Message creation schema."""

    recipient_id: int


class MessageRead(MessageBase):
    """Message read schema."""

    id: int
    sender_id: int
    recipient_id: int
    is_read: bool
    created_at: datetime
    read_at: datetime | None
