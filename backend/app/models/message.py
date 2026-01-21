from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class MessageBase(SQLModel):
    """Base message fields."""

    encrypted_payload_recipient: str | None = None
    encrypted_payload_sender: str | None = None
    signature: str


class Message(MessageBase, table=True):
    """
    Unified message model with integrated attachments.
    All message data (subject, content, attachments) is encrypted as one JSON unit.
    """

    id: int | None = Field(default=None, primary_key=True)
    sender_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)
    recipient_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)

    is_read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    read_at: datetime | None = None


class MessageCreate(SQLModel):
    """Message creation schema."""

    recipient_id: int
    encrypted_payload_recipient: str
    encrypted_payload_sender: str
    signature: str


class MessageRead(SQLModel):
    """Message read schema."""

    id: int
    sender_id: int
    recipient_id: int
    encrypted_payload_recipient: str | None
    encrypted_payload_sender: str | None
    signature: str
    is_read: bool
    created_at: datetime
    read_at: datetime | None
