from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class MessageBase(SQLModel):
    """Base message fields."""

    subject: str = Field(max_length=255)
    # Entire encrypted payload: content + attachments metadata (RSA encrypted)
    encrypted_payload: str  # Base64 encoded
    # Proof of authenticity: SHA256(payload) signed with sender's private key
    signature: str  # Base64 encoded


class Message(MessageBase, table=True):
    """
    Unified message model with integrated attachments.
    Entire message (content + attachments metadata) is encrypted as one unit.
    """

    id: int | None = Field(default=None, primary_key=True)
    sender_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)
    recipient_id: int = Field(foreign_key="user.id", ondelete="CASCADE", index=True)

    # Message state
    is_read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    read_at: datetime | None = None


class MessageCreate(SQLModel):
    """Message creation schema - includes both content and attachments."""

    subject: str
    recipient_id: int
    encrypted_payload: str
    signature: str


class MessageRead(SQLModel):
    """Message read schema."""

    id: int
    sender_id: int
    recipient_id: int
    subject: str
    encrypted_payload: str
    signature: str
    is_read: bool
    created_at: datetime
    read_at: datetime | None
