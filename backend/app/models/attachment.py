from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class AttachmentBase(SQLModel):
    """Base attachment fields."""

    filename: str
    file_size: int
    mime_type: str


class Attachment(AttachmentBase, table=True):
    """Attachment database model."""

    id: int | None = Field(default=None, primary_key=True)
    message_id: int = Field(foreign_key="message.id", ondelete="CASCADE")
    file_path: str  # /uploads folder
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AttachmentCreate(AttachmentBase):
    """Attachment creation schema."""

    pass


class AttachmentRead(AttachmentBase):
    """Attachment read schema."""

    id: int
    created_at: datetime
