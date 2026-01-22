from datetime import datetime

from pydantic import BaseModel

from app.models.user import UserRead


class MessagePayload(BaseModel):
    """Decrypted message payload structure."""

    subject: str
    content: str
    attachments: list[dict] = []


class SendMessageRequest(BaseModel):
    """Request to send an encrypted message."""

    recipient_id: int
    payload_recipient: str
    payload_sender: str
    signature: str


class SendMessageResponse(BaseModel):
    """Response after sending message."""

    id: int
    sender_id: int
    recipient_id: int
    created_at: datetime


class InboxMessagePreview(BaseModel):
    """Preview of inbox message for list view."""

    id: int
    sender_id: int
    sender_username: str
    encrypted_payload: str
    signature: str
    sender_public_key: str
    is_read: bool
    created_at: datetime


class SentMessagePreview(BaseModel):
    """Preview of sent message for list view."""

    id: int
    recipient_id: int
    recipient_username: str
    encrypted_payload: str
    signature: str
    sender_public_key: str
    is_read: bool
    created_at: datetime


class InboxResponse(BaseModel):
    """Paginated inbox response."""

    messages: list[InboxMessagePreview]
    total: int
    page: int
    page_size: int
    total_pages: int


class SentResponse(BaseModel):
    """Paginated sent messages response."""

    messages: list[SentMessagePreview]
    total: int
    page: int
    page_size: int
    total_pages: int


class BulkDeleteRequest(BaseModel):
    """Request to delete multiple messages."""

    message_ids: list[int]


class DecryptedMessageRead(BaseModel):
    """Message with encrypted payload (frontend decrypts it)."""

    id: int
    sender_id: int
    sender: UserRead
    recipient_id: int
    payload: str
    signature: str
    is_read: bool
    created_at: datetime
    read_at: datetime | None
