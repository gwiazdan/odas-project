"""Message routes - encrypted messaging with RSA."""

# ENDPOINTS:
# POST   /messages/send          - Send an encrypted message to recipient
# GET    /messages/inbox         - List received messages with pagination
# GET    /messages/sent          - List sent messages with pagination
# GET    /messages/{message_id}  - Retrieve and decrypt a specific message
# DELETE /messages/{message_id}  - Delete message for current user
# PUT    /messages/{message_id}/mark-as-read - Mark message as read
# POST   /messages/bulk-delete   - Delete multiple messages at once

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.v1.routes.auth import get_current_user
from app.core.db import get_session
from app.models.message import Message, MessageRead
from app.models.user import User, UserRead

router = APIRouter(prefix="/messages", tags=["messages"])


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
    encrypted_payload: str  # Full encrypted payload for frontend decryption
    is_read: bool
    created_at: datetime


class SentMessagePreview(BaseModel):
    """Preview of sent message for list view."""

    id: int
    recipient_id: int
    recipient_username: str
    encrypted_payload: str  # Full encrypted payload for frontend decryption
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
    payload: str  # Encrypted payload as base64 string - frontend decrypts this
    signature: str
    is_read: bool
    created_at: datetime
    read_at: datetime | None


def verify_recipient_exists(
    recipient_id: int,
    db_session: Session,
) -> User:
    """Verify recipient exists and is active."""
    recipient = db_session.get(User, recipient_id)
    if not recipient or not recipient.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )
    return recipient


@router.post(
    "/send", response_model=SendMessageResponse, status_code=status.HTTP_201_CREATED
)
def send_message(
    send_request: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
) -> Message:
    """Send an encrypted message with all data (subject, content, attachments) in payload."""
    verify_recipient_exists(send_request.recipient_id, db_session)

    if send_request.recipient_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot send message to yourself",
        )

    db_message = Message(
        sender_id=current_user.id,
        recipient_id=send_request.recipient_id,
        encrypted_payload_recipient=send_request.payload_recipient,
        encrypted_payload_sender=send_request.payload_sender,
        signature=send_request.signature,
        created_at=datetime.now(UTC),
    )

    db_session.add(db_message)
    db_session.commit()
    db_session.refresh(db_message)

    return db_message


@router.get("/inbox", response_model=InboxResponse)
def get_inbox(
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
) -> InboxResponse:
    """Get received messages with pagination and preview data."""
    # Count total messages (only where recipient's copy exists)
    count_statement = select(Message).where(
        (Message.recipient_id == current_user.id)
        & (Message.encrypted_payload_recipient.isnot(None))
    )
    total = len(db_session.exec(count_statement).all())

    # Calculate pagination
    skip = (page - 1) * page_size
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    # Get messages
    statement = (
        select(Message)
        .where(
            (Message.recipient_id == current_user.id)
            & (Message.encrypted_payload_recipient.isnot(None))
        )
        .order_by(Message.created_at.desc())
        .offset(skip)
        .limit(page_size)
    )
    messages = db_session.exec(statement).all()

    # Build preview list
    previews = []
    for msg in messages:
        sender = db_session.get(User, msg.sender_id)

        previews.append(
            InboxMessagePreview(
                id=msg.id,
                sender_id=msg.sender_id,
                sender_username=sender.full_name if sender else "Unknown",
                encrypted_payload=msg.encrypted_payload_recipient,
                is_read=msg.is_read,
                created_at=msg.created_at,
            )
        )

    return InboxResponse(
        messages=previews,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/sent", response_model=SentResponse)
def get_sent(
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
) -> SentResponse:
    """Get sent messages with pagination and preview data."""
    # Count total messages (only where sender's copy exists)
    count_statement = select(Message).where(
        (Message.sender_id == current_user.id)
        & (Message.encrypted_payload_sender.isnot(None))
    )
    total = len(db_session.exec(count_statement).all())

    # Calculate pagination
    skip = (page - 1) * page_size
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    # Get messages
    statement = (
        select(Message)
        .where(
            (Message.sender_id == current_user.id)
            & (Message.encrypted_payload_sender.isnot(None))
        )
        .order_by(Message.created_at.desc())
        .offset(skip)
        .limit(page_size)
    )
    messages = db_session.exec(statement).all()

    # Build preview list
    previews = []
    for msg in messages:
        recipient = db_session.get(User, msg.recipient_id)

        previews.append(
            SentMessagePreview(
                id=msg.id,
                recipient_id=msg.recipient_id,
                recipient_username=recipient.full_name if recipient else "Unknown",
                encrypted_payload=msg.encrypted_payload_sender,
                is_read=msg.is_read,
                created_at=msg.created_at,
            )
        )

    return SentResponse(
        messages=previews,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{message_id}", response_model=DecryptedMessageRead)
def get_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
) -> DecryptedMessageRead:
    """
    Get a specific message and decrypt it.

    Required: User has private key decrypted with their password.
    The frontend must:
    1. Request user password
    2. Decrypt user's private key with it
    3. Use private key to decrypt message payload
    4. Verify signature with sender's public key
    """
    message = db_session.get(Message, message_id)

    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    # Check if user is recipient or sender
    is_recipient = message.recipient_id == current_user.id
    is_sender = message.sender_id == current_user.id

    if not is_recipient and not is_sender:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Check if the message copy still exists for this user
    if is_recipient and message.encrypted_payload_recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )
    if is_sender and message.encrypted_payload_sender is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    # Get sender info for signature verification
    sender = db_session.get(User, message.sender_id)
    if not sender:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sender not found",
        )

    # Mark as read if not already (only for recipients)
    if is_recipient and not message.is_read:
        message.is_read = True
        message.read_at = datetime.now(UTC)
        db_session.add(message)
        db_session.commit()

    # Use appropriate encrypted payload based on who's viewing
    encrypted_payload = (
        message.encrypted_payload_recipient
        if is_recipient
        else message.encrypted_payload_sender
    )

    # Return encrypted payload as-is - frontend will decrypt and verify signature
    return DecryptedMessageRead(
        id=message.id,
        sender_id=message.sender_id,
        sender=UserRead.from_orm(sender),
        recipient_id=message.recipient_id,
        payload=encrypted_payload,  # Return encrypted string directly
        signature=message.signature,
        is_read=message.is_read,
        created_at=message.created_at,
        read_at=message.read_at,
    )


@router.delete("/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
) -> None:
    """
    Delete a message for current user.

    - If recipient: nulls encrypted_payload_recipient
    - If sender: nulls encrypted_payload_sender
    - If both are null: removes record from database
    """
    message = db_session.get(Message, message_id)

    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    # Check if user is recipient or sender
    is_recipient = message.recipient_id == current_user.id
    is_sender = message.sender_id == current_user.id

    if not is_recipient and not is_sender:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # EXPLANATION:
    # Each message has two encrypted payloads:
    # - encrypted_payload_recipient: for the recipient
    # - encrypted_payload_sender: for the sender
    # When a user deletes a message, we only nullify their respective payload.
    # If both payloads become null, we delete the entire message record.
    # This ensures that each user can independently delete their copy of the message.

    # Null the appropriate payload copy
    if is_recipient:
        message.encrypted_payload_recipient = None
    if is_sender:
        message.encrypted_payload_sender = None

    # If both copies are now empty, delete the record
    if (
        message.encrypted_payload_recipient is None
        and message.encrypted_payload_sender is None
    ):
        db_session.delete(message)
    else:
        db_session.add(message)

    db_session.commit()


@router.put("/{message_id}/mark-as-read", response_model=MessageRead)
def mark_as_read(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
) -> Message:
    """Mark message as read."""
    message = db_session.get(Message, message_id)

    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    if message.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    if not message.is_read:
        message.is_read = True
        message.read_at = datetime.now(UTC)
        db_session.add(message)
        db_session.commit()
        db_session.refresh(message)

    return message


@router.post("/bulk-delete", status_code=status.HTTP_200_OK)
def bulk_delete_messages(
    delete_request: BulkDeleteRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_session),
) -> dict:
    """
    Delete multiple messages for current user.

    - For each message: nulls appropriate payload copy
    - If both copies become null: removes record
    """
    if not delete_request.message_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No message IDs provided",
        )

    deleted_count = 0
    failed_ids = []

    for message_id in delete_request.message_ids:
        message = db_session.get(Message, message_id)

        if not message:
            failed_ids.append(message_id)
            continue

        # Check if user is recipient or sender
        is_recipient = message.recipient_id == current_user.id
        is_sender = message.sender_id == current_user.id

        if not is_recipient and not is_sender:
            failed_ids.append(message_id)
            continue

        # Null the appropriate payload copy
        if is_recipient:
            message.encrypted_payload_recipient = None
        if is_sender:
            message.encrypted_payload_sender = None

        # If both copies are now empty, delete the record
        if (
            message.encrypted_payload_recipient is None
            and message.encrypted_payload_sender is None
        ):
            db_session.delete(message)
        else:
            db_session.add(message)

        deleted_count += 1

    db_session.commit()

    return {
        "deleted": deleted_count,
        "failed": len(failed_ids),
        "failed_ids": failed_ids,
    }
