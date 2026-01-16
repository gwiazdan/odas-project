"""Message routes - encrypted messaging with RSA."""

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.v1.routes.auth import get_current_user
from app.core.db import get_session as get_db_session
from app.core.security import (
    verify_message_signature,
)
from app.models.message import Message, MessageRead
from app.models.user import User, UserRead

router = APIRouter(prefix="/messages", tags=["messages"])


# ============================================================================
# SCHEMAS
# ============================================================================


class MessagePayload(BaseModel):
    """Decrypted message payload structure."""

    content: str
    attachments: list[dict] = []  # [{filename, size, mimetype, data_base64}, ...]


class SendMessageRequest(BaseModel):
    """Request to send an encrypted message."""

    recipient_id: int
    subject: str
    payload: str  # JSON-encoded MessagePayload, encrypted with RSA
    signature: str  # Base64 signature of payload


class SendMessageResponse(BaseModel):
    """Response after sending message."""

    id: int
    sender_id: int
    recipient_id: int
    subject: str
    created_at: datetime


class DecryptedMessageRead(BaseModel):
    """Message with decrypted payload."""

    id: int
    sender_id: int
    sender: UserRead
    recipient_id: int
    subject: str
    payload: MessagePayload
    signature: str
    is_read: bool
    signature_valid: bool
    created_at: datetime
    read_at: datetime | None


# ============================================================================
# HELPERS
# ============================================================================


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


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/send", response_model=SendMessageResponse, status_code=status.HTTP_201_CREATED
)
def send_message(
    send_request: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> Message:
    """
    Send an encrypted message.

    The payload must be:
    1. Encrypted with recipient's public key (RSA-OAEP)
    2. Signed with sender's private key (RSA-PSS for authenticity proof)

    Frontend should:
    1. Create MessagePayload (content + attachments metadata)
    2. Serialize to JSON
    3. Encrypt JSON with recipient's public key
    4. Sign the JSON with sender's private key
    5. Send both encrypted payload and signature
    """
    # Verify recipient exists
    verify_recipient_exists(send_request.recipient_id, db_session)

    # Don't allow sending to self (optional business rule)
    if send_request.recipient_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot send message to yourself",
        )

    # Create message - store encrypted payload and signature as-is
    db_message = Message(
        sender_id=current_user.id,
        recipient_id=send_request.recipient_id,
        subject=send_request.subject[:255],  # Limit subject length
        encrypted_payload=send_request.payload,
        signature=send_request.signature,
        created_at=datetime.now(UTC),
    )

    db_session.add(db_message)
    db_session.commit()
    db_session.refresh(db_message)

    return db_message


@router.get("/inbox", response_model=list[SendMessageResponse])
def get_inbox(
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
) -> list[Message]:
    """Get received messages (list view - encrypted payloads not decrypted)."""
    statement = (
        select(Message)
        .where(Message.recipient_id == current_user.id)
        .order_by(Message.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    messages = db_session.exec(statement).all()
    return messages


@router.get("/{message_id}", response_model=DecryptedMessageRead)
def get_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
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

    # Only recipient can read message
    if message.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Get sender info for signature verification
    sender = db_session.get(User, message.sender_id)
    if not sender:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sender not found",
        )

    # Mark as read if not already
    if not message.is_read:
        message.is_read = True
        message.read_at = datetime.now(UTC)
        db_session.add(message)
        db_session.commit()

    # Verify signature with sender's public key
    payload_bytes = message.encrypted_payload.encode()
    signature_valid = verify_message_signature(
        payload_bytes,
        message.signature,
        sender.public_key,
    )

    # Try to decrypt payload (will fail if user doesn't have/provide private key)
    # For now, return encrypted payload - frontend handles decryption
    try:
        payload_json = message.encrypted_payload
        payload_data = json.loads(payload_json)
    except Exception:
        payload_data = MessagePayload(content="", attachments=[])

    return DecryptedMessageRead(
        id=message.id,
        sender_id=message.sender_id,
        sender=UserRead.from_orm(sender),
        recipient_id=message.recipient_id,
        subject=message.subject,
        payload=payload_data,
        signature=message.signature,
        is_read=message.is_read,
        signature_valid=signature_valid,
        created_at=message.created_at,
        read_at=message.read_at,
    )


@router.delete("/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
) -> None:
    """Delete a message (recipient only)."""
    message = db_session.get(Message, message_id)

    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    # Only recipient can delete message
    if message.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    db_session.delete(message)
    db_session.commit()


@router.put("/{message_id}/mark-as-read", response_model=MessageRead)
def mark_as_read(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db_session: Session = Depends(get_db_session),
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
