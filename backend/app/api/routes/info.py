"""Info route."""

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(tags=["info"])


@router.get("/info")
def get_info():
    """Get application info."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "description": settings.DESCRIPTION,
    }


@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@router.get("/")
def read_root():
    return {"message": "SecureMessage API"}
