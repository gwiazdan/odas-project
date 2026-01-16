from fastapi import APIRouter

from app.api.v1.routes import info_router, auth_router
from app.core.config import settings

api_v1_router = APIRouter(prefix=settings.API_V1_STR)
api_v1_router.include_router(info_router)
api_v1_router.include_router(auth_router)

__all__ = ["api_v1_router"]
