from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.info import router as info_router
from app.api.v1.routes.messages import router as messages_router

__all__ = ["auth_router", "info_router", "messages_router"]
