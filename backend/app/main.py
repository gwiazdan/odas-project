import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_v1_router, info_router
from app.core.config import settings
from app.core.db import init_db
from app.core.logger import logger
from app.core.sessions import init_redis

logger.info(f"Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}")
# Initialize database on startup
init_db()

# Initialize Redis
try:
    init_redis(settings.REDIS_URL)
except Exception as e:
    logger.critical(f"Could not connect to Redis at {settings.REDIS_URL}: {e}")
    sys.exit(1)

app = FastAPI(
    title=settings.PROJECT_NAME,
)


@app.middleware("http")
async def log_exceptions(request: Request, call_next):
    """Log unhandled exceptions with request context."""
    try:
        return await call_next(request)
    except Exception:
        logger.exception("Unhandled exception", extra={"path": str(request.url)})
        raise


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS.split(","),
    allow_credentials=settings.ALLOW_CREDENTIALS,
    allow_methods=settings.ALLOW_METHODS,
    allow_headers=settings.ALLOW_HEADERS,
    max_age=600,
)

app.include_router(api_v1_router)
app.include_router(info_router)
