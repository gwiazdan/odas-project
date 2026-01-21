import sys

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_v1_router, info_router
from app.core.config import settings
from app.core.db import init_db
from app.core.logger import logger
from app.core.sessions import get_session, init_redis

logger.info(f"Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}")
# Initialize database on startup
init_db()

# Initialize Redis
try:
    init_redis()
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


@app.middleware("http")
async def validate_csrf_token(request: Request, call_next):
    """Validate CSRF token for state-changing requests."""
    # Exempt paths that don't require CSRF (auth endpoints)
    exempt_paths = [
        "/api/v1/auth/login",
        "/api/v1/auth/signup",
        "/api/v1/auth/login/verify-2fa",
        "/api/info",
    ]

    # Only check CSRF for state-changing methods
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        if not any(request.url.path.startswith(path) for path in exempt_paths):
            csrf_token = request.headers.get("X-CSRF-Token")
            session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)

            if not session_id or not csrf_token:
                return JSONResponse(
                    {"detail": "CSRF token missing"},
                    status_code=status.HTTP_403_FORBIDDEN,
                )

            session_data = get_session(session_id)
            if not session_data or session_data.csrf_token != csrf_token:
                return JSONResponse(
                    {"detail": "Invalid CSRF token"},
                    status_code=status.HTTP_403_FORBIDDEN,
                )

    return await call_next(request)


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
