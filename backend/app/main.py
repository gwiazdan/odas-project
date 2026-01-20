from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_v1_router, info_router
from app.core.config import settings
from app.core.db import init_db
from app.core.sessions import init_redis

# Initialize database on startup
init_db()

# Initialize Redis for session management
try:
    init_redis("redis://localhost:6379/0")
except Exception as e:
    print(f"Warning: Could not connect to Redis: {e}")
    print("Sessions will not be persisted across restarts")

app = FastAPI(
    title=settings.PROJECT_NAME,
)

# CORS configuration
# When using credentials: 'include', we cannot use allow_origins=["*"]
# We must specify concrete origins
# TODO: CORS configuration will be rewritten and put into the config.py
allowed_origins = [
    "http://localhost:3000",
    "http://localhost",
    "http://127.0.0.1:3000",
    "http://127.0.0.1",
    "http://192.168.200.115:3000",
    "http://192.168.200.133",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_v1_router)
app.include_router(info_router)
