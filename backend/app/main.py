from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_v1_router
from app.core.config import settings
from app.core.db import init_db

# Initialize database on startup
init_db()

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


@app.get("/")
def read_root():
    return {"message": "SecureMessage API"}
