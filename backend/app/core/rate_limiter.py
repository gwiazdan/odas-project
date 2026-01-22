"""Rate limiting and security utilities."""

from datetime import datetime, timedelta, timezone

from fastapi import Request

from app.core.sessions import _get_redis_client


def get_rate_limits(scope: str) -> dict:
    return {
        "login": {"max": 5, "window": 300},
        "search": {"max": 50, "window": 60},
        "2fa": {"max": 5, "window": 60},
    }.get(scope, {"max": 100, "window": 60})


class RateLimiter:
    @staticmethod
    def check(scope: str, identifier: str) -> tuple[bool, int, datetime | None]:
        limits = get_rate_limits(scope)
        client = _get_redis_client()
        key = f"ratelimit:{scope}:{identifier}"

        pipe = client.pipeline()
        pipe.get(key)
        pipe.ttl(key)
        current_str, ttl = pipe.execute()

        current = int(current_str or 0)
        remaining = max(0, limits["max"] - current)
        reset = datetime.now(timezone.utc) + timedelta(seconds=ttl) if ttl > 0 else None

        return current >= limits["max"], remaining, reset

    @staticmethod
    def record(scope: str, identifier: str) -> None:
        limits = get_rate_limits(scope)
        client = _get_redis_client()
        key = f"ratelimit:{scope}:{identifier}"
        client.pipeline().incr(key).expire(key, limits["window"]).execute()


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fallback
    return request.client.host or "127.0.0.1"
