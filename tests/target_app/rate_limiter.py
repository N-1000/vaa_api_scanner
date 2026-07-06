"""
Rate Limiting Module for VAA Cyber-range v2
Implements request rate limiting using SlowAPI
"""

from typing import Callable
from fastapi import Request
from fastapi.responses import JSONResponse

class DummyLimiter:
    """Bypasses rate limiting for local vulnerability testing."""
    def limit(self, *args, **kwargs):
        def decorator(func: Callable):
            return func
        return decorator

limiter = DummyLimiter()

class RateLimitExceeded(Exception):
    pass

async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Custom handler for rate limit exceeded errors
    Returns a JSON response with 429 status code
    """
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": "Too many requests. Please try again later.",
            "limit": str(exc.detail)
        },
        headers={"Retry-After": "60"}
    )
