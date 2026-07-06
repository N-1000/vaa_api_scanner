"""
Security Headers Middleware for VAA Cyber-range v2
Adds enterprise-grade security headers to all responses
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Add security headers to response
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
            
        Returns:
            Response with security headers added
        """
        response = await call_next(request)
        

        response.headers["X-Content-Type-Options"] = "nosniff"
        

        response.headers["X-Frame-Options"] = "DENY"
        

        response.headers["X-XSS-Protection"] = "1; mode=block"
        

        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        

        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        

        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=()"
        )
        

        response.headers["Server"] = "VAA-Cyber-range"
        
        return response
