"""
NiksES Security Utilities

Provides security middleware and utilities for the API:
- Rate limiting
- Security headers
- Error sanitization
"""

import time
import logging
from typing import Dict, Callable, Optional
from collections import defaultdict
from functools import wraps

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window.
    
    For production, consider using Redis-based rate limiting.
    """
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_size = 60  # seconds
        self._requests: Dict[str, list] = defaultdict(list)
    
    def _clean_old_requests(self, client_id: str, current_time: float):
        """Remove requests outside the current window."""
        cutoff = current_time - self.window_size
        self._requests[client_id] = [
            t for t in self._requests[client_id] if t > cutoff
        ]
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed for this client."""
        current_time = time.time()
        self._clean_old_requests(client_id, current_time)
        
        if len(self._requests[client_id]) >= self.requests_per_minute:
            return False
        
        self._requests[client_id].append(current_time)
        return True
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for this client."""
        current_time = time.time()
        self._clean_old_requests(client_id, current_time)
        return max(0, self.requests_per_minute - len(self._requests[client_id]))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware for FastAPI.
    
    Limits requests per IP address per minute.
    """
    
    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.limiter = RateLimiter(requests_per_minute)
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check forwarded headers (for proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/api/v1/health"]:
            return await call_next(request)
        
        # Check rate limit
        if not self.limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please slow down.",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"}
            )
        
        # Add rate limit headers to response
        response = await call_next(request)
        remaining = self.limiter.get_remaining(client_ip)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response


# ============================================================================
# SECURITY HEADERS
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    """
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions policy (disable unnecessary features)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Content Security Policy (adjust as needed)
        # Note: Relaxed for API responses, tighten for HTML responses
        if "text/html" in response.headers.get("content-type", ""):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'"
            )
        
        return response


# ============================================================================
# ERROR SANITIZATION
# ============================================================================

def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message for safe display to users.
    
    Removes potentially sensitive information like:
    - File paths
    - Stack traces
    - Internal class names
    """
    error_str = str(error)
    
    # List of patterns to sanitize
    sensitive_patterns = [
        # File paths
        (r'/home/\S+', '[path]'),
        (r'/app/\S+', '[path]'),
        (r'/usr/\S+', '[path]'),
        (r'C:\\[^\s]+', '[path]'),
        
        # API keys (partial)
        (r'sk-[a-zA-Z0-9]{20,}', '[api_key]'),
        (r'api_key=[^\s&]+', 'api_key=[hidden]'),
        
        # Connection strings
        (r'postgresql://[^\s]+', '[db_connection]'),
        (r'mysql://[^\s]+', '[db_connection]'),
        (r'redis://[^\s]+', '[redis_connection]'),
    ]
    
    import re
    for pattern, replacement in sensitive_patterns:
        error_str = re.sub(pattern, replacement, error_str)
    
    # Truncate if too long
    if len(error_str) > 200:
        error_str = error_str[:200] + "..."
    
    return error_str


def safe_error_response(
    status_code: int,
    default_message: str = "An error occurred",
    error: Optional[Exception] = None,
    include_details: bool = False,
) -> HTTPException:
    """
    Create a safe HTTPException with sanitized error message.
    
    Args:
        status_code: HTTP status code
        default_message: Default message to show
        error: Original exception (optional)
        include_details: Whether to include sanitized error details
        
    Returns:
        HTTPException with safe message
    """
    if include_details and error:
        detail = f"{default_message}: {sanitize_error_message(error)}"
    else:
        detail = default_message
    
    return HTTPException(status_code=status_code, detail=detail)


# ============================================================================
# FILE VALIDATION
# ============================================================================

# Maximum file size in bytes (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Allowed file extensions
ALLOWED_EXTENSIONS = {'.eml', '.msg'}

# Allowed MIME types
ALLOWED_MIME_TYPES = {
    'message/rfc822',  # .eml
    'application/vnd.ms-outlook',  # .msg
    'application/octet-stream',  # Generic binary
}


def validate_file_size(content: bytes, max_size: int = MAX_FILE_SIZE) -> bool:
    """
    Validate file size is within limits.
    
    Args:
        content: File content as bytes
        max_size: Maximum allowed size in bytes
        
    Returns:
        True if valid, raises HTTPException if not
    """
    if len(content) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {max_size // (1024*1024)} MB"
        )
    return True


def validate_file_extension(filename: str) -> bool:
    """
    Validate file extension is allowed.
    
    Args:
        filename: Original filename
        
    Returns:
        True if valid, raises HTTPException if not
    """
    import os
    ext = os.path.splitext(filename.lower())[1]
    
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    return True


# ============================================================================
# INPUT SANITIZATION
# ============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import os
    import re
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Remove potentially dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename


def sanitize_search_query(query: str, max_length: int = 100) -> str:
    """
    Sanitize search query to prevent injection.
    
    Args:
        query: Original search query
        max_length: Maximum allowed length
        
    Returns:
        Sanitized query
    """
    # Remove FTS special characters that could cause issues
    special_chars = ['*', '"', "'", ';', '--', '/*', '*/']
    sanitized = query
    
    for char in special_chars:
        sanitized = sanitized.replace(char, '')
    
    # Truncate
    sanitized = sanitized[:max_length].strip()
    
    return sanitized
