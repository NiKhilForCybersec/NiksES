"""
NiksES Input Validators

Functions for validating user inputs and data.
"""

import re
from typing import Optional, Tuple, BinaryIO, List
from pathlib import Path

from .constants import (
    MAX_EMAIL_SIZE_BYTES,
    MAX_ATTACHMENT_SIZE_BYTES,
    ALLOWED_UPLOAD_EXTENSIONS,
)
from .exceptions import ValidationError


# ============================================================================
# Regular Expression Patterns
# ============================================================================

# Email pattern (RFC 5322 simplified)
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    re.IGNORECASE
)

# Domain pattern
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    re.IGNORECASE
)

# IPv4 pattern
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# IPv6 pattern (simplified)
IPV6_REGEX = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
    r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$',
    re.IGNORECASE
)

# URL pattern
URL_REGEX = re.compile(
    r'^https?://[^\s<>"\']+$',
    re.IGNORECASE
)

# MD5 hash pattern
MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')

# SHA256 hash pattern
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

# SHA1 hash pattern
SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')


# ============================================================================
# File Validation
# ============================================================================

def validate_file_upload(
    content: bytes,
    filename: str,
    max_size: int = MAX_EMAIL_SIZE_BYTES,
    allowed_extensions: List[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Validate uploaded file.
    
    Args:
        content: File content as bytes
        filename: Original filename
        max_size: Maximum allowed size in bytes
        allowed_extensions: List of allowed extensions (default: .eml, .msg)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if allowed_extensions is None:
        allowed_extensions = ALLOWED_UPLOAD_EXTENSIONS
    
    # Check size
    if len(content) > max_size:
        return False, f"File size exceeds maximum of {max_size // (1024*1024)}MB"
    
    # Check extension
    ext = Path(filename).suffix.lower()
    if ext not in allowed_extensions:
        return False, f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
    
    # Basic content validation
    if len(content) == 0:
        return False, "File is empty"
    
    return True, None


def validate_file_size(size_bytes: int, max_bytes: int = MAX_EMAIL_SIZE_BYTES) -> bool:
    """Validate file size is within limits."""
    return 0 < size_bytes <= max_bytes


def validate_file_extension(filename: str, allowed: List[str] = None) -> bool:
    """Validate file has allowed extension."""
    if allowed is None:
        allowed = ALLOWED_UPLOAD_EXTENSIONS
    ext = Path(filename).suffix.lower()
    return ext in allowed


# ============================================================================
# Email and Domain Validation
# ============================================================================

def validate_email_address(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid format
    """
    if not email or not isinstance(email, str):
        return False
    
    email = email.strip()
    
    # Check length
    if len(email) > 254:
        return False
    
    # Check format
    return bool(EMAIL_REGEX.match(email))


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid format
    """
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.strip().lower()
    
    # Check length
    if len(domain) > 253:
        return False
    
    # Check format
    return bool(DOMAIN_REGEX.match(domain))


# ============================================================================
# IP Address Validation
# ============================================================================

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid format
    """
    if not ip or not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    
    return bool(IPV4_REGEX.match(ip) or IPV6_REGEX.match(ip))


def validate_ipv4(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not ip:
        return False
    return bool(IPV4_REGEX.match(ip.strip()))


def validate_ipv6(ip: str) -> bool:
    """Validate IPv6 address format."""
    if not ip:
        return False
    return bool(IPV6_REGEX.match(ip.strip()))


# ============================================================================
# URL Validation
# ============================================================================

def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid format
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    
    return bool(URL_REGEX.match(url))


# ============================================================================
# Hash Validation
# ============================================================================

def validate_md5(hash_str: str) -> bool:
    """Validate MD5 hash format."""
    if not hash_str:
        return False
    return bool(MD5_REGEX.match(hash_str.strip()))


def validate_sha256(hash_str: str) -> bool:
    """Validate SHA256 hash format."""
    if not hash_str:
        return False
    return bool(SHA256_REGEX.match(hash_str.strip()))


def validate_sha1(hash_str: str) -> bool:
    """Validate SHA1 hash format."""
    if not hash_str:
        return False
    return bool(SHA1_REGEX.match(hash_str.strip()))


def validate_hash(hash_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate hash and determine type.
    
    Returns:
        Tuple of (is_valid, hash_type or None)
    """
    if not hash_str:
        return False, None
    
    hash_str = hash_str.strip()
    
    if validate_md5(hash_str):
        return True, 'md5'
    if validate_sha1(hash_str):
        return True, 'sha1'
    if validate_sha256(hash_str):
        return True, 'sha256'
    
    return False, None


# ============================================================================
# Raw Email Validation
# ============================================================================

def validate_raw_email(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validate raw email content (pasted text).
    
    Args:
        content: Raw email text
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not content or not isinstance(content, str):
        return False, "No content provided"
    
    content = content.strip()
    
    if len(content) < 50:
        return False, "Content too short to be a valid email"
    
    # Check for basic email headers
    required_headers = ['from:', 'to:', 'subject:', 'date:']
    content_lower = content.lower()
    
    has_header = any(header in content_lower for header in required_headers)
    if not has_header:
        return False, "No email headers found"
    
    return True, None


# ============================================================================
# Sanitization Functions
# ============================================================================

def sanitize_string(s: str, max_length: int = 1000) -> str:
    """
    Sanitize string for safe storage/display.
    
    - Remove control characters
    - Limit length
    - Strip whitespace
    """
    if not s:
        return ""
    
    # Remove control characters except newlines and tabs
    sanitized = ''.join(c for c in s if c.isprintable() or c in '\n\t')
    
    # Strip and limit length
    sanitized = sanitized.strip()[:max_length]
    
    return sanitized


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage.
    
    - Remove path components
    - Remove dangerous characters
    - Limit length
    """
    if not filename:
        return "unnamed"
    
    # Get just the filename, no path
    filename = Path(filename).name
    
    # Remove dangerous characters
    dangerous_chars = '<>:"/\\|?*\x00'
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        name = Path(filename).stem[:200]
        ext = Path(filename).suffix[:50]
        filename = name + ext
    
    return filename or "unnamed"


def sanitize_html(html: str) -> str:
    """
    Basic HTML sanitization (remove script tags).
    
    For full sanitization, use bleach library.
    """
    if not html:
        return ""
    
    # Remove script tags
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove on* event handlers
    html = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
    
    return html
