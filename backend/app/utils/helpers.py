"""
NiksES Helper Functions

Utility functions used throughout the application.
"""

import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from .constants import SHORTENER_DOMAINS, SUSPICIOUS_TLDS, RISK_THRESHOLDS


# ============================================================================
# ID and Timestamp Generation
# ============================================================================

def generate_analysis_id() -> str:
    """Generate a unique analysis ID."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Format datetime to string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(format_str)


# ============================================================================
# Hash Calculation
# ============================================================================

def calculate_hash(data: bytes, algorithm: str = 'sha256') -> str:
    """
    Calculate hash of data.
    
    Args:
        data: Bytes to hash
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest string
    """
    if algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def calculate_md5(data: bytes) -> str:
    """Calculate MD5 hash of data."""
    return calculate_hash(data, 'md5')


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA256 hash of data."""
    return calculate_hash(data, 'sha256')


# ============================================================================
# Domain and URL Extraction
# ============================================================================

def extract_domain(url_or_email: str) -> Optional[str]:
    """Extract domain from URL or email address."""
    if '@' in url_or_email:
        return extract_domain_from_email(url_or_email)
    return extract_domain_from_url(url_or_email)


def extract_domain_from_email(email: str) -> Optional[str]:
    """Extract domain from email address."""
    if not email or '@' not in email:
        return None
    try:
        return email.split('@')[1].lower().strip()
    except IndexError:
        return None


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    if not url:
        return None
    
    try:
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain if domain else None
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """
    Normalize URL for comparison.
    
    - Lowercase scheme and domain
    - Remove default ports
    - Remove trailing slashes
    - Sort query parameters
    """
    if not url:
        return ""
    
    try:
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        
        # Lowercase scheme and domain
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if ':80' in netloc and scheme == 'http':
            netloc = netloc.replace(':80', '')
        if ':443' in netloc and scheme == 'https':
            netloc = netloc.replace(':443', '')
        
        # Normalize path
        path = parsed.path.rstrip('/') or '/'
        
        # Keep query but remove fragment
        query = parsed.query
        
        # Reconstruct
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        
        return normalized
    except Exception:
        return url.lower()


# ============================================================================
# Defanging (for safe display/sharing)
# ============================================================================

def defang_url(url: str) -> str:
    """
    Defang URL for safe sharing.
    
    hxxp[://]example[.]com
    """
    if not url:
        return ""
    
    defanged = url
    defanged = defanged.replace('http', 'hxxp')
    defanged = defanged.replace('://', '[://]')
    defanged = re.sub(r'\.(?=[a-zA-Z])', '[.]', defanged)
    
    return defanged


def defang_ip(ip: str) -> str:
    """
    Defang IP address for safe sharing.
    
    192[.]168[.]1[.]1
    """
    if not ip:
        return ""
    return ip.replace('.', '[.]')


def refang_url(defanged: str) -> str:
    """Convert defanged URL back to normal."""
    if not defanged:
        return ""
    
    refanged = defanged
    refanged = refanged.replace('hxxp', 'http')
    refanged = refanged.replace('[://]', '://')
    refanged = refanged.replace('[.]', '.')
    
    return refanged


# ============================================================================
# Pattern Extraction
# ============================================================================

# URL pattern
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+|'
    r'www\.[^\s<>"\']+',
    re.IGNORECASE
)

# IP pattern (IPv4)
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Email pattern
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE
)


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    if not text:
        return []
    return URL_PATTERN.findall(text)


def extract_ips(text: str) -> List[str]:
    """Extract all IPv4 addresses from text."""
    if not text:
        return []
    return IP_PATTERN.findall(text)


def extract_emails(text: str) -> List[str]:
    """Extract all email addresses from text."""
    if not text:
        return []
    return EMAIL_PATTERN.findall(text)


# ============================================================================
# Risk Level Calculation
# ============================================================================

def get_risk_level(score: int) -> str:
    """
    Get risk level string from numeric score.
    
    Args:
        score: Risk score 0-100
        
    Returns:
        Risk level string (informational, low, medium, high, critical)
    """
    if score < 0:
        score = 0
    if score > 100:
        score = 100
    
    for level, (min_score, max_score) in RISK_THRESHOLDS.items():
        if min_score <= score <= max_score:
            return level
    
    return "informational"


# ============================================================================
# String Utilities
# ============================================================================

def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string to max length with suffix."""
    if not s or len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def clean_string(s: str) -> str:
    """Clean string of control characters."""
    if not s:
        return ""
    # Remove control characters except newlines and tabs
    return ''.join(c for c in s if c.isprintable() or c in '\n\t')


def is_shortened_url(url: str) -> bool:
    """Check if URL is from a known URL shortener."""
    domain = extract_domain_from_url(url)
    if not domain:
        return False
    return domain in SHORTENER_DOMAINS


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain has a suspicious TLD."""
    if not domain:
        return False
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False


# ============================================================================
# Phone Number Extraction
# ============================================================================

PHONE_PATTERN = re.compile(
    r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}|'
    r'\+[0-9]{1,3}[-.\s]?[0-9]{6,14}'
)


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text."""
    if not text:
        return []
    return PHONE_PATTERN.findall(text)


# ============================================================================
# IP Utilities
# ============================================================================

def is_private_ip(ip: str) -> bool:
    """Check if IP address is private/reserved."""
    if not ip:
        return False
    
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return True
        
        return False
    except (ValueError, AttributeError):
        return False


def is_public_ip(ip: str) -> bool:
    """Check if IP address is public."""
    return not is_private_ip(ip)
