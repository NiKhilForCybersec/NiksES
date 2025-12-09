"""
NiksES URL Extractor

Extract and normalize URLs from email body and HTML content.
"""

import logging
import re
from typing import List, Optional, Set
from urllib.parse import urlparse, parse_qs, urljoin

from app.models.email import ExtractedURL
from app.utils.constants import SHORTENER_DOMAINS

logger = logging.getLogger(__name__)


def extract_urls(body_text: Optional[str], body_html: Optional[str]) -> List[ExtractedURL]:
    """
    Extract all URLs from email body.
    
    Args:
        body_text: Plain text body
        body_html: HTML body
        
    Returns:
        List of ExtractedURL objects
    """
    # TODO: Implement in Session 4
    raise NotImplementedError


def extract_urls_from_text(text: str, source: str = "body_text") -> List[ExtractedURL]:
    """
    Extract URLs from plain text using regex.
    
    Args:
        text: Text to search
        source: Source identifier for tracking
        
    Returns:
        List of ExtractedURL objects
    """
    # TODO: Implement in Session 4
    raise NotImplementedError


def extract_urls_from_html(html: str) -> List[ExtractedURL]:
    """
    Extract URLs from HTML content (href, src attributes).
    
    Args:
        html: HTML content
        
    Returns:
        List of ExtractedURL objects
    """
    # TODO: Implement in Session 4
    raise NotImplementedError


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent comparison.
    
    - Lowercase scheme and domain
    - Remove default ports
    - Sort query parameters
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    # TODO: Implement in Session 4
    raise NotImplementedError


def is_shortened_url(url: str) -> bool:
    """Check if URL is from a URL shortener service."""
    # TODO: Implement in Session 4
    raise NotImplementedError


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    # TODO: Implement in Session 4
    raise NotImplementedError


def _deduplicate_urls(urls: List[ExtractedURL]) -> List[ExtractedURL]:
    """Remove duplicate URLs, keeping first occurrence."""
    # TODO: Implement in Session 4
    raise NotImplementedError
