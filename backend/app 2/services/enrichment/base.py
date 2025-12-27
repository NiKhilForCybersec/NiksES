"""
NiksES Base Enrichment Provider

Abstract base class for all threat intelligence providers.
Includes retry logic with exponential backoff and API status tracking.
"""

import logging
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import Optional, Any, Dict, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from app.utils.constants import API_TIMEOUT_ENRICHMENT

logger = logging.getLogger(__name__)


class APIStatus(str, Enum):
    """API availability status."""
    AVAILABLE = "available"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    UNCONFIGURED = "unconfigured"
    UNKNOWN = "unknown"


@dataclass
class APIStatusInfo:
    """Tracks API status and usage."""
    provider_name: str
    status: APIStatus = APIStatus.UNKNOWN
    last_success: Optional[datetime] = None
    last_error: Optional[datetime] = None
    last_error_message: Optional[str] = None
    requests_made: int = 0
    requests_failed: int = 0
    rate_limit_reset: Optional[datetime] = None
    is_configured: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "status": self.status.value,
            "is_configured": self.is_configured,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_error": self.last_error.isoformat() if self.last_error else None,
            "last_error_message": self.last_error_message,
            "requests_made": self.requests_made,
            "requests_failed": self.requests_failed,
            "rate_limit_reset": self.rate_limit_reset.isoformat() if self.rate_limit_reset else None,
        }


@dataclass
class EnrichmentResult:
    """Result from an enrichment API call."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    provider: str = ""
    attempts: int = 1
    was_rate_limited: bool = False
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "provider": self.provider,
            "attempts": self.attempts,
            "was_rate_limited": self.was_rate_limited,
            "cached": self.cached,
        }


class BaseEnrichmentProvider(ABC):
    """
    Abstract base class for threat intelligence providers.
    
    Features:
    - Automatic retry with exponential backoff (4 attempts)
    - Rate limit detection and handling
    - API status tracking
    - Graceful degradation on failures
    
    All enrichment providers must inherit from this class.
    """
    
    # Provider identification
    provider_name: str = "base"
    requires_api_key: bool = True
    is_free: bool = False
    
    # Retry configuration - 4 retries with exponential backoff
    MAX_RETRIES: int = 4
    INITIAL_BACKOFF: float = 1.0  # seconds
    MAX_BACKOFF: float = 15.0  # seconds (reduced from 30 for faster fallback)
    BACKOFF_MULTIPLIER: float = 2.0
    
    # Rate limit detection patterns
    RATE_LIMIT_STATUS_CODES = {429, 503}
    RATE_LIMIT_MESSAGES = ["rate limit", "too many requests", "quota exceeded", "limit exceeded"]
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize provider.
        
        Args:
            api_key: API key for the service (if required)
        """
        self.api_key = api_key
        self.timeout = API_TIMEOUT_ENRICHMENT
        self._status = APIStatusInfo(provider_name=self.provider_name)
        self._status.is_configured = self.is_configured
        
    @property
    def is_configured(self) -> bool:
        """Check if provider is properly configured."""
        if not self.requires_api_key:
            return True
        return self.api_key is not None and len(self.api_key) > 0
    
    @property
    def status(self) -> APIStatusInfo:
        """Get current API status."""
        return self._status
    
    def _is_rate_limited(self) -> bool:
        """Check if we're currently rate limited."""
        if self._status.status != APIStatus.RATE_LIMITED:
            return False
        if self._status.rate_limit_reset and datetime.utcnow() > self._status.rate_limit_reset:
            self._status.status = APIStatus.AVAILABLE
            return False
        return True
    
    def _detect_rate_limit(self, status_code: int, response_text: str) -> bool:
        """Detect if response indicates rate limiting."""
        if status_code in self.RATE_LIMIT_STATUS_CODES:
            return True
        response_lower = response_text.lower()
        return any(msg in response_lower for msg in self.RATE_LIMIT_MESSAGES)
    
    def _record_success(self) -> None:
        """Record a successful API call."""
        self._status.last_success = datetime.utcnow()
        self._status.requests_made += 1
        self._status.status = APIStatus.AVAILABLE
    
    def _record_failure(self, error_msg: str, is_rate_limit: bool = False) -> None:
        """Record a failed API call."""
        self._status.last_error = datetime.utcnow()
        self._status.last_error_message = error_msg
        self._status.requests_failed += 1
        
        if is_rate_limit:
            self._status.status = APIStatus.RATE_LIMITED
            # Assume rate limit resets in 60 seconds if not specified
            self._status.rate_limit_reset = datetime.utcnow() + timedelta(seconds=60)
        else:
            self._status.status = APIStatus.ERROR
    
    async def _execute_with_retry(
        self,
        operation: str,
        func,
        *args,
        **kwargs
    ) -> EnrichmentResult:
        """
        Execute an API call with retry logic (4 attempts).
        
        After 4 failed attempts, returns a failure result and 
        allows the analysis to continue with other available data.
        
        Args:
            operation: Description of the operation (for logging)
            func: Async function to call
            *args, **kwargs: Arguments to pass to func
            
        Returns:
            EnrichmentResult with success/failure data
        """
        if not self.is_configured:
            return EnrichmentResult(
                success=False,
                error=f"{self.provider_name} API key not configured",
                provider=self.provider_name,
                attempts=0,
            )
        
        if self._is_rate_limited():
            reset_time = self._status.rate_limit_reset
            return EnrichmentResult(
                success=False,
                error=f"{self.provider_name} is rate limited. Resets at {reset_time}",
                provider=self.provider_name,
                attempts=0,
                was_rate_limited=True,
            )
        
        last_error = None
        backoff = self.INITIAL_BACKOFF
        
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                logger.info(f"{self.provider_name}: {operation} (attempt {attempt}/{self.MAX_RETRIES})")
                
                result = await func(*args, **kwargs)
                
                # Check for rate limit in result
                if isinstance(result, dict):
                    if result.get("rate_limited"):
                        self._record_failure("Rate limited", is_rate_limit=True)
                        last_error = "Rate limited"
                        
                        if attempt < self.MAX_RETRIES:
                            logger.warning(f"{self.provider_name}: Rate limited, retrying in {backoff}s...")
                            await asyncio.sleep(backoff)
                            backoff = min(backoff * self.BACKOFF_MULTIPLIER, self.MAX_BACKOFF)
                            continue
                        else:
                            logger.error(f"{self.provider_name}: Rate limited after {attempt} attempts, moving on")
                            return EnrichmentResult(
                                success=False,
                                error=f"{self.provider_name} rate limited after {attempt} attempts",
                                provider=self.provider_name,
                                attempts=attempt,
                                was_rate_limited=True,
                            )
                
                # Success!
                self._record_success()
                logger.info(f"{self.provider_name}: {operation} succeeded on attempt {attempt}")
                return EnrichmentResult(
                    success=True,
                    data=result if isinstance(result, dict) else {"result": result},
                    provider=self.provider_name,
                    attempts=attempt,
                )
                
            except aiohttp.ClientResponseError as e:
                is_rate_limit = self._detect_rate_limit(e.status, str(e.message))
                self._record_failure(str(e), is_rate_limit=is_rate_limit)
                last_error = str(e)
                
                if is_rate_limit:
                    logger.warning(f"{self.provider_name}: Rate limited on attempt {attempt}")
                else:
                    logger.warning(f"{self.provider_name}: HTTP {e.status} on attempt {attempt}")
                
            except asyncio.TimeoutError:
                self._record_failure("Request timed out")
                last_error = "Request timed out"
                logger.warning(f"{self.provider_name}: Timeout on attempt {attempt}/{self.MAX_RETRIES}")
                
            except aiohttp.ClientError as e:
                self._record_failure(str(e))
                last_error = f"Connection error: {str(e)}"
                logger.warning(f"{self.provider_name}: Connection error on attempt {attempt}: {e}")
                
            except Exception as e:
                self._record_failure(str(e))
                last_error = str(e)
                logger.warning(f"{self.provider_name}: Error on attempt {attempt}: {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < self.MAX_RETRIES:
                logger.info(f"{self.provider_name}: Waiting {backoff}s before retry {attempt + 1}...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * self.BACKOFF_MULTIPLIER, self.MAX_BACKOFF)
        
        # All retries exhausted - log and move on
        logger.error(f"{self.provider_name}: Failed after {self.MAX_RETRIES} attempts ({last_error}), continuing without this source")
        return EnrichmentResult(
            success=False,
            error=f"{self.provider_name} failed after {self.MAX_RETRIES} attempts: {last_error}",
            provider=self.provider_name,
            attempts=self.MAX_RETRIES,
            was_rate_limited=self._status.status == APIStatus.RATE_LIMITED,
        )
    
    @abstractmethod
    async def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL reputation."""
        pass
    
    @abstractmethod
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation."""
        pass
    
    @abstractmethod
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation."""
        pass
    
    @abstractmethod
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash reputation."""
        pass
    
    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test if provider connection is working.
        
        Returns:
            Tuple of (success, message)
        """
        if not self.is_configured:
            return False, "API key not configured"
        
        try:
            # Try a simple lookup to verify connection
            result = await self.check_domain("google.com")
            if result:
                return True, "Connection successful"
            return False, "No response from API"
        except Exception as e:
            return False, str(e)
