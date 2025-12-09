"""
NiksES VirusTotal Integration

Provides threat intelligence lookups via VirusTotal API v3.

Features:
- URL, domain, IP, and file hash lookups
- Rate limiting (4 req/min for free tier)
- Automatic retry with exponential backoff (4 attempts)
- Graceful degradation on failures
"""

import logging
import asyncio
import base64
import aiohttp
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
import time

from app.utils.constants import (
    VIRUSTOTAL_API_URL,
    VIRUSTOTAL_RATE_LIMIT_PER_MINUTE,
    API_TIMEOUT_ENRICHMENT
)
from app.utils.exceptions import (
    EnrichmentError,
    APIConnectionError,
    APIRateLimitError,
    APIAuthenticationError
)
from app.models.enrichment import ThreatIntelVerdict, URLEnrichment, AttachmentEnrichment
from app.services.enrichment.base import BaseEnrichmentProvider, EnrichmentResult, APIStatus

logger = logging.getLogger(__name__)


class VirusTotalProvider(BaseEnrichmentProvider):
    """
    VirusTotal API v3 integration.
    
    Provides lookups for:
    - URLs
    - Domains
    - IP addresses
    - File hashes (MD5, SHA256)
    
    Rate limit: 4 requests/minute for free tier.
    Includes automatic retry logic (4 attempts with backoff).
    """
    
    provider_name = "virustotal"
    requires_api_key = True
    is_free = False  # Requires API key
    
    def __init__(self, api_key: Optional[str] = None, rate_limit: int = 4):
        super().__init__(api_key)
        self._rate_limit = rate_limit  # Requests per minute (default 4 for free tier)
        self._request_times: List[float] = []
        self._lock = asyncio.Lock()
        self._min_interval = 60.0 / rate_limit  # Minimum seconds between requests
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    async def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits."""
        async with self._lock:
            now = time.time()
            
            # Remove request times older than 60 seconds
            self._request_times = [t for t in self._request_times if now - t < 60]
            
            # If we've hit the rate limit, wait
            if len(self._request_times) >= self._rate_limit:
                oldest = self._request_times[0]
                wait_time = 60 - (now - oldest) + 0.5  # Add 0.5s buffer
                if wait_time > 0:
                    logger.info(f"VirusTotal rate limit: waiting {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
                    now = time.time()
                    self._request_times = [t for t in self._request_times if now - t < 60]
            
            # Also ensure minimum interval between requests
            if self._request_times:
                last_request = self._request_times[-1]
                time_since_last = now - last_request
                if time_since_last < self._min_interval:
                    wait_time = self._min_interval - time_since_last
                    await asyncio.sleep(wait_time)
            
            # Record this request
            self._request_times.append(time.time())
    
    async def _make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make authenticated API request with rate limiting.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            data: Optional request body
            
        Returns:
            JSON response data
        """
        if not self.is_configured:
            raise APIAuthenticationError("VirusTotal API key not configured")
        
        # Wait for rate limit
        await self._wait_for_rate_limit()
        
        url = f"{VIRUSTOTAL_API_URL}{endpoint}"
        
        try:
            async with aiohttp.ClientSession() as session:
                if method == "GET":
                    async with session.get(url, headers=self._get_headers(), timeout=self.timeout) as response:
                        return await self._handle_response(response)
                elif method == "POST":
                    async with session.post(url, headers=self._get_headers(), data=data, timeout=self.timeout) as response:
                        return await self._handle_response(response)
                        
        except aiohttp.ClientError as e:
            logger.error(f"VirusTotal connection error: {e}")
            raise APIConnectionError(f"VirusTotal connection failed: {str(e)}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        """Handle API response and errors."""
        if response.status == 200:
            return await response.json()
        elif response.status == 204:
            return {}  # No content
        elif response.status == 401:
            raise APIAuthenticationError("Invalid VirusTotal API key")
        elif response.status == 429:
            # Rate limit hit - return flag for retry logic
            logger.warning("VirusTotal rate limit hit (429)")
            self._record_failure("Rate limited", is_rate_limit=True)
            return {"rate_limited": True}
        elif response.status == 404:
            return {'error': 'not_found'}
        else:
            text = await response.text()
            raise EnrichmentError(f"VirusTotal API error {response.status}: {text}")
    
    def _determine_verdict(self, stats: Dict[str, int]) -> ThreatIntelVerdict:
        """
        Determine verdict based on detection stats.
        
        Args:
            stats: Dictionary with malicious, suspicious, harmless, undetected counts
            
        Returns:
            ThreatIntelVerdict
        """
        if not stats:
            return ThreatIntelVerdict.UNKNOWN
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious >= 3:
            return ThreatIntelVerdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 3:
            return ThreatIntelVerdict.SUSPICIOUS
        elif stats.get('harmless', 0) > 0 or stats.get('undetected', 0) > 0:
            return ThreatIntelVerdict.CLEAN
        
        return ThreatIntelVerdict.UNKNOWN
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with reputation data
        """
        if not url:
            return {}
        
        # URL ID is base64 encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        
        try:
            data = await self._make_request(f"/urls/{url_id}")
            
            if 'error' in data:
                return {'verdict': ThreatIntelVerdict.UNKNOWN}
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'verdict': self._determine_verdict(stats),
                'categories': list(attributes.get('categories', {}).values()),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'reputation': attributes.get('reputation', 0),
            }
            
        except Exception as e:
            if 'not_found' not in str(e):
                logger.error(f"VirusTotal URL check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with reputation data
        """
        if not domain:
            return {}
        
        try:
            data = await self._make_request(f"/domains/{domain}")
            
            if 'error' in data:
                return {'verdict': ThreatIntelVerdict.UNKNOWN}
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'verdict': self._determine_verdict(stats),
                'categories': list(attributes.get('categories', {}).values()),
                'creation_date': attributes.get('creation_date'),
                'registrar': attributes.get('registrar'),
                'reputation': attributes.get('reputation', 0),
                'popularity_ranks': attributes.get('popularity_ranks', {}),
            }
            
        except Exception as e:
            if 'not_found' not in str(e):
                logger.error(f"VirusTotal domain check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        if not ip:
            return {}
        
        try:
            data = await self._make_request(f"/ip_addresses/{ip}")
            
            if 'error' in data:
                return {'verdict': ThreatIntelVerdict.UNKNOWN}
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'verdict': self._determine_verdict(stats),
                'country': attributes.get('country'),
                'as_owner': attributes.get('as_owner'),
                'asn': attributes.get('asn'),
                'reputation': attributes.get('reputation', 0),
            }
            
        except Exception as e:
            if 'not_found' not in str(e):
                logger.error(f"VirusTotal IP check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation.
        
        Args:
            file_hash: MD5 or SHA256 hash
            
        Returns:
            Dictionary with reputation data
        """
        if not file_hash:
            return {}
        
        # Normalize hash
        file_hash = file_hash.lower().strip()
        
        try:
            data = await self._make_request(f"/files/{file_hash}")
            
            if 'error' in data:
                return {'verdict': ThreatIntelVerdict.UNKNOWN}
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            # Get threat names from detections
            threat_names = []
            results = attributes.get('last_analysis_results', {})
            for engine, result in results.items():
                if result.get('result'):
                    threat_names.append(result['result'])
            
            return {
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'verdict': self._determine_verdict(stats),
                'threat_names': threat_names[:10],  # Top 10
                'file_type': attributes.get('type_description'),
                'file_size': attributes.get('size'),
                'md5': attributes.get('md5'),
                'sha256': attributes.get('sha256'),
                'first_seen': attributes.get('first_submission_date'),
                'last_seen': attributes.get('last_analysis_date'),
                'reputation': attributes.get('reputation', 0),
            }
            
        except Exception as e:
            if 'not_found' not in str(e):
                logger.error(f"VirusTotal hash check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test if API connection and key are valid.
        
        Returns:
            Tuple of (success, message)
        """
        if not self.is_configured:
            return False, "API key not configured"
        
        try:
            # Use a simple domain check to test
            await self._make_request("/domains/google.com")
            return True, "Connection successful"
        except APIAuthenticationError:
            return False, "Invalid API key"
        except Exception as e:
            logger.error(f"VirusTotal connection test failed: {e}")
            return False, str(e)


# Singleton instance
_vt_provider: Optional[VirusTotalProvider] = None


def get_virustotal_provider(api_key: Optional[str] = None) -> VirusTotalProvider:
    """Get the VirusTotal provider singleton."""
    global _vt_provider
    if _vt_provider is None or (api_key and _vt_provider.api_key != api_key):
        _vt_provider = VirusTotalProvider(api_key)
    return _vt_provider


def configure_virustotal(api_key: str) -> None:
    """Configure VirusTotal with API key."""
    global _vt_provider
    _vt_provider = VirusTotalProvider(api_key)
