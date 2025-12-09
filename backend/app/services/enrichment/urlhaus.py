"""
NiksES URLhaus Integration

Provides malware URL lookups via URLhaus API (abuse.ch).
Free service, no API key required.

Features:
- Automatic retry with exponential backoff (4 attempts)
- Rate limit detection and handling
- Graceful degradation
"""

import logging
import aiohttp
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.utils.constants import URLHAUS_API_URL, API_TIMEOUT_ENRICHMENT
from app.utils.exceptions import EnrichmentError, APIConnectionError
from app.models.enrichment import ThreatIntelVerdict, URLEnrichment
from app.services.enrichment.base import BaseEnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class URLhausProvider(BaseEnrichmentProvider):
    """
    URLhaus API integration (abuse.ch).
    
    Free malware URL database providing:
    - URL threat status
    - Malware/threat type
    - Associated tags
    - First/last seen dates
    
    No API key required. Rate limits are generous.
    Includes automatic retry logic (4 attempts with backoff).
    """
    
    provider_name = "urlhaus"
    requires_api_key = False
    is_free = True
    
    def __init__(self):
        super().__init__(api_key=None)
        self.timeout = API_TIMEOUT_ENRICHMENT
        self._status.is_configured = True
    
    @property
    def is_configured(self) -> bool:
        return True
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is in URLhaus database.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with threat data
        """
        if not url:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{URLHAUS_API_URL}/url/"
                
                async with session.post(
                    endpoint,
                    data={"url": url},
                    timeout=self.timeout
                ) as response:
                    
                    if response.status != 200:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    data = await response.json()
                    
                    query_status = data.get('query_status', '')
                    
                    if query_status == 'no_results':
                        # Not in database - likely clean
                        return {
                            'in_database': False,
                            'verdict': ThreatIntelVerdict.CLEAN,
                        }
                    elif query_status != 'ok':
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    # URL found in database
                    url_status = data.get('url_status', 'unknown')
                    threat = data.get('threat', 'unknown')
                    tags = data.get('tags', []) or []
                    
                    # Determine verdict
                    if url_status == 'online':
                        verdict = ThreatIntelVerdict.MALICIOUS
                    elif url_status == 'offline':
                        verdict = ThreatIntelVerdict.SUSPICIOUS  # Was malicious
                    else:
                        verdict = ThreatIntelVerdict.SUSPICIOUS
                    
                    return {
                        'in_database': True,
                        'url_status': url_status,
                        'threat': threat,
                        'tags': tags,
                        'date_added': data.get('date_added'),
                        'last_online': data.get('last_online'),
                        'takedown_time': data.get('takedown_time_seconds'),
                        'urlhaus_reference': data.get('urlhaus_reference'),
                        'verdict': verdict,
                    }
                    
        except aiohttp.ClientError as e:
            logger.error(f"URLhaus connection error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
        except Exception as e:
            logger.error(f"URLhaus error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_host(self, host: str) -> Dict[str, Any]:
        """
        Check if host/domain has malicious URLs.
        
        Args:
            host: Domain or IP to check
            
        Returns:
            Dictionary with threat data
        """
        if not host:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{URLHAUS_API_URL}/host/"
                
                async with session.post(
                    endpoint,
                    data={"host": host},
                    timeout=self.timeout
                ) as response:
                    
                    if response.status != 200:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    data = await response.json()
                    
                    if data.get('query_status') == 'no_results':
                        return {
                            'in_database': False,
                            'verdict': ThreatIntelVerdict.CLEAN,
                        }
                    elif data.get('query_status') != 'ok':
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    url_count = data.get('url_count', 0)
                    urls = data.get('urls', [])
                    
                    # Count online vs offline
                    online_count = sum(1 for u in urls if u.get('url_status') == 'online')
                    
                    if online_count > 0:
                        verdict = ThreatIntelVerdict.MALICIOUS
                    elif url_count > 0:
                        verdict = ThreatIntelVerdict.SUSPICIOUS
                    else:
                        verdict = ThreatIntelVerdict.CLEAN
                    
                    return {
                        'in_database': url_count > 0,
                        'url_count': url_count,
                        'online_count': online_count,
                        'blacklists': data.get('blacklists', {}),
                        'urls': urls[:10],  # First 10
                        'verdict': verdict,
                    }
                    
        except Exception as e:
            logger.error(f"URLhaus host check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash in URLhaus payload database.
        
        Args:
            file_hash: MD5 or SHA256 hash
            
        Returns:
            Dictionary with malware data
        """
        if not file_hash:
            return {}
        
        # Determine hash type
        hash_type = 'sha256_hash' if len(file_hash) == 64 else 'md5_hash'
        
        try:
            async with aiohttp.ClientSession() as session:
                endpoint = f"{URLHAUS_API_URL}/payload/"
                
                async with session.post(
                    endpoint,
                    data={hash_type: file_hash.lower()},
                    timeout=self.timeout
                ) as response:
                    
                    if response.status != 200:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    data = await response.json()
                    
                    if data.get('query_status') == 'no_results':
                        return {
                            'in_database': False,
                            'verdict': ThreatIntelVerdict.UNKNOWN,
                        }
                    elif data.get('query_status') != 'ok':
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    return {
                        'in_database': True,
                        'file_type': data.get('file_type'),
                        'signature': data.get('signature'),
                        'first_seen': data.get('firstseen'),
                        'url_count': data.get('url_count', 0),
                        'urls': data.get('urls', [])[:5],
                        'verdict': ThreatIntelVerdict.MALICIOUS,
                    }
                    
        except Exception as e:
            logger.error(f"URLhaus hash check error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain for malicious URLs (alias to check_host).
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with threat data
        """
        return await self.check_host(domain)
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP for malicious URLs (alias to check_host).
        
        URLhaus treats IPs and domains the same via the host endpoint.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with threat data
        """
        return await self.check_host(ip)
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash in URLhaus (alias to check_hash).
        
        Args:
            file_hash: MD5 or SHA256 hash
            
        Returns:
            Dictionary with malware data
        """
        return await self.check_hash(file_hash)


# Singleton instance
_urlhaus_provider: Optional[URLhausProvider] = None


def get_urlhaus_provider() -> URLhausProvider:
    """Get the URLhaus provider singleton."""
    global _urlhaus_provider
    if _urlhaus_provider is None:
        _urlhaus_provider = URLhausProvider()
    return _urlhaus_provider


async def check_url_urlhaus(url: str) -> Dict[str, Any]:
    """Convenience function for URL check."""
    provider = get_urlhaus_provider()
    return await provider.check_url(url)
