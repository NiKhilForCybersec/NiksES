"""
NiksES PhishTank Integration

Provides phishing URL lookups via PhishTank API.
"""

import logging
import aiohttp
from typing import Optional, Dict, Any
from datetime import datetime
import hashlib

from app.utils.constants import PHISHTANK_API_URL, API_TIMEOUT_ENRICHMENT
from app.utils.exceptions import EnrichmentError, APIConnectionError
from app.models.enrichment import ThreatIntelVerdict

logger = logging.getLogger(__name__)


class PhishTankProvider:
    """
    PhishTank API integration.
    
    Free phishing URL database providing:
    - Verified phishing status
    - Target brand (when available)
    - Verification date
    
    API key is optional but recommended for higher rate limits.
    """
    
    provider_name = "phishtank"
    requires_api_key = False  # Optional
    is_free = True
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = API_TIMEOUT_ENRICHMENT
    
    @property
    def is_configured(self) -> bool:
        return True  # Works without API key
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is in PhishTank database.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with phishing data
        """
        if not url:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                # Build request data
                data = {
                    'url': url,
                    'format': 'json',
                }
                
                # Add API key if available
                if self.api_key:
                    data['app_key'] = self.api_key
                
                async with session.post(
                    PHISHTANK_API_URL,
                    data=data,
                    timeout=self.timeout
                ) as response:
                    
                    if response.status != 200:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    result = await response.json()
                    
                    if 'results' not in result:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    results = result['results']
                    
                    in_database = results.get('in_database', False)
                    
                    if not in_database:
                        return {
                            'in_database': False,
                            'verdict': ThreatIntelVerdict.CLEAN,
                        }
                    
                    # URL is in database
                    verified = results.get('verified', False)
                    verified_at = results.get('verified_at')
                    
                    if verified:
                        verdict = ThreatIntelVerdict.MALICIOUS
                    else:
                        verdict = ThreatIntelVerdict.SUSPICIOUS
                    
                    return {
                        'in_database': True,
                        'phish_id': results.get('phish_id'),
                        'verified': verified,
                        'verified_at': verified_at,
                        'valid': results.get('valid', False),
                        'phish_detail_url': results.get('phish_detail_url'),
                        'verdict': verdict,
                    }
                    
        except aiohttp.ClientError as e:
            logger.error(f"PhishTank connection error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
        except Exception as e:
            logger.error(f"PhishTank error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    async def check_url_hash(self, url: str) -> Dict[str, Any]:
        """
        Check URL by SHA256 hash (alternative method).
        
        Some implementations prefer hash-based lookups.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with phishing data
        """
        if not url:
            return {}
        
        # Normalize and hash URL
        normalized_url = url.lower().strip()
        url_hash = hashlib.sha256(normalized_url.encode()).hexdigest()
        
        # PhishTank API doesn't directly support hash lookup
        # Fall back to regular check
        return await self.check_url(url)
    
    def _parse_verified_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse PhishTank date format."""
        if not date_str:
            return None
        
        try:
            # PhishTank format: "2024-01-15T12:30:00+00:00"
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except ValueError:
            return None


# Singleton instance
_phishtank_provider: Optional[PhishTankProvider] = None


def get_phishtank_provider(api_key: Optional[str] = None) -> PhishTankProvider:
    """Get the PhishTank provider singleton."""
    global _phishtank_provider
    if _phishtank_provider is None or (api_key and _phishtank_provider.api_key != api_key):
        _phishtank_provider = PhishTankProvider(api_key)
    return _phishtank_provider


async def check_url_phishtank(url: str) -> Dict[str, Any]:
    """Convenience function for URL check."""
    provider = get_phishtank_provider()
    return await provider.check_url(url)
