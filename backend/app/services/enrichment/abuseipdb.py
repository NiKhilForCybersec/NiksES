"""
NiksES AbuseIPDB Integration

Provides IP reputation lookups via AbuseIPDB API.
"""

import logging
import aiohttp
from typing import Optional, Dict, Any, Tuple
from datetime import datetime

from app.utils.constants import (
    ABUSEIPDB_API_URL,
    ABUSEIPDB_RATE_LIMIT_PER_DAY,
    API_TIMEOUT_ENRICHMENT
)
from app.utils.exceptions import (
    EnrichmentError,
    APIConnectionError,
    APIRateLimitError,
    APIAuthenticationError
)
from app.models.enrichment import ThreatIntelVerdict, IPEnrichment
from app.services.enrichment.base import BaseEnrichmentProvider, EnrichmentResult

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(BaseEnrichmentProvider):
    """
    AbuseIPDB API integration.
    
    Provides IP reputation checking with:
    - Abuse confidence score (0-100)
    - Number of reports
    - Categories of abuse
    - ISP/ASN information
    
    Rate limit: 1000 requests/day for free tier.
    Inherits retry logic from BaseEnrichmentProvider.
    """
    
    provider_name = "abuseipdb"
    requires_api_key = True
    is_free = False
    
    # Abuse categories
    CATEGORIES = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted",
    }
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        self._request_count = 0
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        return {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    async def check_ip(self, ip: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """
        Check IP reputation.
        
        Args:
            ip: IP address to check
            max_age_in_days: How far back to look for reports (1-365)
            
        Returns:
            Dictionary with reputation data
        """
        if not self.is_configured:
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': 'API key not configured'}
        
        if not ip:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{ABUSEIPDB_API_URL}/check"
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": str(max_age_in_days),
                    "verbose": ""  # Get additional details
                }
                
                async with session.get(
                    url,
                    headers=self._get_headers(),
                    params=params,
                    timeout=self.timeout
                ) as response:
                    
                    if response.status == 401:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': 'Invalid API key'}
                    elif response.status == 429:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'rate_limited': True, 'error': 'Rate limited'}
                    elif response.status != 200:
                        text = await response.text()
                        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': f'HTTP {response.status}'}
                    
                    data = await response.json()
                    
                    if 'data' not in data:
                        return {'verdict': ThreatIntelVerdict.UNKNOWN}
                    
                    ip_data = data['data']
                    
                    # Determine verdict based on abuse score
                    score = ip_data.get('abuseConfidenceScore', 0)
                    verdict = self._determine_verdict(score)
                    
                    # Map category IDs to names
                    categories = []
                    for cat_id in ip_data.get('categories', []):
                        if cat_id in self.CATEGORIES:
                            categories.append(self.CATEGORIES[cat_id])
                    
                    return {
                        'abuseConfidenceScore': score,
                        'score': score,
                        'total_reports': ip_data.get('totalReports', 0),
                        'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                        'last_reported_at': ip_data.get('lastReportedAt'),
                        'is_whitelisted': ip_data.get('isWhitelisted', False),
                        'country_code': ip_data.get('countryCode'),
                        'isp': ip_data.get('isp'),
                        'domain': ip_data.get('domain'),
                        'usage_type': ip_data.get('usageType'),
                        'is_tor': ip_data.get('isTor', False),
                        'categories': categories,
                        'verdict': verdict,
                    }
                    
        except aiohttp.ClientError as e:
            logger.error(f"AbuseIPDB connection error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': str(e)}
    
    def _determine_verdict(self, score: int) -> ThreatIntelVerdict:
        """
        Determine verdict based on abuse confidence score.
        
        Args:
            score: Abuse confidence score (0-100)
            
        Returns:
            ThreatIntelVerdict
        
        Thresholds:
        - >= 75: Malicious (high confidence of abuse)
        - >= 25: Suspicious (moderate confidence)
        - > 0: Suspicious (some reports)
        - == 0: Clean (no reports)
        """
        if score >= 75:
            return ThreatIntelVerdict.MALICIOUS
        elif score >= 25:
            return ThreatIntelVerdict.SUSPICIOUS
        elif score > 0:
            return ThreatIntelVerdict.SUSPICIOUS
        else:
            return ThreatIntelVerdict.CLEAN
    
    # Required abstract method implementations
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        AbuseIPDB doesn't check URLs directly.
        Returns not supported.
        """
        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': 'URL check not supported by AbuseIPDB'}
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        AbuseIPDB doesn't check domains directly.
        Returns not supported.
        """
        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': 'Domain check not supported by AbuseIPDB'}
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        AbuseIPDB doesn't check file hashes.
        Returns not supported.
        """
        return {'verdict': ThreatIntelVerdict.UNKNOWN, 'error': 'File hash check not supported by AbuseIPDB'}
    
    async def enrich_ip(self, ip: str) -> IPEnrichment:
        """
        Fully enrich an IP with AbuseIPDB data.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            IPEnrichment model
        """
        data = await self.check_ip(ip)
        
        return IPEnrichment(
            ip_address=ip,
            country_code=data.get('country_code'),
            isp=data.get('isp'),
            abuseipdb_score=data.get('score'),
            abuseipdb_reports=data.get('total_reports'),
            abuseipdb_verdict=data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            is_tor=data.get('is_tor', False),
        )
    
    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test if API connection and key are valid.
        
        Returns:
            Tuple of (success, message)
        """
        if not self.is_configured:
            return False, "API key not configured"
        try:
            # Check a known IP (Google DNS)
            result = await self.check_ip("8.8.8.8")
            if 'error' in result and 'Invalid' in result.get('error', ''):
                return False, "Invalid API key"
            return True, "Connection successful"
        except Exception as e:
            logger.error(f"AbuseIPDB connection test failed: {e}")
            return False, str(e)


# Singleton instance
_abuseipdb_provider: Optional[AbuseIPDBProvider] = None


def get_abuseipdb_provider(api_key: Optional[str] = None) -> AbuseIPDBProvider:
    """Get the AbuseIPDB provider singleton."""
    global _abuseipdb_provider
    if _abuseipdb_provider is None or (api_key and _abuseipdb_provider.api_key != api_key):
        _abuseipdb_provider = AbuseIPDBProvider(api_key)
    return _abuseipdb_provider


def configure_abuseipdb(api_key: str) -> None:
    """Configure AbuseIPDB with API key."""
    global _abuseipdb_provider
    _abuseipdb_provider = AbuseIPDBProvider(api_key)
