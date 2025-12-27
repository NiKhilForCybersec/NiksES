"""
NiksES GeoIP Lookup

Provides IP geolocation using ip-api.com (free tier).
"""

import logging
import aiohttp
from typing import Optional, Dict, Any

from app.utils.constants import GEOIP_API_URL, API_TIMEOUT_ENRICHMENT, GEOIP_RATE_LIMIT_PER_MINUTE
from app.utils.exceptions import EnrichmentError, APIConnectionError, APIRateLimitError
from app.models.enrichment import IPEnrichment, ThreatIntelVerdict

logger = logging.getLogger(__name__)


class GeoIPProvider:
    """
    GeoIP lookup using ip-api.com free API.
    
    Rate limit: 45 requests per minute for free tier.
    No API key required for basic usage.
    """
    
    provider_name = "geoip"
    requires_api_key = False
    is_free = True
    
    def __init__(self):
        self.timeout = API_TIMEOUT_ENRICHMENT
        self._request_count = 0
    
    @property
    def is_configured(self) -> bool:
        return True  # No API key needed
    
    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup IP geolocation.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with geolocation data
        """
        if not ip:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{GEOIP_API_URL}/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"
                
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 429:
                        raise APIRateLimitError("GeoIP rate limit exceeded")
                    
                    data = await response.json()
                    
                    if data.get('status') == 'fail':
                        logger.warning(f"GeoIP lookup failed for {ip}: {data.get('message')}")
                        return {}
                    
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'asn': self._parse_asn(data.get('as', '')),
                        'as_org': data.get('asname'),
                        'is_mobile': data.get('mobile', False),
                        'is_proxy': data.get('proxy', False),
                        'is_datacenter': data.get('hosting', False),
                    }
                    
        except aiohttp.ClientError as e:
            logger.error(f"GeoIP connection error: {e}")
            raise APIConnectionError(f"GeoIP lookup failed: {str(e)}")
        except Exception as e:
            logger.error(f"GeoIP error: {e}")
            return {}
    
    def _parse_asn(self, as_string: str) -> Optional[int]:
        """Extract ASN number from AS string like 'AS15169 Google LLC'."""
        if not as_string:
            return None
        try:
            # Format: "AS15169 Google LLC"
            parts = as_string.split()
            if parts and parts[0].startswith('AS'):
                return int(parts[0][2:])
        except (ValueError, IndexError):
            pass
        return None
    
    async def enrich_ip(self, ip: str) -> IPEnrichment:
        """
        Fully enrich an IP address with geolocation.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            IPEnrichment model
        """
        geo_data = await self.lookup_ip(ip)
        
        return IPEnrichment(
            ip_address=ip,
            country=geo_data.get('country'),
            country_code=geo_data.get('country_code'),
            city=geo_data.get('city'),
            region=geo_data.get('region'),
            asn=geo_data.get('asn'),
            as_org=geo_data.get('as_org'),
            isp=geo_data.get('isp'),
            is_proxy=geo_data.get('is_proxy', False),
            is_datacenter=geo_data.get('is_datacenter', False),
        )


# Singleton instance
_geoip_provider: Optional[GeoIPProvider] = None


def get_geoip_provider() -> GeoIPProvider:
    """Get the GeoIP provider singleton."""
    global _geoip_provider
    if _geoip_provider is None:
        _geoip_provider = GeoIPProvider()
    return _geoip_provider


async def lookup_ip(ip: str) -> Dict[str, Any]:
    """Convenience function for IP lookup."""
    provider = get_geoip_provider()
    return await provider.lookup_ip(ip)
