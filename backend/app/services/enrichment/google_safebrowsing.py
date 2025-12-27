"""
Google Safe Browsing API Integration

Checks URLs against Google's constantly updated lists of unsafe web resources:
- Malware
- Social Engineering (Phishing)
- Unwanted Software
- Potentially Harmful Applications

API Docs: https://developers.google.com/safe-browsing/v4/lookup-api
"""

import logging
import aiohttp
import asyncio
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingClient:
    """
    Client for Google Safe Browsing Lookup API v4.
    
    Features:
    - Check URLs against Google's threat lists
    - Detect malware, phishing, unwanted software
    - Batch URL checking (up to 500 URLs)
    - Real-time threat detection
    """
    
    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    # Threat types to check
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]
    
    # Platform types
    PLATFORM_TYPES = [
        "ANY_PLATFORM",
        "WINDOWS",
        "LINUX",
        "OSX",
        "ANDROID",
        "IOS",
    ]
    
    # Threat entry types
    THREAT_ENTRY_TYPES = ["URL"]
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=15)
        self._session: Optional[aiohttp.ClientSession] = None
    
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a single URL against Safe Browsing.
        
        Args:
            url: The URL to check
        
        Returns:
            Dict with threat information
        """
        results = await self.check_urls([url])
        return results[0] if results else {"url": url, "safe": True, "threats": []}
    
    async def check_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Check multiple URLs against Safe Browsing.
        
        Args:
            urls: List of URLs to check (max 500)
        
        Returns:
            List of threat information for each URL
        """
        if not self.api_key:
            return [{"url": url, "error": "No API key configured", "safe": None} for url in urls]
        
        if not urls:
            return []
        
        # Limit to 500 URLs per request
        urls = urls[:500]
        
        try:
            session = await self._get_session()
            
            # Build request payload
            payload = {
                "client": {
                    "clientId": "nikses-email-security",
                    "clientVersion": "3.0.1",
                },
                "threatInfo": {
                    "threatTypes": self.THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": self.THREAT_ENTRY_TYPES,
                    "threatEntries": [{"url": url} for url in urls],
                },
            }
            
            request_url = f"{self.BASE_URL}?key={self.api_key}"
            
            async with session.post(request_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._process_response(data, urls)
                elif response.status == 400:
                    error_data = await response.json()
                    error_msg = error_data.get("error", {}).get("message", "Bad request")
                    return [{"url": url, "error": error_msg, "safe": None} for url in urls]
                elif response.status == 403:
                    return [{"url": url, "error": "Invalid API key or quota exceeded", "safe": None} for url in urls]
                else:
                    return [{"url": url, "error": f"API error: {response.status}", "safe": None} for url in urls]
        
        except asyncio.TimeoutError:
            logger.warning("Google Safe Browsing timeout")
            return [{"url": url, "error": "Request timeout", "safe": None} for url in urls]
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            return [{"url": url, "error": str(e), "safe": None} for url in urls]
    
    def _process_response(self, data: Dict, urls: List[str]) -> List[Dict[str, Any]]:
        """Process and normalize the API response."""
        # Build a map of URL to threats
        threat_map: Dict[str, List[Dict]] = {url: [] for url in urls}
        
        matches = data.get("matches", [])
        
        for match in matches:
            url = match.get("threat", {}).get("url", "")
            if url in threat_map:
                threat_map[url].append({
                    "threat_type": match.get("threatType", "UNKNOWN"),
                    "platform_type": match.get("platformType", "ANY_PLATFORM"),
                    "threat_entry_type": match.get("threatEntryType", "URL"),
                    "cache_duration": match.get("cacheDuration", ""),
                })
        
        # Build results
        results = []
        for url in urls:
            threats = threat_map.get(url, [])
            
            result = {
                "url": url,
                "safe": len(threats) == 0,
                "checked_at": datetime.utcnow().isoformat(),
                "threats": threats,
                "threat_count": len(threats),
            }
            
            if threats:
                # Determine severity
                threat_types = [t["threat_type"] for t in threats]
                
                if "MALWARE" in threat_types:
                    result["severity"] = "critical"
                    result["primary_threat"] = "malware"
                elif "SOCIAL_ENGINEERING" in threat_types:
                    result["severity"] = "critical"
                    result["primary_threat"] = "phishing"
                elif "POTENTIALLY_HARMFUL_APPLICATION" in threat_types:
                    result["severity"] = "high"
                    result["primary_threat"] = "harmful_app"
                elif "UNWANTED_SOFTWARE" in threat_types:
                    result["severity"] = "medium"
                    result["primary_threat"] = "unwanted_software"
                else:
                    result["severity"] = "medium"
                    result["primary_threat"] = threat_types[0].lower()
                
                # Build verdict
                result["verdict"] = f"UNSAFE: {', '.join(set(threat_types))}"
                result["is_malicious"] = True
            else:
                result["severity"] = "safe"
                result["primary_threat"] = None
                result["verdict"] = "Clean - No threats detected"
                result["is_malicious"] = False
            
            results.append(result)
        
        return results
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get human-readable threat description."""
        descriptions = {
            "MALWARE": "Malicious software that can harm your device",
            "SOCIAL_ENGINEERING": "Phishing or deceptive site trying to steal information",
            "UNWANTED_SOFTWARE": "Software that may affect your browsing experience",
            "POTENTIALLY_HARMFUL_APPLICATION": "Application that may be harmful to your device",
        }
        return descriptions.get(threat_type, "Unknown threat type")


# Singleton instance
_client: Optional[GoogleSafeBrowsingClient] = None


def get_client(api_key: str) -> GoogleSafeBrowsingClient:
    """Get or create Google Safe Browsing client."""
    global _client
    if _client is None or _client.api_key != api_key:
        _client = GoogleSafeBrowsingClient(api_key)
    return _client


async def check_url(url: str, api_key: str) -> Dict[str, Any]:
    """
    Convenience function to check a URL.
    
    Args:
        url: URL to check
        api_key: Google Safe Browsing API key
    
    Returns:
        Threat information
    """
    client = get_client(api_key)
    return await client.check_url(url)


async def check_urls(urls: List[str], api_key: str) -> List[Dict[str, Any]]:
    """
    Convenience function to check multiple URLs.
    
    Args:
        urls: URLs to check
        api_key: Google Safe Browsing API key
    
    Returns:
        List of threat information
    """
    client = get_client(api_key)
    return await client.check_urls(urls)
