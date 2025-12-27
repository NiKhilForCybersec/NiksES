"""
IPQualityScore API Integration

Provides comprehensive URL and IP reputation data including:
- Phishing detection
- Malware detection
- Suspicious URL patterns
- Domain age and reputation
- Risk scoring

API Docs: https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
"""

import logging
import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from urllib.parse import quote_plus
from datetime import datetime

logger = logging.getLogger(__name__)


class IPQualityScoreClient:
    """
    Client for IPQualityScore Malicious URL Scanner API.
    
    Features:
    - Real-time URL scanning
    - Phishing detection
    - Malware detection
    - Domain reputation
    - Risk scoring (0-100)
    """
    
    BASE_URL = "https://www.ipqualityscore.com/api/json/url"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=45)
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
    
    async def scan_url(self, url: str, strictness: int = 2) -> Dict[str, Any]:
        """
        Scan a URL for threats.
        
        Args:
            url: The URL to scan
            strictness: 0-2 (0=low, 1=medium, 2=high sensitivity)
                       Default is 2 (high) for maximum phishing detection
        
        Returns:
            Dict with scan results including risk_score, phishing, malware, etc.
        """
        if not self.api_key:
            logger.warning("IPQualityScore: No API key configured")
            return {"error": "No API key configured", "success": False}
        
        try:
            # URL encode the target URL
            encoded_url = quote_plus(url)
            
            # Build request URL
            request_url = f"{self.BASE_URL}/{self.api_key}/{encoded_url}"
            
            params = {
                "strictness": strictness,
                "fast": "false",  # Full scan for better accuracy
            }
            
            logger.info(f"IPQualityScore: Scanning URL {url} with strictness={strictness}")
            
            # Use context manager to ensure session is closed
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(request_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = self._process_response(data, url)
                        logger.info(f"IPQualityScore: URL {url} -> risk_score={result.get('risk_score')}, phishing={result.get('is_phishing')}, malware={result.get('is_malware')}")
                        return result
                    elif response.status == 402:
                        logger.error("IPQualityScore: API quota exceeded")
                        return {"error": "API quota exceeded", "success": False}
                    elif response.status == 403:
                        logger.error("IPQualityScore: Invalid API key")
                        return {"error": "Invalid API key", "success": False}
                    else:
                        logger.error(f"IPQualityScore: API error {response.status}")
                        return {"error": f"API error: {response.status}", "success": False}
        
        except asyncio.TimeoutError:
            logger.warning(f"IPQualityScore timeout for URL: {url}")
            return {"error": "Request timeout", "success": False}
        except Exception as e:
            logger.error(f"IPQualityScore error: {e}")
            return {"error": str(e), "success": False}
    
    def _process_response(self, data: Dict, url: str) -> Dict[str, Any]:
        """Process and normalize the API response."""
        if not data.get("success", False):
            return {
                "success": False,
                "error": data.get("message", "Unknown error"),
                "url": url,
            }
        
        # Extract key fields
        result = {
            "success": True,
            "url": url,
            "scanned_at": datetime.utcnow().isoformat(),
            
            # Risk assessment
            "risk_score": data.get("risk_score", 0),
            "is_malicious": data.get("risk_score", 0) >= 75,
            "is_suspicious": data.get("suspicious", False),
            "is_phishing": data.get("phishing", False),
            "is_malware": data.get("malware", False),
            
            # Additional flags
            "is_parking": data.get("parking", False),
            "is_spamming": data.get("spamming", False),
            "is_adult": data.get("adult", False),
            
            # Domain info
            "domain": data.get("domain", ""),
            "domain_rank": data.get("domain_rank", 0),
            "domain_age": data.get("domain_age", {}),
            "dns_valid": data.get("dns_valid", True),
            
            # Categories
            "category": data.get("category", "unknown"),
            "content_type": data.get("content_type", ""),
            
            # Server info
            "server": data.get("server", ""),
            "ip_address": data.get("ip_address", ""),
            "country_code": data.get("country_code", ""),
            
            # URL characteristics
            "redirected": data.get("redirected", False),
            "final_url": data.get("final_url", url),
            "page_size": data.get("page_size", 0),
            
            # Raw response for detailed analysis
            "raw_response": data,
        }
        
        # Calculate threat level
        risk_score = result["risk_score"]
        if risk_score >= 85:
            result["threat_level"] = "critical"
        elif risk_score >= 75:
            result["threat_level"] = "high"
        elif risk_score >= 50:
            result["threat_level"] = "medium"
        elif risk_score >= 25:
            result["threat_level"] = "low"
        else:
            result["threat_level"] = "safe"
        
        # Build verdict
        threats = []
        if result["is_phishing"]:
            threats.append("phishing")
        if result["is_malware"]:
            threats.append("malware")
        if result["is_suspicious"]:
            threats.append("suspicious")
        if result["is_spamming"]:
            threats.append("spam")
        
        if threats:
            result["verdict"] = f"Detected: {', '.join(threats)}"
        elif risk_score >= 50:
            result["verdict"] = f"Risky (score: {risk_score})"
        else:
            result["verdict"] = "Clean"
        
        return result
    
    async def scan_urls_batch(self, urls: List[str], strictness: int = 1) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs concurrently.
        
        Args:
            urls: List of URLs to scan
            strictness: Scanning strictness level
        
        Returns:
            List of scan results
        """
        tasks = [self.scan_url(url, strictness) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed = []
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                processed.append({
                    "success": False,
                    "url": url,
                    "error": str(result),
                })
            else:
                processed.append(result)
        
        return processed
    
    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation.
        
        Args:
            ip_address: IP to check
        
        Returns:
            Dict with IP reputation data
        """
        if not self.api_key:
            return {"error": "No API key configured", "success": False}
        
        try:
            # IP reputation endpoint
            request_url = f"https://www.ipqualityscore.com/api/json/ip/{self.api_key}/{ip_address}"
            
            params = {
                "strictness": 1,
                "allow_public_access_points": "true",
            }
            
            # Use context manager to ensure session is closed
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(request_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._process_ip_response(data, ip_address)
                    else:
                        return {"error": f"API error: {response.status}", "success": False}
        
        except Exception as e:
            logger.error(f"IPQualityScore IP check error: {e}")
            return {"error": str(e), "success": False}
    
    def _process_ip_response(self, data: Dict, ip: str) -> Dict[str, Any]:
        """Process IP reputation response."""
        if not data.get("success", False):
            return {"success": False, "error": data.get("message", "Unknown error"), "ip": ip}
        
        return {
            "success": True,
            "ip": ip,
            "fraud_score": data.get("fraud_score", 0),
            "is_proxy": data.get("proxy", False),
            "is_vpn": data.get("vpn", False),
            "is_tor": data.get("tor", False),
            "is_bot": data.get("bot_status", False),
            "is_crawler": data.get("is_crawler", False),
            "recent_abuse": data.get("recent_abuse", False),
            "country_code": data.get("country_code", ""),
            "city": data.get("city", ""),
            "isp": data.get("ISP", ""),
            "organization": data.get("organization", ""),
            "abuse_velocity": data.get("abuse_velocity", "none"),
        }


# Singleton instance
_client: Optional[IPQualityScoreClient] = None


def get_client(api_key: str) -> IPQualityScoreClient:
    """Get or create IPQualityScore client."""
    global _client
    if _client is None or _client.api_key != api_key:
        _client = IPQualityScoreClient(api_key)
    return _client


async def scan_url(url: str, api_key: str, strictness: int = 1) -> Dict[str, Any]:
    """
    Convenience function to scan a URL.
    
    Args:
        url: URL to scan
        api_key: IPQualityScore API key
        strictness: 0-2 scanning strictness
    
    Returns:
        Scan results
    """
    client = get_client(api_key)
    return await client.scan_url(url, strictness)


async def scan_urls(urls: List[str], api_key: str, strictness: int = 1) -> List[Dict[str, Any]]:
    """
    Convenience function to scan multiple URLs.
    
    Args:
        urls: URLs to scan
        api_key: IPQualityScore API key
        strictness: 0-2 scanning strictness
    
    Returns:
        List of scan results
    """
    client = get_client(api_key)
    return await client.scan_urls_batch(urls, strictness)
