"""
NiksES MXToolbox Integration

Provides email security lookups via MXToolbox API:
- DNS lookups
- MX record verification  
- Blacklist checks
- SPF/DKIM/DMARC validation
"""

import logging
import aiohttp
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class MXToolboxProvider:
    """
    MXToolbox API provider.
    
    API docs: https://mxtoolbox.com/User/Api/Usage.aspx
    
    Provides:
    - DNS lookups (A, MX, TXT, etc.)
    - Blacklist monitoring
    - Email deliverability checks
    - SPF/DKIM/DMARC validation
    """
    
    provider_name = "mxtoolbox"
    requires_api_key = True
    
    API_BASE = "https://mxtoolbox.com/api/v1"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        return {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
        }
    
    async def _make_request(self, endpoint: str, command: str, argument: str) -> Dict[str, Any]:
        """
        Make API request to MXToolbox.
        
        Args:
            endpoint: API endpoint (Lookup, Monitor, etc.)
            command: Lookup command (mx, a, spf, blacklist, etc.)
            argument: Domain or IP to lookup
            
        Returns:
            API response dictionary
        """
        if not self.is_configured:
            return {"error": "MXToolbox API key not configured"}
        
        try:
            session = await self._get_session()
            url = f"{self.API_BASE}/{endpoint}/{command}/{argument}"
            
            async with session.get(url, headers=self._get_headers()) as response:
                if response.status == 401:
                    logger.error("MXToolbox API: Invalid API key")
                    return {"error": "Invalid API key"}
                
                if response.status == 429:
                    logger.warning("MXToolbox API: Rate limit exceeded")
                    return {"error": "Rate limit exceeded"}
                
                if response.status != 200:
                    logger.warning(f"MXToolbox API error: {response.status}")
                    return {"error": f"API error: {response.status}"}
                
                return await response.json()
                
        except aiohttp.ClientTimeout:
            logger.warning(f"MXToolbox timeout for {argument}")
            return {"error": "Timeout"}
        except Exception as e:
            logger.error(f"MXToolbox error: {e}")
            return {"error": str(e)}
    
    async def lookup_mx(self, domain: str) -> Dict[str, Any]:
        """
        Lookup MX records for a domain.
        
        Returns:
            Dictionary with MX records and mail server info
        """
        result = await self._make_request("Lookup", "mx", domain)
        
        if "error" in result:
            return result
        
        # Parse MX records
        mx_records = []
        has_mx = False
        
        if "Information" in result:
            for info in result.get("Information", []):
                if info.get("Type") == "MX":
                    has_mx = True
                    mx_records.append({
                        "priority": info.get("Priority", 0),
                        "hostname": info.get("Domain Name", ""),
                        "ip": info.get("IP Address", ""),
                    })
        
        return {
            "domain": domain,
            "has_mx_records": has_mx,
            "mx_records": mx_records,
            "raw": result,
        }
    
    async def lookup_spf(self, domain: str) -> Dict[str, Any]:
        """
        Lookup and validate SPF record for a domain.
        
        Returns:
            Dictionary with SPF record details and validation status
        """
        result = await self._make_request("Lookup", "spf", domain)
        
        if "error" in result:
            return result
        
        has_spf = False
        spf_record = None
        spf_valid = False
        
        if "Information" in result:
            for info in result.get("Information", []):
                if "SPF Record" in info.get("String", ""):
                    has_spf = True
                    spf_record = info.get("String", "")
        
        # Check for passed status
        if "Passed" in result:
            spf_valid = len(result.get("Passed", [])) > 0 and len(result.get("Failed", [])) == 0
        
        return {
            "domain": domain,
            "has_spf_record": has_spf,
            "spf_record": spf_record,
            "spf_valid": spf_valid,
            "warnings": [w.get("Info", "") for w in result.get("Warnings", [])],
            "failures": [f.get("Info", "") for f in result.get("Failed", [])],
            "raw": result,
        }
    
    async def lookup_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Lookup DMARC record for a domain.
        
        Returns:
            Dictionary with DMARC policy details
        """
        result = await self._make_request("Lookup", "dmarc", domain)
        
        if "error" in result:
            return result
        
        has_dmarc = False
        dmarc_policy = None
        dmarc_record = None
        
        if "Information" in result:
            for info in result.get("Information", []):
                info_str = info.get("String", "")
                if "v=DMARC1" in info_str:
                    has_dmarc = True
                    dmarc_record = info_str
                    # Extract policy
                    if "p=reject" in info_str:
                        dmarc_policy = "reject"
                    elif "p=quarantine" in info_str:
                        dmarc_policy = "quarantine"
                    elif "p=none" in info_str:
                        dmarc_policy = "none"
        
        return {
            "domain": domain,
            "has_dmarc_record": has_dmarc,
            "dmarc_record": dmarc_record,
            "dmarc_policy": dmarc_policy,
            "raw": result,
        }
    
    async def check_blacklist(self, ip_or_domain: str) -> Dict[str, Any]:
        """
        Check if IP or domain is blacklisted.
        
        Returns:
            Dictionary with blacklist status and details
        """
        result = await self._make_request("Lookup", "blacklist", ip_or_domain)
        
        if "error" in result:
            return result
        
        is_blacklisted = False
        blacklist_count = 0
        blacklists = []
        
        if "Failed" in result:
            blacklist_count = len(result.get("Failed", []))
            is_blacklisted = blacklist_count > 0
            for fail in result.get("Failed", []):
                blacklists.append({
                    "name": fail.get("Name", ""),
                    "info": fail.get("Info", ""),
                })
        
        return {
            "target": ip_or_domain,
            "is_blacklisted": is_blacklisted,
            "blacklist_count": blacklist_count,
            "blacklists": blacklists,
            "total_checked": len(result.get("Passed", [])) + blacklist_count,
            "raw": result,
        }
    
    async def lookup_a_record(self, domain: str) -> Dict[str, Any]:
        """
        Lookup A records for a domain.
        
        Returns:
            Dictionary with IP addresses
        """
        result = await self._make_request("Lookup", "a", domain)
        
        if "error" in result:
            return result
        
        ip_addresses = []
        
        if "Information" in result:
            for info in result.get("Information", []):
                ip = info.get("IP Address", "")
                if ip:
                    ip_addresses.append(ip)
        
        return {
            "domain": domain,
            "ip_addresses": ip_addresses,
            "raw": result,
        }
    
    async def lookup_dns_full(self, domain: str) -> Dict[str, Any]:
        """
        Perform full DNS lookup including MX, SPF, DMARC.
        
        This is a comprehensive check useful for email security analysis.
        
        Returns:
            Dictionary with all DNS-related email security info
        """
        # Run all lookups in parallel
        import asyncio
        
        mx_task = self.lookup_mx(domain)
        spf_task = self.lookup_spf(domain)
        dmarc_task = self.lookup_dmarc(domain)
        
        mx_result, spf_result, dmarc_result = await asyncio.gather(
            mx_task, spf_task, dmarc_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        mx_result = mx_result if not isinstance(mx_result, Exception) else {"error": str(mx_result)}
        spf_result = spf_result if not isinstance(spf_result, Exception) else {"error": str(spf_result)}
        dmarc_result = dmarc_result if not isinstance(dmarc_result, Exception) else {"error": str(dmarc_result)}
        
        return {
            "domain": domain,
            "mx": mx_result,
            "spf": spf_result,
            "dmarc": dmarc_result,
            "email_security_score": self._calculate_email_security_score(mx_result, spf_result, dmarc_result),
        }
    
    def _calculate_email_security_score(
        self, 
        mx_result: Dict[str, Any],
        spf_result: Dict[str, Any],
        dmarc_result: Dict[str, Any]
    ) -> int:
        """
        Calculate email security score based on DNS configuration.
        
        Score: 0-100
        - MX records: 20 points
        - Valid SPF: 30 points
        - DMARC with reject/quarantine: 50 points
        - DMARC with none: 20 points
        """
        score = 0
        
        # MX records
        if mx_result.get("has_mx_records"):
            score += 20
        
        # SPF
        if spf_result.get("has_spf_record"):
            score += 15
            if spf_result.get("spf_valid"):
                score += 15
        
        # DMARC
        if dmarc_result.get("has_dmarc_record"):
            policy = dmarc_result.get("dmarc_policy")
            if policy == "reject":
                score += 50
            elif policy == "quarantine":
                score += 40
            elif policy == "none":
                score += 20
        
        return min(score, 100)


# Singleton instance
_mxtoolbox_provider: Optional[MXToolboxProvider] = None


def get_mxtoolbox_provider(api_key: Optional[str] = None) -> MXToolboxProvider:
    """Get or create MXToolbox provider singleton."""
    global _mxtoolbox_provider
    if _mxtoolbox_provider is None:
        _mxtoolbox_provider = MXToolboxProvider(api_key=api_key)
    elif api_key and _mxtoolbox_provider.api_key != api_key:
        _mxtoolbox_provider.api_key = api_key
    return _mxtoolbox_provider


def configure_mxtoolbox(api_key: Optional[str] = None):
    """Configure MXToolbox provider with API key."""
    provider = get_mxtoolbox_provider()
    if api_key:
        provider.api_key = api_key
        logger.info("MXToolbox API configured")
