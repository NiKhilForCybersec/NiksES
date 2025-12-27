"""
NiksES WHOIS Lookup

Provides domain WHOIS data including registration dates and registrar info.
"""

import logging
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import whois

from app.utils.constants import WHOIS_TIMEOUT, NEWLY_REGISTERED_DAYS_THRESHOLD
from app.utils.exceptions import EnrichmentError

logger = logging.getLogger(__name__)


class WHOISProvider:
    """
    WHOIS lookup provider using python-whois.
    
    Provides domain registration data:
    - Creation date
    - Expiration date  
    - Registrar
    - Registrant info (when available)
    - Age calculation
    """
    
    provider_name = "whois"
    requires_api_key = False
    is_free = True
    
    def __init__(self, timeout: int = WHOIS_TIMEOUT):
        self.timeout = timeout
    
    @property
    def is_configured(self) -> bool:
        return True
    
    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup WHOIS data for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with WHOIS data
        """
        if not domain:
            return {}
        
        # Clean domain - remove subdomains for WHOIS
        domain = self._get_registrable_domain(domain)
        
        try:
            loop = asyncio.get_event_loop()
            
            # Run synchronous whois in executor with timeout
            w = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: whois.whois(domain)),
                timeout=self.timeout
            )
            
            if not w or not w.domain_name:
                return {}
            
            # Parse creation date
            creation_date = self._parse_date(w.creation_date)
            expiration_date = self._parse_date(w.expiration_date)
            updated_date = self._parse_date(w.updated_date)
            
            # Calculate age
            age_days = None
            is_newly_registered = False
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                is_newly_registered = age_days <= NEWLY_REGISTERED_DAYS_THRESHOLD
            
            return {
                'domain': domain,
                'registrar': self._get_first(w.registrar),
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'updated_date': updated_date,
                'age_days': age_days,
                'is_newly_registered': is_newly_registered,
                'registrant_name': self._get_first(w.name),
                'registrant_org': self._get_first(w.org),
                'registrant_country': self._get_first(w.country),
                'registrant_email': self._get_first(w.emails) if isinstance(w.emails, list) else w.emails,
                'nameservers': self._normalize_nameservers(w.name_servers),
                'status': self._normalize_list(w.status),
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
            }
            
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS timeout for {domain}")
            return {'error': 'timeout'}
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS parse error for {domain}: {e}")
            return {'error': str(e)}
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {e}")
            return {'error': str(e)}
    
    def _get_registrable_domain(self, domain: str) -> str:
        """
        Extract registrable domain from full domain.
        
        E.g., 'mail.google.com' -> 'google.com'
        """
        # Simple approach - take last two parts for common TLDs
        parts = domain.lower().strip().split('.')
        
        if len(parts) <= 2:
            return domain
        
        # Handle country TLDs like .co.uk, .com.au
        country_tlds = ['co.uk', 'com.au', 'com.br', 'co.jp', 'co.nz', 'co.za']
        last_two = '.'.join(parts[-2:])
        if last_two in country_tlds:
            return '.'.join(parts[-3:])
        
        return '.'.join(parts[-2:])
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse various date formats from WHOIS."""
        if date_value is None:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            # Try common formats
            formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%d-%b-%Y',
                '%Y/%m/%d',
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(date_value[:19], fmt)
                except ValueError:
                    continue
        
        return None
    
    def _get_first(self, value) -> Optional[str]:
        """Get first value if list, otherwise return value."""
        if value is None:
            return None
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value)
    
    def _normalize_nameservers(self, nameservers) -> list:
        """Normalize nameserver list."""
        if not nameservers:
            return []
        
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        
        return [ns.lower().rstrip('.') for ns in nameservers if ns]
    
    def _normalize_list(self, value) -> list:
        """Normalize to list."""
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)
    
    async def is_newly_registered(self, domain: str, days: int = NEWLY_REGISTERED_DAYS_THRESHOLD) -> bool:
        """
        Check if domain was registered within specified days.
        
        Args:
            domain: Domain to check
            days: Number of days threshold
            
        Returns:
            True if newly registered
        """
        whois_data = await self.lookup_domain(domain)
        
        if 'error' in whois_data:
            return False  # Can't determine
        
        age_days = whois_data.get('age_days')
        if age_days is None:
            return False
        
        return age_days <= days
    
    async def get_domain_age(self, domain: str) -> Optional[int]:
        """
        Get domain age in days.
        
        Args:
            domain: Domain to check
            
        Returns:
            Age in days or None
        """
        whois_data = await self.lookup_domain(domain)
        return whois_data.get('age_days')


# Singleton instance
_whois_provider: Optional[WHOISProvider] = None


def get_whois_provider() -> WHOISProvider:
    """Get the WHOIS provider singleton."""
    global _whois_provider
    if _whois_provider is None:
        _whois_provider = WHOISProvider()
    return _whois_provider


async def lookup_domain_whois(domain: str) -> Dict[str, Any]:
    """Convenience function for WHOIS lookup."""
    provider = get_whois_provider()
    return await provider.lookup_domain(domain)
