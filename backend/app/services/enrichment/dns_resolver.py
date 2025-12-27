"""
NiksES DNS Resolver

Provides DNS lookups for domains including MX, SPF, DMARC, and TXT records.
"""

import logging
import asyncio
from typing import Optional, Dict, Any, List
import dns.resolver
import dns.exception

from app.utils.constants import DNS_TIMEOUT
from app.utils.exceptions import EnrichmentError

logger = logging.getLogger(__name__)


class DNSResolver:
    """
    DNS resolver for email-related lookups.
    
    Provides async wrappers around dnspython for:
    - MX records (mail servers)
    - TXT records (SPF, DMARC, DKIM)
    - A/AAAA records
    - NS records
    """
    
    provider_name = "dns"
    requires_api_key = False
    is_free = True
    
    def __init__(self, timeout: int = DNS_TIMEOUT):
        self.timeout = timeout
        # Create resolver with fallback to public DNS
        try:
            self._resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            # No system DNS configured, use empty resolver
            self._resolver = dns.resolver.Resolver(configure=False)
            self._resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        
        # Ensure we have nameservers
        if not self._resolver.nameservers:
            self._resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    
    @property
    def is_configured(self) -> bool:
        return True
    
    async def resolve_mx(self, domain: str) -> List[Dict[str, Any]]:
        """
        Resolve MX records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of MX records with priority and exchange
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, 
                lambda: self._resolver.resolve(domain, 'MX')
            )
            
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            
            # Sort by priority
            mx_records.sort(key=lambda x: x['priority'])
            return mx_records
            
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No MX records for {domain}")
            return []
        except dns.exception.Timeout:
            logger.warning(f"DNS timeout for MX lookup: {domain}")
            return []
        except Exception as e:
            logger.error(f"DNS MX error for {domain}: {e}")
            return []
    
    async def resolve_txt(self, domain: str) -> List[str]:
        """
        Resolve TXT records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of TXT record values
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self._resolver.resolve(domain, 'TXT')
            )
            
            txt_records = []
            for rdata in answers:
                # TXT records can be split, join them
                txt_value = ''.join([s.decode('utf-8', errors='ignore') 
                                     for s in rdata.strings])
                txt_records.append(txt_value)
            
            return txt_records
            
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.Timeout:
            logger.warning(f"DNS timeout for TXT lookup: {domain}")
            return []
        except Exception as e:
            logger.error(f"DNS TXT error for {domain}: {e}")
            return []
    
    async def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Get SPF record for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            SPF record string or None
        """
        txt_records = await self.resolve_txt(domain)
        
        for record in txt_records:
            if record.lower().startswith('v=spf1'):
                return record
        
        return None
    
    async def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Get DMARC record for a domain.
        
        DMARC records are at _dmarc.domain.com
        
        Args:
            domain: Domain to query
            
        Returns:
            DMARC record string or None
        """
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = await self.resolve_txt(dmarc_domain)
        
        for record in txt_records:
            if record.lower().startswith('v=dmarc1'):
                return record
        
        return None
    
    async def get_dkim_record(self, domain: str, selector: str = "default") -> Optional[str]:
        """
        Get DKIM record for a domain with specified selector.
        
        DKIM records are at selector._domainkey.domain.com
        
        Args:
            domain: Domain to query
            selector: DKIM selector (default: "default")
            
        Returns:
            DKIM record string or None
        """
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = await self.resolve_txt(dkim_domain)
        
        for record in txt_records:
            if 'v=dkim1' in record.lower() or 'k=rsa' in record.lower():
                return record
        
        return None
    
    async def resolve_a(self, domain: str) -> List[str]:
        """
        Resolve A records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of IPv4 addresses
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self._resolver.resolve(domain, 'A')
            )
            
            return [str(rdata.address) for rdata in answers]
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.error(f"DNS A error for {domain}: {e}")
            return []
    
    async def resolve_aaaa(self, domain: str) -> List[str]:
        """
        Resolve AAAA records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of IPv6 addresses
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self._resolver.resolve(domain, 'AAAA')
            )
            
            return [str(rdata.address) for rdata in answers]
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.error(f"DNS AAAA error for {domain}: {e}")
            return []
    
    async def resolve_ns(self, domain: str) -> List[str]:
        """
        Resolve NS records for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of nameservers
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self._resolver.resolve(domain, 'NS')
            )
            
            return [str(rdata.target).rstrip('.') for rdata in answers]
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.error(f"DNS NS error for {domain}: {e}")
            return []
    
    async def get_email_security_records(self, domain: str) -> Dict[str, Any]:
        """
        Get all email security related DNS records.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with SPF, DMARC, MX, and NS records
        """
        # Run lookups concurrently
        spf_task = self.get_spf_record(domain)
        dmarc_task = self.get_dmarc_record(domain)
        mx_task = self.resolve_mx(domain)
        ns_task = self.resolve_ns(domain)
        
        spf, dmarc, mx, ns = await asyncio.gather(
            spf_task, dmarc_task, mx_task, ns_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        spf = spf if not isinstance(spf, Exception) else None
        dmarc = dmarc if not isinstance(dmarc, Exception) else None
        mx = mx if not isinstance(mx, Exception) else []
        ns = ns if not isinstance(ns, Exception) else []
        
        return {
            'has_spf_record': spf is not None,
            'spf_record': spf,
            'has_dmarc_record': dmarc is not None,
            'dmarc_record': dmarc,
            'has_mx_records': len(mx) > 0,
            'mx_records': mx,
            'nameservers': ns,
        }
    
    async def check_domain_exists(self, domain: str) -> bool:
        """
        Check if a domain exists (has any DNS records).
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain has DNS records
        """
        # Check for A, AAAA, or MX records
        a_records = await self.resolve_a(domain)
        if a_records:
            return True
        
        mx_records = await self.resolve_mx(domain)
        if mx_records:
            return True
        
        return False


# Singleton instance
_dns_resolver: Optional[DNSResolver] = None


def get_dns_resolver() -> DNSResolver:
    """Get the DNS resolver singleton."""
    global _dns_resolver
    if _dns_resolver is None:
        _dns_resolver = DNSResolver()
    return _dns_resolver


async def get_email_security_records(domain: str) -> Dict[str, Any]:
    """Convenience function for email security lookups."""
    resolver = get_dns_resolver()
    return await resolver.get_email_security_records(domain)
