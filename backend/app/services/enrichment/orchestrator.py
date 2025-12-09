"""
NiksES Enrichment Orchestrator

Coordinates all threat intelligence enrichments and combines results.
"""

import logging
import asyncio
from typing import Optional, Dict, Any, List, Set
from datetime import datetime

from app.models.email import ParsedEmail, ExtractedURL, AttachmentInfo
from app.models.enrichment import (
    EnrichmentResults,
    DomainEnrichment,
    IPEnrichment,
    URLEnrichment,
    AttachmentEnrichment,
    ThreatIntelVerdict
)
from app.utils.constants import (
    CACHE_TTL_ENRICHMENT,
    NEWLY_REGISTERED_DAYS_THRESHOLD,
    MAX_URLS_PER_EMAIL
)
from app.utils.exceptions import EnrichmentError

from .geoip import GeoIPProvider, get_geoip_provider
from .dns_resolver import DNSResolver, get_dns_resolver
from .whois_lookup import WHOISProvider, get_whois_provider
from .virustotal import VirusTotalProvider, get_virustotal_provider
from .abuseipdb import AbuseIPDBProvider, get_abuseipdb_provider
from .urlhaus import URLhausProvider, get_urlhaus_provider
from .phishtank import PhishTankProvider, get_phishtank_provider
from .mxtoolbox import MXToolboxProvider, get_mxtoolbox_provider

logger = logging.getLogger(__name__)


class EnrichmentOrchestrator:
    """
    Orchestrates all threat intelligence enrichments.
    
    Coordinates lookups across multiple providers:
    - Domain: WHOIS, DNS, VirusTotal, MXToolbox (blacklists)
    - IP: GeoIP, AbuseIPDB, VirusTotal, MXToolbox (blacklists)
    - URL: VirusTotal, URLhaus, PhishTank
    - File: VirusTotal, URLhaus
    
    Features:
    - Parallel execution for speed
    - Caching to reduce API calls
    - Graceful degradation on errors
    - Priority-based enrichment
    """
    
    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        phishtank_api_key: Optional[str] = None,
        mxtoolbox_api_key: Optional[str] = None,
    ):
        # Initialize providers
        self.geoip = get_geoip_provider()
        self.dns = get_dns_resolver()
        self.whois = get_whois_provider()
        self.virustotal = get_virustotal_provider(virustotal_api_key)
        self.abuseipdb = get_abuseipdb_provider(abuseipdb_api_key)
        self.urlhaus = get_urlhaus_provider()
        self.phishtank = get_phishtank_provider(phishtank_api_key)
        self.mxtoolbox = get_mxtoolbox_provider(mxtoolbox_api_key)
        
        # Simple in-memory cache
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
    
    def configure_api_keys(
        self,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        phishtank_api_key: Optional[str] = None,
        mxtoolbox_api_key: Optional[str] = None,
    ) -> None:
        """Update API keys for providers."""
        if virustotal_api_key:
            self.virustotal = get_virustotal_provider(virustotal_api_key)
        if abuseipdb_api_key:
            self.abuseipdb = get_abuseipdb_provider(abuseipdb_api_key)
        if phishtank_api_key:
            self.phishtank = get_phishtank_provider(phishtank_api_key)
        if mxtoolbox_api_key:
            self.mxtoolbox = get_mxtoolbox_provider(mxtoolbox_api_key)
    
    def _get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if valid."""
        if key not in self._cache:
            return None
        
        timestamp = self._cache_timestamps.get(key)
        if not timestamp:
            return None
        
        age = (datetime.utcnow() - timestamp).total_seconds()
        if age > CACHE_TTL_ENRICHMENT:
            del self._cache[key]
            del self._cache_timestamps[key]
            return None
        
        return self._cache[key]
    
    def _set_cache(self, key: str, value: Dict[str, Any]) -> None:
        """Store result in cache."""
        self._cache[key] = value
        self._cache_timestamps[key] = datetime.utcnow()
    
    async def enrich_email(self, parsed_email: ParsedEmail) -> EnrichmentResults:
        """
        Fully enrich a parsed email with threat intelligence.
        
        Args:
            parsed_email: Parsed email to enrich
            
        Returns:
            EnrichmentResults with all enrichment data
        """
        results = EnrichmentResults()
        
        # Collect unique items to enrich
        domains_to_check: Set[str] = set()
        ips_to_check: Set[str] = set()
        urls_to_check: List[ExtractedURL] = []
        
        # Sender domain
        if parsed_email.sender and parsed_email.sender.domain:
            domains_to_check.add(parsed_email.sender.domain)
        
        # Reply-to domain
        if parsed_email.reply_to:
            for addr in parsed_email.reply_to:
                if addr.domain:
                    domains_to_check.add(addr.domain)
        
        # Originating IP
        if parsed_email.header_analysis and parsed_email.header_analysis.originating_ip:
            ips_to_check.add(parsed_email.header_analysis.originating_ip)
        
        # All IPs from received chain
        if parsed_email.header_analysis and parsed_email.header_analysis.received_chain:
            for hop in parsed_email.header_analysis.received_chain:
                if hop.from_ip:
                    ips_to_check.add(hop.from_ip)
        
        # URLs
        urls_to_check = parsed_email.urls[:MAX_URLS_PER_EMAIL]
        for url in urls_to_check:
            if url.domain:
                domains_to_check.add(url.domain)
        
        # Run enrichments in parallel
        tasks = []
        
        # Domain enrichments
        for domain in domains_to_check:
            tasks.append(self._enrich_domain_task(domain))
        
        # IP enrichments
        for ip in ips_to_check:
            tasks.append(self._enrich_ip_task(ip))
        
        # URL enrichments
        for url in urls_to_check:
            tasks.append(self._enrich_url_task(url))
        
        # Attachment enrichments
        for attachment in parsed_email.attachments:
            if attachment.sha256:
                tasks.append(self._enrich_attachment_task(attachment))
        
        # Execute all tasks
        enrichment_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        domain_enrichments: Dict[str, DomainEnrichment] = {}
        ip_enrichments: Dict[str, IPEnrichment] = {}
        url_enrichments: List[URLEnrichment] = []
        attachment_enrichments: List[AttachmentEnrichment] = []
        
        for result in enrichment_results:
            if isinstance(result, Exception):
                logger.warning(f"Enrichment task failed: {result}")
                continue
            
            if isinstance(result, DomainEnrichment):
                domain_enrichments[result.domain] = result
            elif isinstance(result, IPEnrichment):
                ip_enrichments[result.ip_address] = result
            elif isinstance(result, URLEnrichment):
                url_enrichments.append(result)
            elif isinstance(result, AttachmentEnrichment):
                attachment_enrichments.append(result)
        
        # Populate results
        if parsed_email.sender and parsed_email.sender.domain:
            results.sender_domain = domain_enrichments.get(parsed_email.sender.domain)
        
        if parsed_email.reply_to:
            for addr in parsed_email.reply_to:
                if addr.domain and addr.domain in domain_enrichments:
                    results.reply_to_domain = domain_enrichments[addr.domain]
                    break
        
        results.url_domains = [
            domain_enrichments[url.domain]
            for url in urls_to_check
            if url.domain and url.domain in domain_enrichments
        ]
        
        if parsed_email.header_analysis and parsed_email.header_analysis.originating_ip:
            results.originating_ip = ip_enrichments.get(
                parsed_email.header_analysis.originating_ip
            )
        
        results.all_ips = list(ip_enrichments.values())
        results.urls = url_enrichments
        results.attachments = attachment_enrichments
        
        return results
    
    async def _enrich_domain_task(self, domain: str) -> DomainEnrichment:
        """Enrich a single domain."""
        cache_key = f"domain:{domain}"
        cached = self._get_cache(cache_key)
        if cached:
            return DomainEnrichment(**cached)
        
        # Run lookups in parallel
        whois_task = self.whois.lookup_domain(domain)
        dns_task = self.dns.get_email_security_records(domain)
        vt_task = self.virustotal.check_domain(domain) if self.virustotal.is_configured else asyncio.sleep(0)
        mx_task = self.mxtoolbox.check_blacklist(domain) if self.mxtoolbox.is_configured else asyncio.sleep(0)
        
        whois_data, dns_data, vt_data, mx_data = await asyncio.gather(
            whois_task, dns_task, vt_task, mx_task,
            return_exceptions=True
        )
        
        # Handle exceptions AND None values (asyncio.sleep returns None)
        whois_data = whois_data if isinstance(whois_data, dict) else {}
        dns_data = dns_data if isinstance(dns_data, dict) else {}
        vt_data = vt_data if isinstance(vt_data, dict) else {}
        mx_data = mx_data if isinstance(mx_data, dict) else {}
        
        # Extract blacklist names from MXToolbox response
        blacklists_listed = []
        if mx_data.get('blacklists'):
            blacklists_listed = [bl.get('name', '') for bl in mx_data['blacklists'] if bl.get('name')]
        
        enrichment = DomainEnrichment(
            domain=domain,
            registrar=whois_data.get('registrar'),
            creation_date=whois_data.get('creation_date'),
            expiration_date=whois_data.get('expiration_date'),
            age_days=whois_data.get('age_days'),
            is_newly_registered=whois_data.get('is_newly_registered', False),
            registrant_country=whois_data.get('registrant_country'),
            has_mx_records=dns_data.get('has_mx_records', False),
            has_spf_record=dns_data.get('has_spf_record', False),
            has_dmarc_record=dns_data.get('has_dmarc_record', False),
            nameservers=dns_data.get('nameservers', []),
            virustotal_stats=vt_data.get('stats'),
            virustotal_positives=vt_data.get('positives'),
            virustotal_total=vt_data.get('total'),
            virustotal_verdict=vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            blacklists_listed=blacklists_listed,
            blacklist_count=mx_data.get('blacklist_count', 0),
        )
        
        self._set_cache(cache_key, enrichment.model_dump())
        return enrichment
    
    async def _enrich_ip_task(self, ip: str) -> IPEnrichment:
        """Enrich a single IP address."""
        cache_key = f"ip:{ip}"
        cached = self._get_cache(cache_key)
        if cached:
            return IPEnrichment(**cached)
        
        # Run lookups in parallel
        geo_task = self.geoip.lookup_ip(ip)
        abuse_task = self.abuseipdb.check_ip(ip) if self.abuseipdb.is_configured else asyncio.sleep(0)
        vt_task = self.virustotal.check_ip(ip) if self.virustotal.is_configured else asyncio.sleep(0)
        mx_task = self.mxtoolbox.check_blacklist(ip) if self.mxtoolbox.is_configured else asyncio.sleep(0)
        
        geo_data, abuse_data, vt_data, mx_data = await asyncio.gather(
            geo_task, abuse_task, vt_task, mx_task,
            return_exceptions=True
        )
        
        # Handle exceptions AND None values (asyncio.sleep returns None)
        geo_data = geo_data if isinstance(geo_data, dict) else {}
        abuse_data = abuse_data if isinstance(abuse_data, dict) else {}
        vt_data = vt_data if isinstance(vt_data, dict) else {}
        mx_data = mx_data if isinstance(mx_data, dict) else {}
        
        # Extract blacklist names from MXToolbox response
        blacklists_listed = []
        if mx_data.get('blacklists'):
            blacklists_listed = [bl.get('name', '') for bl in mx_data['blacklists'] if bl.get('name')]
        
        enrichment = IPEnrichment(
            ip_address=ip,
            country=geo_data.get('country'),
            country_code=geo_data.get('country_code'),
            city=geo_data.get('city'),
            region=geo_data.get('region'),
            lat=geo_data.get('lat'),
            lon=geo_data.get('lon'),
            timezone=geo_data.get('timezone'),
            asn=geo_data.get('asn'),
            as_org=geo_data.get('as_org'),
            isp=geo_data.get('isp'),
            abuseipdb_score=abuse_data.get('score'),
            abuseipdb_reports=abuse_data.get('total_reports'),
            abuseipdb_verdict=abuse_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            virustotal_stats=vt_data.get('stats'),
            virustotal_positives=vt_data.get('positives'),
            virustotal_total=vt_data.get('total'),
            virustotal_verdict=vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            blacklists_listed=blacklists_listed,
            blacklist_count=mx_data.get('blacklist_count', 0),
            is_vpn=self._detect_vpn(geo_data, abuse_data),
            is_proxy=geo_data.get('is_proxy', False),
            is_tor=abuse_data.get('is_tor', False),
            is_datacenter=geo_data.get('is_datacenter', False),
            is_mobile=geo_data.get('is_mobile', False),
        )
        
        self._set_cache(cache_key, enrichment.model_dump())
        return enrichment
    
    async def _enrich_url_task(self, url: ExtractedURL) -> URLEnrichment:
        """Enrich a single URL."""
        cache_key = f"url:{url.normalized_url}"
        cached = self._get_cache(cache_key)
        if cached:
            return URLEnrichment(**cached)
        
        # Run lookups in parallel
        vt_task = self.virustotal.check_url(url.url) if self.virustotal.is_configured else asyncio.sleep(0)
        urlhaus_task = self.urlhaus.check_url(url.url)
        phishtank_task = self.phishtank.check_url(url.url)
        
        vt_data, urlhaus_data, phishtank_data = await asyncio.gather(
            vt_task, urlhaus_task, phishtank_task,
            return_exceptions=True
        )
        
        # Handle exceptions AND None values (asyncio.sleep returns None)
        vt_data = vt_data if isinstance(vt_data, dict) else {}
        urlhaus_data = urlhaus_data if isinstance(urlhaus_data, dict) else {}
        phishtank_data = phishtank_data if isinstance(phishtank_data, dict) else {}
        
        # Determine final verdict
        verdicts = [
            vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            urlhaus_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            phishtank_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
        ]
        
        final_verdict = self._combine_verdicts(verdicts)
        
        enrichment = URLEnrichment(
            url=url.url,
            domain=url.domain or '',
            virustotal_positives=vt_data.get('positives'),
            virustotal_total=vt_data.get('total'),
            virustotal_verdict=vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            virustotal_categories=vt_data.get('categories', []),
            urlhaus_status=urlhaus_data.get('url_status'),
            urlhaus_threat=urlhaus_data.get('threat'),
            urlhaus_tags=urlhaus_data.get('tags', []),
            phishtank_in_database=phishtank_data.get('in_database', False),
            phishtank_verified=phishtank_data.get('verified', False),
            phishtank_verified_at=phishtank_data.get('verified_at'),
            final_verdict=final_verdict,
            is_shortened=url.is_shortened,
        )
        
        self._set_cache(cache_key, enrichment.model_dump())
        return enrichment
    
    async def _enrich_attachment_task(self, attachment: AttachmentInfo) -> AttachmentEnrichment:
        """Enrich a single attachment."""
        cache_key = f"file:{attachment.sha256}"
        cached = self._get_cache(cache_key)
        if cached:
            return AttachmentEnrichment(**cached)
        
        # Run lookups in parallel
        vt_task = self.virustotal.check_file_hash(attachment.sha256) if self.virustotal.is_configured else asyncio.sleep(0)
        urlhaus_task = self.urlhaus.check_hash(attachment.sha256)
        
        vt_data, urlhaus_data = await asyncio.gather(
            vt_task, urlhaus_task,
            return_exceptions=True
        )
        
        # Handle exceptions AND None values (asyncio.sleep returns None)
        vt_data = vt_data if isinstance(vt_data, dict) else {}
        urlhaus_data = urlhaus_data if isinstance(urlhaus_data, dict) else {}
        
        # Determine final verdict
        verdicts = [
            vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            urlhaus_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
        ]
        
        final_verdict = self._combine_verdicts(verdicts)
        
        enrichment = AttachmentEnrichment(
            sha256=attachment.sha256,
            md5=attachment.md5 or '',
            filename=attachment.filename,
            virustotal_positives=vt_data.get('positives'),
            virustotal_total=vt_data.get('total'),
            virustotal_verdict=vt_data.get('verdict', ThreatIntelVerdict.UNKNOWN),
            virustotal_threat_names=vt_data.get('threat_names', []),
            malwarebazaar_known=urlhaus_data.get('in_database', False),
            malwarebazaar_tags=urlhaus_data.get('tags', []),
            final_verdict=final_verdict,
        )
        
        self._set_cache(cache_key, enrichment.model_dump())
        return enrichment
    
    def _combine_verdicts(self, verdicts: List[ThreatIntelVerdict]) -> ThreatIntelVerdict:
        """
        Combine multiple verdicts into a final verdict.
        
        Priority: MALICIOUS > SUSPICIOUS > CLEAN > UNKNOWN
        """
        if ThreatIntelVerdict.MALICIOUS in verdicts:
            return ThreatIntelVerdict.MALICIOUS
        if ThreatIntelVerdict.SUSPICIOUS in verdicts:
            return ThreatIntelVerdict.SUSPICIOUS
        if ThreatIntelVerdict.CLEAN in verdicts:
            return ThreatIntelVerdict.CLEAN
        return ThreatIntelVerdict.UNKNOWN
    
    def _detect_vpn(self, geo_data: Dict[str, Any], abuse_data: Dict[str, Any]) -> bool:
        """
        Detect if IP is a VPN.
        
        Uses combination of:
        - AbuseIPDB usage_type
        - AbuseIPDB categories (13 = VPN IP)
        - ISP/org name patterns
        """
        # Check AbuseIPDB usage type
        usage_type = abuse_data.get('usage_type', '').lower()
        if 'vpn' in usage_type or 'commercial vpn' in usage_type:
            return True
        
        # Check AbuseIPDB categories (13 = VPN IP)
        categories = abuse_data.get('categories', [])
        if isinstance(categories, list):
            # Check if 'VPN IP' is in categories
            if 'VPN IP' in categories or 13 in [c if isinstance(c, int) else 0 for c in categories]:
                return True
        
        # Check ISP/org for VPN keywords
        isp = (geo_data.get('isp') or '').lower()
        org = (geo_data.get('org') or '').lower()
        as_org = (geo_data.get('as_org') or '').lower()
        
        vpn_keywords = [
            'vpn', 'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'cyberghost',
            'private internet access', 'pia', 'mullvad', 'ipvanish', 'tunnelbear',
            'windscribe', 'hotspot shield', 'purevpn', 'hide.me', 'privatevpn'
        ]
        
        for keyword in vpn_keywords:
            if keyword in isp or keyword in org or keyword in as_org:
                return True
        
        return False
    
    async def enrich_single_domain(self, domain: str) -> DomainEnrichment:
        """Enrich a single domain on demand."""
        return await self._enrich_domain_task(domain)
    
    async def enrich_single_ip(self, ip: str) -> IPEnrichment:
        """Enrich a single IP on demand."""
        return await self._enrich_ip_task(ip)
    
    async def enrich_single_url(self, url: str) -> URLEnrichment:
        """Enrich a single URL on demand."""
        extracted_url = ExtractedURL(
            url=url,
            normalized_url=url.lower(),
            domain=self._extract_domain(url),
        )
        return await self._enrich_url_task(extracted_url)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ''
    
    def clear_cache(self) -> None:
        """Clear the enrichment cache."""
        self._cache.clear()
        self._cache_timestamps.clear()
    
    def get_provider_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all providers."""
        return {
            'geoip': {
                'name': 'GeoIP (ip-api.com)',
                'configured': self.geoip.is_configured,
                'requires_key': False,
            },
            'dns': {
                'name': 'DNS Resolver',
                'configured': self.dns.is_configured,
                'requires_key': False,
            },
            'whois': {
                'name': 'WHOIS',
                'configured': self.whois.is_configured,
                'requires_key': False,
            },
            'virustotal': {
                'name': 'VirusTotal',
                'configured': self.virustotal.is_configured,
                'requires_key': True,
            },
            'abuseipdb': {
                'name': 'AbuseIPDB',
                'configured': self.abuseipdb.is_configured,
                'requires_key': True,
            },
            'urlhaus': {
                'name': 'URLhaus',
                'configured': self.urlhaus.is_configured,
                'requires_key': False,
            },
            'phishtank': {
                'name': 'PhishTank',
                'configured': self.phishtank.is_configured,
                'requires_key': False,
            },
        }


# Singleton instance
_orchestrator: Optional[EnrichmentOrchestrator] = None


def get_enrichment_orchestrator() -> EnrichmentOrchestrator:
    """Get the enrichment orchestrator singleton."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = EnrichmentOrchestrator()
    return _orchestrator


def configure_enrichment(
    virustotal_api_key: Optional[str] = None,
    abuseipdb_api_key: Optional[str] = None,
    phishtank_api_key: Optional[str] = None,
) -> EnrichmentOrchestrator:
    """Configure and get the enrichment orchestrator."""
    global _orchestrator
    _orchestrator = EnrichmentOrchestrator(
        virustotal_api_key=virustotal_api_key,
        abuseipdb_api_key=abuseipdb_api_key,
        phishtank_api_key=phishtank_api_key,
    )
    return _orchestrator
