"""
NiksES Enrichment Data Models

Pydantic models for threat intelligence enrichment results.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatIntelVerdict(str, Enum):
    """Threat intelligence verdict."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    ERROR = "error"


class DomainEnrichment(BaseModel):
    """Domain reputation and WHOIS data."""
    domain: str = Field(..., description="Domain name")
    
    # WHOIS data
    registrar: Optional[str] = Field(None, description="Domain registrar")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    expiration_date: Optional[datetime] = Field(None, description="Domain expiration date")
    age_days: Optional[int] = Field(None, description="Domain age in days")
    is_newly_registered: bool = Field(False, description="Registered within 30 days")
    registrant_country: Optional[str] = Field(None, description="Registrant country")
    
    # DNS data
    has_mx_records: bool = Field(False, description="Has MX records")
    has_spf_record: bool = Field(False, description="Has SPF record")
    has_dmarc_record: bool = Field(False, description="Has DMARC record")
    nameservers: List[str] = Field(default_factory=list)
    
    # Reputation
    virustotal_stats: Optional[Dict[str, Any]] = Field(None)
    virustotal_positives: Optional[int] = Field(None, description="VirusTotal malicious + suspicious")
    virustotal_total: Optional[int] = Field(None, description="VirusTotal total engines")
    virustotal_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    is_known_phishing: bool = Field(False)
    is_disposable_email: bool = Field(False)
    
    # Blacklist data (from MXToolbox or similar)
    blacklists_listed: List[str] = Field(default_factory=list, description="Blacklists where domain is listed")
    blacklist_count: int = Field(0, description="Number of blacklists domain appears on")
    
    # Lookalike analysis
    is_lookalike: bool = Field(False, description="Is lookalike domain")
    lookalike_target: Optional[str] = Field(None, description="Target domain being impersonated")
    lookalike_distance: Optional[int] = Field(None, description="Edit distance to target")
    lookalike_technique: Optional[str] = Field(None, description="Technique: typosquat, homoglyph, etc.")


class IPEnrichment(BaseModel):
    """IP reputation and geolocation."""
    ip_address: str = Field(..., description="IP address")
    
    # Geolocation
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(None, description="ISO country code")
    city: Optional[str] = Field(None, description="City")
    region: Optional[str] = Field(None, description="Region/state")
    lat: Optional[float] = Field(None, description="Latitude")
    lon: Optional[float] = Field(None, description="Longitude")
    timezone: Optional[str] = Field(None, description="Timezone")
    asn: Optional[int] = Field(None, description="AS number")
    as_org: Optional[str] = Field(None, description="AS organization")
    isp: Optional[str] = Field(None, description="ISP name")
    
    # Reputation - AbuseIPDB
    abuseipdb_score: Optional[int] = Field(None, description="AbuseIPDB score 0-100")
    abuseipdb_reports: Optional[int] = Field(None, description="Number of abuse reports")
    abuseipdb_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    
    # Reputation - VirusTotal
    virustotal_stats: Optional[Dict[str, Any]] = Field(None)
    virustotal_positives: Optional[int] = Field(None, description="VirusTotal malicious + suspicious")
    virustotal_total: Optional[int] = Field(None, description="VirusTotal total engines")
    virustotal_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    
    # Blacklist data
    blacklists_listed: List[str] = Field(default_factory=list, description="Blacklists where IP is listed")
    blacklist_count: int = Field(0, description="Number of blacklists IP appears on")
    
    # Classification
    is_vpn: bool = Field(False)
    is_proxy: bool = Field(False)
    is_tor: bool = Field(False)
    is_datacenter: bool = Field(False)
    is_mobile: bool = Field(False, description="Mobile network IP")
    is_known_attacker: bool = Field(False)


class URLEnrichment(BaseModel):
    """URL threat intelligence."""
    url: str = Field(..., description="URL")
    domain: str = Field(..., description="Domain from URL")
    
    # VirusTotal
    virustotal_positives: Optional[int] = Field(None, description="Engines detecting as malicious")
    virustotal_total: Optional[int] = Field(None, description="Total engines scanned")
    virustotal_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    virustotal_categories: List[str] = Field(default_factory=list)
    
    # URLhaus
    urlhaus_status: Optional[str] = Field(None, description="URLhaus status")
    urlhaus_threat: Optional[str] = Field(None, description="Threat type")
    urlhaus_tags: List[str] = Field(default_factory=list)
    
    # PhishTank
    phishtank_in_database: bool = Field(False)
    phishtank_verified: bool = Field(False)
    phishtank_verified_at: Optional[datetime] = Field(None)
    
    # IPQualityScore
    ipqs_risk_score: Optional[int] = Field(None, description="IPQS risk score 0-100")
    ipqs_is_phishing: Optional[bool] = Field(None, description="IPQS phishing detection")
    ipqs_is_malware: Optional[bool] = Field(None, description="IPQS malware detection")
    ipqs_is_suspicious: Optional[bool] = Field(None, description="IPQS suspicious flag")
    ipqs_domain_age: Optional[str] = Field(None, description="Domain age from IPQS")
    ipqs_threat_level: Optional[str] = Field(None, description="IPQS threat level: safe/low/medium/high/critical")
    
    # Google Safe Browsing
    gsb_is_safe: Optional[bool] = Field(None, description="Google Safe Browsing safe status")
    gsb_threats: List[Dict[str, Any]] = Field(default_factory=list, description="GSB threat matches")
    gsb_primary_threat: Optional[str] = Field(None, description="Primary threat type from GSB")
    
    # Overall
    final_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    is_shortened: bool = Field(False)
    redirect_chain: List[str] = Field(default_factory=list)


class AttachmentEnrichment(BaseModel):
    """Attachment threat intelligence."""
    sha256: str = Field(..., description="SHA256 hash")
    md5: str = Field(..., description="MD5 hash")
    filename: str = Field(..., description="Filename")
    
    # VirusTotal
    virustotal_positives: Optional[int] = Field(None)
    virustotal_total: Optional[int] = Field(None)
    virustotal_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)
    virustotal_threat_names: List[str] = Field(default_factory=list)
    
    # MalwareBazaar
    malwarebazaar_known: bool = Field(False)
    malwarebazaar_tags: List[str] = Field(default_factory=list)
    
    # Overall
    final_verdict: ThreatIntelVerdict = Field(ThreatIntelVerdict.UNKNOWN)


class EnrichmentResults(BaseModel):
    """Aggregated enrichment results."""
    sender_domain: Optional[DomainEnrichment] = Field(None)
    reply_to_domain: Optional[DomainEnrichment] = Field(None)
    url_domains: List[DomainEnrichment] = Field(default_factory=list)
    
    originating_ip: Optional[IPEnrichment] = Field(None)
    all_ips: List[IPEnrichment] = Field(default_factory=list)
    
    urls: List[URLEnrichment] = Field(default_factory=list)
    attachments: List[AttachmentEnrichment] = Field(default_factory=list)
