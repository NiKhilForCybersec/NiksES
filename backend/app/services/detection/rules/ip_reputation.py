"""
NiksES IP Reputation Detection Rules

Rules for detecting suspicious/malicious IP addresses using threat intelligence.
"""

from typing import Optional, List, Dict, Any

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults, IPEnrichment, ThreatIntelVerdict
from app.models.detection import RiskLevel

from .base import DetectionRule, RuleMatch, register_rule

# Import centralized scoring configuration
try:
    from app.config.scoring import get_scoring_config
    USE_CENTRALIZED_CONFIG = True
except ImportError:
    USE_CENTRALIZED_CONFIG = False


def get_abuseipdb_thresholds():
    """Get AbuseIPDB thresholds from centralized config or fallback."""
    if USE_CENTRALIZED_CONFIG:
        config = get_scoring_config()
        return (
            config.ti_thresholds.abuseipdb_malicious,
            config.ti_thresholds.abuseipdb_suspicious
        )
    return (75, 25)  # Fallback defaults


# Fallback thresholds (used when config not available)
ABUSEIPDB_MALICIOUS_THRESHOLD = 75  # Score >= 75 = malicious
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 25  # Score >= 25 = suspicious
ABUSEIPDB_HIGH_REPORTS_THRESHOLD = 10  # More than 10 reports is concerning

# =============================================================================
# LEGITIMATE MAIL PROVIDER WHITELIST
# =============================================================================
# These ASNs and PTR patterns belong to major email providers.
# When SPF/DKIM/DMARC pass, these IPs should NOT be flagged as malicious
# even if they have abuse reports (due to their scale, legitimate mail servers
# often get reported by misconfigured systems or spam traps).

LEGITIMATE_MAIL_ASNS = {
    15169,   # Google
    8075,    # Microsoft
    16509,   # Amazon (AWS/SES)
    13335,   # Cloudflare
    14618,   # Amazon
    36351,   # SoftLayer (IBM)
    19527,   # Google Cloud
    396982,  # Google Cloud
}

# ISP/AS organization names for major mail providers
LEGITIMATE_MAIL_ISP_PATTERNS = [
    "google",
    "microsoft",
    "amazon",
    "outlook",
    "office365",
    "sendgrid",
    "mailchimp",
    "proofpoint",
    "mimecast",
    "barracuda",
]


def is_legitimate_mail_provider(
    ip_data: IPEnrichment,
    email: Optional[ParsedEmail] = None
) -> bool:
    """
    Check if IP belongs to a legitimate mail provider with passing authentication.
    
    This prevents false positives on major email infrastructure like Google,
    Microsoft, Amazon SES, etc. which often have abuse reports due to scale.
    
    Args:
        ip_data: IP enrichment data with ASN, ISP, etc.
        email: Optional parsed email to check authentication results
        
    Returns:
        True if this appears to be legitimate mail infrastructure
    """
    # Check if ASN belongs to known mail provider
    is_known_asn = ip_data.asn in LEGITIMATE_MAIL_ASNS if ip_data.asn else False
    
    # Check ISP/AS org name against known patterns
    isp_matches = False
    isp_name = (ip_data.isp or ip_data.as_org or "").lower()
    for pattern in LEGITIMATE_MAIL_ISP_PATTERNS:
        if pattern in isp_name:
            isp_matches = True
            break
    
    # If ASN or ISP matches known provider, check authentication
    if is_known_asn or isp_matches:
        # If we have email data, verify authentication passed
        if email:
            spf_pass = (
                email.spf_result and 
                email.spf_result.result and 
                email.spf_result.result.lower() == 'pass'
            )
            dkim_pass = (
                email.dkim_result and 
                email.dkim_result.result and 
                email.dkim_result.result.lower() == 'pass'
            )
            
            # At least SPF should pass for legitimate provider
            if spf_pass or dkim_pass:
                return True
            
            # If no auth passes but this is definitely a major provider's ASN
            # Be conservative - only whitelist if we're very confident
            if is_known_asn and isp_matches:
                return True
        else:
            # No email auth data but matches known infrastructure
            # Be conservative - if both ASN and ISP match, whitelist
            if is_known_asn and isp_matches:
                return True
    
    return False


@register_rule
class MaliciousIPRule(DetectionRule):
    """Detect emails originating from malicious IP addresses."""
    
    rule_id = "IPREP-001"
    name = "Malicious Originating IP"
    description = "Email originates from an IP flagged as malicious by AbuseIPDB"
    category = "ip_reputation"
    severity = RiskLevel.CRITICAL
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment:
            return None
        
        # Check originating IP first
        malicious_ips = []
        
        # Check originating IP
        if enrichment.originating_ip:
            ip_data = enrichment.originating_ip
            
            # IMPORTANT: Skip if this is a legitimate mail provider
            # (e.g., Google, Microsoft) with passing authentication
            if is_legitimate_mail_provider(ip_data, email):
                return None
            
            if self._is_malicious(ip_data):
                malicious_ips.append({
                    'ip': ip_data.ip_address,
                    'abuseipdb_score': ip_data.abuseipdb_score,
                    'abuseipdb_reports': ip_data.abuseipdb_reports,
                    'country': ip_data.country_code,
                    'isp': ip_data.isp,
                    'is_originating': True,
                })
        
        # Check all IPs in the received chain
        for ip_data in enrichment.all_ips:
            # Skip legitimate providers in chain
            if is_legitimate_mail_provider(ip_data, email):
                continue
                
            if self._is_malicious(ip_data):
                # Avoid duplicates
                if not any(m['ip'] == ip_data.ip_address for m in malicious_ips):
                    malicious_ips.append({
                        'ip': ip_data.ip_address,
                        'abuseipdb_score': ip_data.abuseipdb_score,
                        'abuseipdb_reports': ip_data.abuseipdb_reports,
                        'country': ip_data.country_code,
                        'isp': ip_data.isp,
                        'is_originating': False,
                    })
        
        if malicious_ips:
            evidence = [f"Found {len(malicious_ips)} malicious IP(s):"]
            for ip_info in malicious_ips[:5]:
                origin_tag = " (ORIGINATING)" if ip_info.get('is_originating') else ""
                evidence.append(f"  - {ip_info['ip']}{origin_tag}")
                evidence.append(f"    AbuseIPDB Score: {ip_info['abuseipdb_score']}/100")
                if ip_info.get('abuseipdb_reports'):
                    evidence.append(f"    Reports: {ip_info['abuseipdb_reports']}")
                if ip_info.get('country'):
                    evidence.append(f"    Country: {ip_info['country']}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'malicious_ip',
                    **ip
                } for ip in malicious_ips],
            )
        
        return None
    
    def _is_malicious(self, ip_data: IPEnrichment) -> bool:
        """Check if IP is considered malicious."""
        # Check AbuseIPDB verdict first
        if ip_data.abuseipdb_verdict == ThreatIntelVerdict.MALICIOUS:
            return True
        
        # Check AbuseIPDB score threshold using dynamic config
        malicious_th, _ = get_abuseipdb_thresholds()
        if ip_data.abuseipdb_score is not None and ip_data.abuseipdb_score >= malicious_th:
            return True
        
        # Check VirusTotal verdict
        if ip_data.virustotal_verdict == ThreatIntelVerdict.MALICIOUS:
            return True
        
        # Check known attacker flag
        if ip_data.is_known_attacker:
            return True
        
        return False


@register_rule  
class SuspiciousIPRule(DetectionRule):
    """Detect emails from suspicious IP addresses."""
    
    rule_id = "IPREP-002"
    name = "Suspicious Originating IP"
    description = "Email originates from an IP with moderate abuse reports"
    category = "ip_reputation"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment:
            return None
        
        suspicious_ips = []
        
        # Check originating IP
        if enrichment.originating_ip:
            ip_data = enrichment.originating_ip
            if self._is_suspicious(ip_data):
                suspicious_ips.append({
                    'ip': ip_data.ip_address,
                    'abuseipdb_score': ip_data.abuseipdb_score,
                    'abuseipdb_reports': ip_data.abuseipdb_reports,
                    'country': ip_data.country_code,
                    'isp': ip_data.isp,
                    'is_originating': True,
                })
        
        # Check all IPs
        for ip_data in enrichment.all_ips:
            if self._is_suspicious(ip_data):
                if not any(m['ip'] == ip_data.ip_address for m in suspicious_ips):
                    suspicious_ips.append({
                        'ip': ip_data.ip_address,
                        'abuseipdb_score': ip_data.abuseipdb_score,
                        'abuseipdb_reports': ip_data.abuseipdb_reports,
                        'country': ip_data.country_code,
                        'isp': ip_data.isp,
                        'is_originating': False,
                    })
        
        if suspicious_ips:
            evidence = [f"Found {len(suspicious_ips)} suspicious IP(s):"]
            for ip_info in suspicious_ips[:5]:
                origin_tag = " (ORIGINATING)" if ip_info.get('is_originating') else ""
                evidence.append(f"  - {ip_info['ip']}{origin_tag}")
                if ip_info.get('abuseipdb_score') is not None:
                    evidence.append(f"    AbuseIPDB Score: {ip_info['abuseipdb_score']}/100")
                if ip_info.get('abuseipdb_reports'):
                    evidence.append(f"    Reports: {ip_info['abuseipdb_reports']}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'suspicious_ip',
                    **ip
                } for ip in suspicious_ips],
            )
        
        return None
    
    def _is_suspicious(self, ip_data: IPEnrichment) -> bool:
        """Check if IP is considered suspicious (but not malicious)."""
        # Get dynamic thresholds
        malicious_th, suspicious_th = get_abuseipdb_thresholds()
        
        # Skip if already malicious (handled by IPREP-001)
        if ip_data.abuseipdb_verdict == ThreatIntelVerdict.MALICIOUS:
            return False
        if ip_data.abuseipdb_score is not None and ip_data.abuseipdb_score >= malicious_th:
            return False
        if ip_data.virustotal_verdict == ThreatIntelVerdict.MALICIOUS:
            return False
        if ip_data.is_known_attacker:
            return False
        
        # Check for suspicious indicators
        if ip_data.abuseipdb_verdict == ThreatIntelVerdict.SUSPICIOUS:
            return True
        
        if ip_data.abuseipdb_score is not None and ip_data.abuseipdb_score >= suspicious_th:
            return True
        
        if ip_data.virustotal_verdict == ThreatIntelVerdict.SUSPICIOUS:
            return True
        
        # High number of reports is suspicious
        if ip_data.abuseipdb_reports is not None and ip_data.abuseipdb_reports >= ABUSEIPDB_HIGH_REPORTS_THRESHOLD:
            return True
        
        return False


@register_rule
class TorExitNodeRule(DetectionRule):
    """Detect emails originating from Tor exit nodes."""
    
    rule_id = "IPREP-003"
    name = "Tor Exit Node Detected"
    description = "Email originates from a known Tor exit node"
    category = "ip_reputation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1090.003"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment:
            return None
        
        tor_ips = []
        
        # Check originating IP
        if enrichment.originating_ip and enrichment.originating_ip.is_tor:
            tor_ips.append({
                'ip': enrichment.originating_ip.ip_address,
                'is_originating': True,
            })
        
        # Check all IPs
        for ip_data in enrichment.all_ips:
            if ip_data.is_tor:
                if not any(m['ip'] == ip_data.ip_address for m in tor_ips):
                    tor_ips.append({
                        'ip': ip_data.ip_address,
                        'is_originating': False,
                    })
        
        if tor_ips:
            evidence = [
                f"Detected {len(tor_ips)} Tor exit node(s) in email path:",
                "Tor is often used to anonymize malicious email activity",
            ]
            for ip_info in tor_ips:
                origin_tag = " (ORIGINATING)" if ip_info.get('is_originating') else ""
                evidence.append(f"  - {ip_info['ip']}{origin_tag}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'tor_exit_node',
                    **ip
                } for ip in tor_ips],
            )
        
        return None


@register_rule
class VPNProxyIPRule(DetectionRule):
    """Detect emails originating from VPN or proxy services."""
    
    rule_id = "IPREP-004"
    name = "VPN/Proxy IP Detected"
    description = "Email originates from a known VPN or proxy service"
    category = "ip_reputation"
    severity = RiskLevel.LOW
    mitre_technique = "T1090.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment:
            return None
        
        vpn_proxy_ips = []
        
        # Check originating IP
        if enrichment.originating_ip:
            ip = enrichment.originating_ip
            
            # Skip legitimate mail providers
            if is_legitimate_mail_provider(ip, email):
                return None
            
            if ip.is_vpn or ip.is_proxy:
                vpn_proxy_ips.append({
                    'ip': ip.ip_address,
                    'is_vpn': ip.is_vpn,
                    'is_proxy': ip.is_proxy,
                    'is_originating': True,
                    'isp': ip.isp,
                })
        
        # Check all IPs
        for ip_data in enrichment.all_ips:
            # Skip legitimate providers
            if is_legitimate_mail_provider(ip_data, email):
                continue
                
            if ip_data.is_vpn or ip_data.is_proxy:
                if not any(m['ip'] == ip_data.ip_address for m in vpn_proxy_ips):
                    vpn_proxy_ips.append({
                        'ip': ip_data.ip_address,
                        'is_vpn': ip_data.is_vpn,
                        'is_proxy': ip_data.is_proxy,
                        'is_originating': False,
                        'isp': ip_data.isp,
                    })
        
        if vpn_proxy_ips:
            evidence = [f"Found {len(vpn_proxy_ips)} VPN/Proxy IP(s):"]
            for ip_info in vpn_proxy_ips[:3]:
                origin_tag = " (ORIGINATING)" if ip_info.get('is_originating') else ""
                ip_type = "VPN" if ip_info.get('is_vpn') else "Proxy"
                evidence.append(f"  - {ip_info['ip']} ({ip_type}){origin_tag}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'vpn_proxy_ip',
                    **ip
                } for ip in vpn_proxy_ips],
            )
        
        return None


@register_rule
class DatacenterIPRule(DetectionRule):
    """Detect emails originating from datacenter/hosting IPs."""
    
    rule_id = "IPREP-005"
    name = "Datacenter IP Detected"
    description = "Email originates from a datacenter/hosting provider IP"
    category = "ip_reputation"
    severity = RiskLevel.INFORMATIONAL
    mitre_technique = "T1583.003"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.originating_ip:
            return None
        
        # Only flag if originating IP is datacenter
        ip = enrichment.originating_ip
        
        # Skip legitimate mail providers - major email services
        # run on datacenter infrastructure by design
        if is_legitimate_mail_provider(ip, email):
            return None
        
        if ip.is_datacenter:
            evidence = [
                f"Originating IP: {ip.ip_address}",
                "IP belongs to a datacenter/hosting provider",
                f"ISP/AS: {ip.isp or ip.as_org or 'Unknown'}",
            ]
            
            # Increase severity if combined with other factors
            severity = RiskLevel.LOW if ip.abuseipdb_score and ip.abuseipdb_score > 0 else RiskLevel.INFORMATIONAL
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'datacenter_ip',
                    'ip': ip.ip_address,
                    'isp': ip.isp,
                    'as_org': ip.as_org,
                    'asn': ip.asn,
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class HighAbuseReportsRule(DetectionRule):
    """Detect emails from IPs with high number of abuse reports."""
    
    rule_id = "IPREP-006"
    name = "High Abuse Report Count"
    description = "Email originates from an IP with many abuse reports"
    category = "ip_reputation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.originating_ip:
            return None
        
        ip = enrichment.originating_ip
        
        # Skip legitimate mail providers - they often have abuse reports
        # due to scale, not because they're actually malicious
        if is_legitimate_mail_provider(ip, email):
            return None
        
        # Check for high report count even if score is moderate
        if ip.abuseipdb_reports is not None and ip.abuseipdb_reports >= 50:
            # Higher severity for very high report counts
            if ip.abuseipdb_reports >= 100:
                severity = RiskLevel.CRITICAL
            elif ip.abuseipdb_reports >= 50:
                severity = RiskLevel.HIGH
            else:
                severity = RiskLevel.MEDIUM
            
            evidence = [
                f"Originating IP: {ip.ip_address}",
                f"Abuse Reports: {ip.abuseipdb_reports}",
                f"AbuseIPDB Score: {ip.abuseipdb_score or 'N/A'}/100",
                "High report count indicates repeated malicious activity",
            ]
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'high_abuse_reports',
                    'ip': ip.ip_address,
                    'reports': ip.abuseipdb_reports,
                    'score': ip.abuseipdb_score,
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class IPGeolocationAnomalyRule(DetectionRule):
    """Detect unusual geolocation patterns (high-risk countries)."""
    
    rule_id = "IPREP-007"
    name = "High-Risk Country IP"
    description = "Email originates from a country commonly associated with abuse"
    category = "ip_reputation"
    severity = RiskLevel.LOW
    mitre_technique = "T1566.001"
    
    # Countries with high rates of email abuse (for informational purposes only)
    HIGH_RISK_COUNTRIES = {
        "CN", "RU", "NG", "IN", "BR", "PK", "BD", "VN", "ID", "UA",
    }
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.originating_ip:
            return None
        
        ip = enrichment.originating_ip
        
        if ip.country_code and ip.country_code.upper() in self.HIGH_RISK_COUNTRIES:
            # Only trigger if there are other suspicious signals
            has_other_signals = (
                (ip.abuseipdb_score is not None and ip.abuseipdb_score > 0) or
                ip.is_datacenter or
                ip.is_vpn or
                ip.is_proxy
            )
            
            if has_other_signals:
                evidence = [
                    f"Originating IP: {ip.ip_address}",
                    f"Country: {ip.country or ip.country_code}",
                    "Combined with other suspicious indicators",
                ]
                
                if ip.abuseipdb_score:
                    evidence.append(f"AbuseIPDB Score: {ip.abuseipdb_score}/100")
                
                return self.create_match(
                    evidence=evidence,
                    indicators=[{
                        'type': 'high_risk_country',
                        'ip': ip.ip_address,
                        'country': ip.country_code,
                        'abuseipdb_score': ip.abuseipdb_score,
                    }],
                )
        
        return None
