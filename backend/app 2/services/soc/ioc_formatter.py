"""
NiksES IOC Formatter

Formats and exports IOCs for SOC analyst use.
Supports defanging for safe sharing and multiple export formats.
"""

import re
import json
import csv
import io
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


class DefangMode(str, Enum):
    """Defanging mode for IOCs."""
    NONE = "none"           # No defanging
    BRACKETS = "brackets"   # evil.com -> evil[.]com
    FULL = "full"           # hxxps://evil[.]com


@dataclass
class ExtractedIOCs:
    """Container for extracted IOCs."""
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    hashes_md5: List[str] = field(default_factory=list)
    hashes_sha1: List[str] = field(default_factory=list)
    hashes_sha256: List[str] = field(default_factory=list)
    file_names: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List[str]]:
        return {
            'domains': self.domains,
            'urls': self.urls,
            'ips': self.ips,
            'email_addresses': self.email_addresses,
            'hashes_md5': self.hashes_md5,
            'hashes_sha1': self.hashes_sha1,
            'hashes_sha256': self.hashes_sha256,
            'file_names': self.file_names,
        }
    
    def total_count(self) -> int:
        return (len(self.domains) + len(self.urls) + len(self.ips) + 
                len(self.email_addresses) + len(self.hashes_md5) + 
                len(self.hashes_sha1) + len(self.hashes_sha256) + len(self.file_names))


class IOCFormatter:
    """
    IOC extraction and formatting for SOC analysts.
    
    Supports:
    - Extraction from analysis results
    - Defanging for safe sharing
    - Multiple export formats (CSV, JSON, plain text)
    - SIEM-ready formatting
    """
    
    # Common TLDs for domain validation
    COMMON_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'io', 'co', 'info', 'biz',
        'ru', 'cn', 'uk', 'de', 'fr', 'jp', 'br', 'in', 'au', 'xyz',
        'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'su', 'ws'
    }
    
    @staticmethod
    def defang_url(url: str, mode: DefangMode = DefangMode.BRACKETS) -> str:
        """Defang a URL for safe sharing."""
        if mode == DefangMode.NONE:
            return url
        
        result = url
        
        # First replace dots in domain part (before protocol substitution)
        # Find domain part (after :// and before first /)
        match = re.match(r'^(https?://|ftp://)?([^/]+)(.*)', result, re.IGNORECASE)
        if match:
            prefix = match.group(1) or ''
            domain = match.group(2)
            path = match.group(3) or ''
            
            # Defang domain dots
            domain = domain.replace('.', '[.]')
            result = prefix + domain + path
        else:
            # Simple replacement
            result = result.replace('.', '[.]')
        
        # Now replace protocol for FULL mode
        if mode == DefangMode.FULL:
            result = re.sub(r'^http://', 'hxxp://', result, flags=re.IGNORECASE)
            result = re.sub(r'^https://', 'hxxps://', result, flags=re.IGNORECASE)
            result = re.sub(r'^ftp://', 'fxp://', result, flags=re.IGNORECASE)
        
        return result
        
        return result
    
    @staticmethod
    def defang_domain(domain: str, mode: DefangMode = DefangMode.BRACKETS) -> str:
        """Defang a domain for safe sharing."""
        if mode == DefangMode.NONE:
            return domain
        
        return domain.replace('.', '[.]')
    
    @staticmethod
    def defang_ip(ip: str, mode: DefangMode = DefangMode.BRACKETS) -> str:
        """Defang an IP address for safe sharing."""
        if mode == DefangMode.NONE:
            return ip
        
        return ip.replace('.', '[.]')
    
    @staticmethod
    def defang_email(email: str, mode: DefangMode = DefangMode.BRACKETS) -> str:
        """Defang an email address for safe sharing."""
        if mode == DefangMode.NONE:
            return email
        
        result = email.replace('@', '[@]')
        result = result.replace('.', '[.]')
        return result
    
    @staticmethod
    def refang(text: str) -> str:
        """Remove defanging from text (reverse defang)."""
        result = text
        result = result.replace('[.]', '.')
        result = result.replace('[@]', '@')
        result = result.replace('hxxp://', 'http://')
        result = result.replace('hxxps://', 'https://')
        result = result.replace('fxp://', 'ftp://')
        return result
    
    @classmethod
    def extract_from_analysis(cls, analysis_result: Dict[str, Any]) -> ExtractedIOCs:
        """Extract all IOCs from an analysis result."""
        iocs = ExtractedIOCs()
        
        domains_set: Set[str] = set()
        urls_set: Set[str] = set()
        ips_set: Set[str] = set()
        emails_set: Set[str] = set()
        md5_set: Set[str] = set()
        sha1_set: Set[str] = set()
        sha256_set: Set[str] = set()
        files_set: Set[str] = set()
        
        # Extract from email data
        email = analysis_result.get('email', {})
        
        # Sender domain/email
        sender = email.get('sender', {})
        if isinstance(sender, dict):
            if sender.get('domain'):
                domains_set.add(sender['domain'].lower())
            if sender.get('email'):
                emails_set.add(sender['email'].lower())
        
        # Reply-to
        reply_to = email.get('reply_to', [])
        if isinstance(reply_to, list):
            for rt in reply_to:
                if isinstance(rt, dict):
                    if rt.get('email'):
                        emails_set.add(rt['email'].lower())
                    if rt.get('domain'):
                        domains_set.add(rt['domain'].lower())
                elif isinstance(rt, str) and '@' in rt:
                    emails_set.add(rt.lower())
        
        # URLs
        urls = email.get('urls', [])
        for url_data in urls:
            if isinstance(url_data, dict):
                url = url_data.get('url', '')
                domain = url_data.get('domain', '')
            else:
                url = str(url_data)
                domain = ''
            
            if url:
                urls_set.add(url)
            if domain:
                domains_set.add(domain.lower())
        
        # Attachments
        attachments = email.get('attachments', [])
        for att in attachments:
            if isinstance(att, dict):
                filename = att.get('filename', '')
                if filename:
                    files_set.add(filename)
                
                # Hashes
                if att.get('md5'):
                    md5_set.add(att['md5'].lower())
                if att.get('sha1'):
                    sha1_set.add(att['sha1'].lower())
                if att.get('sha256'):
                    sha256_set.add(att['sha256'].lower())
                
                # Extracted IOCs from static analysis
                for url in att.get('extracted_urls', []):
                    if url:
                        urls_set.add(url)
                        # Also extract domain from URL
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            if parsed.netloc:
                                domains_set.add(parsed.netloc.lower())
                        except:
                            pass
                
                for ip in att.get('extracted_ips', []):
                    if ip and cls._is_valid_ip(ip):
                        ips_set.add(ip)
        
        # Extract from enrichment
        enrichment = analysis_result.get('enrichment', {})
        
        # Originating IP
        orig_ip = enrichment.get('originating_ip', {})
        if isinstance(orig_ip, dict) and orig_ip.get('ip'):
            ips_set.add(orig_ip['ip'])
        elif isinstance(orig_ip, str):
            ips_set.add(orig_ip)
        
        # Sender domain enrichment
        sender_domain = enrichment.get('sender_domain', {})
        if isinstance(sender_domain, dict) and sender_domain.get('domain'):
            domains_set.add(sender_domain['domain'].lower())
        
        # Extract from headers
        headers = email.get('headers', {})
        
        # X-Originating-IP
        x_orig_ip = headers.get('x-originating-ip', '')
        if x_orig_ip:
            # Clean up brackets often seen
            clean_ip = x_orig_ip.strip('[]')
            if cls._is_valid_ip(clean_ip):
                ips_set.add(clean_ip)
        
        # Extract from IOCs section if present
        iocs_section = analysis_result.get('iocs', {})
        if iocs_section:
            for d in iocs_section.get('domains', []):
                domains_set.add(d.lower())
            for u in iocs_section.get('urls', []):
                urls_set.add(u)
            for ip in iocs_section.get('ips', []):
                ips_set.add(ip)
            for e in iocs_section.get('email_addresses', []):
                emails_set.add(e.lower())
            for h in iocs_section.get('hashes', []):
                if isinstance(h, dict):
                    hash_type = h.get('type', '').lower()
                    hash_val = h.get('value', '').lower()
                    if hash_type == 'md5':
                        md5_set.add(hash_val)
                    elif hash_type == 'sha1':
                        sha1_set.add(hash_val)
                    elif hash_type == 'sha256':
                        sha256_set.add(hash_val)
        
        # Convert sets to sorted lists
        iocs.domains = sorted(list(domains_set))
        iocs.urls = sorted(list(urls_set))
        iocs.ips = sorted(list(ips_set))
        iocs.email_addresses = sorted(list(emails_set))
        iocs.hashes_md5 = sorted(list(md5_set))
        iocs.hashes_sha1 = sorted(list(sha1_set))
        iocs.hashes_sha256 = sorted(list(sha256_set))
        iocs.file_names = sorted(list(files_set))
        
        return iocs
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    @classmethod
    def format_for_copy(
        cls,
        iocs: ExtractedIOCs,
        defang_mode: DefangMode = DefangMode.BRACKETS,
        include_types: Optional[List[str]] = None,
    ) -> str:
        """
        Format IOCs for clipboard copy.
        
        Args:
            iocs: Extracted IOCs
            defang_mode: How to defang IOCs
            include_types: List of IOC types to include (None = all)
            
        Returns:
            Formatted string ready for copy
        """
        lines = []
        
        types_to_include = include_types or [
            'domains', 'urls', 'ips', 'email_addresses',
            'hashes_md5', 'hashes_sha1', 'hashes_sha256', 'file_names'
        ]
        
        if 'domains' in types_to_include and iocs.domains:
            lines.append("=== DOMAINS ===")
            for d in iocs.domains:
                lines.append(cls.defang_domain(d, defang_mode))
            lines.append("")
        
        if 'urls' in types_to_include and iocs.urls:
            lines.append("=== URLs ===")
            for u in iocs.urls:
                lines.append(cls.defang_url(u, defang_mode))
            lines.append("")
        
        if 'ips' in types_to_include and iocs.ips:
            lines.append("=== IP ADDRESSES ===")
            for ip in iocs.ips:
                lines.append(cls.defang_ip(ip, defang_mode))
            lines.append("")
        
        if 'email_addresses' in types_to_include and iocs.email_addresses:
            lines.append("=== EMAIL ADDRESSES ===")
            for e in iocs.email_addresses:
                lines.append(cls.defang_email(e, defang_mode))
            lines.append("")
        
        if 'hashes_sha256' in types_to_include and iocs.hashes_sha256:
            lines.append("=== SHA256 HASHES ===")
            for h in iocs.hashes_sha256:
                lines.append(h)
            lines.append("")
        
        if 'hashes_sha1' in types_to_include and iocs.hashes_sha1:
            lines.append("=== SHA1 HASHES ===")
            for h in iocs.hashes_sha1:
                lines.append(h)
            lines.append("")
        
        if 'hashes_md5' in types_to_include and iocs.hashes_md5:
            lines.append("=== MD5 HASHES ===")
            for h in iocs.hashes_md5:
                lines.append(h)
            lines.append("")
        
        if 'file_names' in types_to_include and iocs.file_names:
            lines.append("=== FILE NAMES ===")
            for f in iocs.file_names:
                lines.append(f)
            lines.append("")
        
        return "\n".join(lines).strip()
    
    @classmethod
    def export_csv(
        cls,
        iocs: ExtractedIOCs,
        defang_mode: DefangMode = DefangMode.NONE,
        include_header: bool = True,
    ) -> str:
        """
        Export IOCs as CSV for SIEM import.
        
        Format: type,value,defanged_value
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        if include_header:
            writer.writerow(['type', 'value', 'defanged'])
        
        for d in iocs.domains:
            writer.writerow(['domain', d, cls.defang_domain(d, defang_mode)])
        
        for u in iocs.urls:
            writer.writerow(['url', u, cls.defang_url(u, defang_mode)])
        
        for ip in iocs.ips:
            writer.writerow(['ip', ip, cls.defang_ip(ip, defang_mode)])
        
        for e in iocs.email_addresses:
            writer.writerow(['email', e, cls.defang_email(e, defang_mode)])
        
        for h in iocs.hashes_sha256:
            writer.writerow(['sha256', h, h])
        
        for h in iocs.hashes_sha1:
            writer.writerow(['sha1', h, h])
        
        for h in iocs.hashes_md5:
            writer.writerow(['md5', h, h])
        
        for f in iocs.file_names:
            writer.writerow(['filename', f, f])
        
        return output.getvalue()
    
    @classmethod
    def export_json(
        cls,
        iocs: ExtractedIOCs,
        defang_mode: DefangMode = DefangMode.NONE,
        siem_format: str = "generic",
    ) -> str:
        """
        Export IOCs as JSON for SIEM import.
        
        Args:
            iocs: Extracted IOCs
            defang_mode: Defanging mode
            siem_format: "generic", "splunk", "elastic", "sentinel"
        """
        if siem_format == "splunk":
            return cls._export_splunk_json(iocs, defang_mode)
        elif siem_format == "elastic":
            return cls._export_elastic_json(iocs, defang_mode)
        elif siem_format == "sentinel":
            return cls._export_sentinel_json(iocs, defang_mode)
        else:
            return cls._export_generic_json(iocs, defang_mode)
    
    @classmethod
    def _export_generic_json(cls, iocs: ExtractedIOCs, defang_mode: DefangMode) -> str:
        """Export as generic JSON."""
        data = {
            "extracted_at": datetime.utcnow().isoformat() + "Z",
            "total_iocs": iocs.total_count(),
            "iocs": {
                "domains": [
                    {"value": d, "defanged": cls.defang_domain(d, defang_mode)}
                    for d in iocs.domains
                ],
                "urls": [
                    {"value": u, "defanged": cls.defang_url(u, defang_mode)}
                    for u in iocs.urls
                ],
                "ips": [
                    {"value": ip, "defanged": cls.defang_ip(ip, defang_mode)}
                    for ip in iocs.ips
                ],
                "emails": [
                    {"value": e, "defanged": cls.defang_email(e, defang_mode)}
                    for e in iocs.email_addresses
                ],
                "hashes": {
                    "sha256": iocs.hashes_sha256,
                    "sha1": iocs.hashes_sha1,
                    "md5": iocs.hashes_md5,
                },
                "files": iocs.file_names,
            }
        }
        return json.dumps(data, indent=2)
    
    @classmethod
    def _export_splunk_json(cls, iocs: ExtractedIOCs, defang_mode: DefangMode) -> str:
        """Export in Splunk-compatible format."""
        events = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for d in iocs.domains:
            events.append({
                "time": timestamp,
                "event": {"ioc_type": "domain", "ioc_value": d},
                "sourcetype": "nikses:ioc"
            })
        
        for u in iocs.urls:
            events.append({
                "time": timestamp,
                "event": {"ioc_type": "url", "ioc_value": u},
                "sourcetype": "nikses:ioc"
            })
        
        for ip in iocs.ips:
            events.append({
                "time": timestamp,
                "event": {"ioc_type": "ip", "ioc_value": ip},
                "sourcetype": "nikses:ioc"
            })
        
        for h in iocs.hashes_sha256:
            events.append({
                "time": timestamp,
                "event": {"ioc_type": "sha256", "ioc_value": h},
                "sourcetype": "nikses:ioc"
            })
        
        # Return as newline-delimited JSON for Splunk HEC
        return "\n".join(json.dumps(e) for e in events)
    
    @classmethod
    def _export_elastic_json(cls, iocs: ExtractedIOCs, defang_mode: DefangMode) -> str:
        """Export in Elasticsearch bulk format."""
        lines = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for d in iocs.domains:
            lines.append(json.dumps({"index": {"_index": "nikses-iocs"}}))
            lines.append(json.dumps({
                "@timestamp": timestamp,
                "ioc.type": "domain",
                "ioc.value": d,
                "tags": ["email-analysis"]
            }))
        
        for u in iocs.urls:
            lines.append(json.dumps({"index": {"_index": "nikses-iocs"}}))
            lines.append(json.dumps({
                "@timestamp": timestamp,
                "ioc.type": "url",
                "ioc.value": u,
                "tags": ["email-analysis"]
            }))
        
        for ip in iocs.ips:
            lines.append(json.dumps({"index": {"_index": "nikses-iocs"}}))
            lines.append(json.dumps({
                "@timestamp": timestamp,
                "ioc.type": "ip",
                "ioc.value": ip,
                "tags": ["email-analysis"]
            }))
        
        return "\n".join(lines)
    
    @classmethod
    def _export_sentinel_json(cls, iocs: ExtractedIOCs, defang_mode: DefangMode) -> str:
        """Export in Microsoft Sentinel format."""
        indicators = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        for d in iocs.domains:
            indicators.append({
                "kind": "indicator",
                "properties": {
                    "patternType": "domain-name",
                    "pattern": f"[domain-name:value = '{d}']",
                    "validFrom": timestamp,
                    "source": "NiksES Email Analysis",
                    "threatTypes": ["Phishing"]
                }
            })
        
        for u in iocs.urls:
            indicators.append({
                "kind": "indicator",
                "properties": {
                    "patternType": "url",
                    "pattern": f"[url:value = '{u}']",
                    "validFrom": timestamp,
                    "source": "NiksES Email Analysis",
                    "threatTypes": ["Phishing"]
                }
            })
        
        for ip in iocs.ips:
            indicators.append({
                "kind": "indicator",
                "properties": {
                    "patternType": "ipv4-addr",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "validFrom": timestamp,
                    "source": "NiksES Email Analysis",
                    "threatTypes": ["Phishing"]
                }
            })
        
        return json.dumps({"value": indicators}, indent=2)
    
    @classmethod
    def format_for_block_list(
        cls,
        iocs: ExtractedIOCs,
        list_type: str = "domain",
    ) -> str:
        """
        Format IOCs for firewall/proxy block list.
        
        Args:
            iocs: Extracted IOCs
            list_type: "domain", "url", "ip", or "all"
        """
        lines = []
        
        if list_type in ("domain", "all"):
            for d in iocs.domains:
                lines.append(d)
        
        if list_type in ("url", "all"):
            for u in iocs.urls:
                lines.append(u)
        
        if list_type in ("ip", "all"):
            for ip in iocs.ips:
                lines.append(ip)
        
        return "\n".join(lines)
