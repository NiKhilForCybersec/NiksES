"""
NiksES Detection Rule Generators

Auto-generate YARA and Sigma rules from email analysis results.
Ready for deployment to EDR/SIEM systems.
"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class GeneratedRule:
    """Container for a generated detection rule."""
    rule_type: str  # "yara" or "sigma"
    rule_name: str
    rule_content: str
    description: str
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_type": self.rule_type,
            "rule_name": self.rule_name,
            "rule_content": self.rule_content,
            "description": self.description,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity,
        }


class YARARuleGenerator:
    """
    Generate YARA rules from email analysis.
    
    Creates rules to detect:
    - Similar phishing emails
    - Malicious attachment patterns
    - Specific sender patterns
    - URL patterns
    """
    
    @classmethod
    def generate_from_analysis(
        cls,
        analysis_result: Dict[str, Any],
        rule_name_prefix: str = "NiksES",
    ) -> List[GeneratedRule]:
        """
        Generate YARA rules from analysis result.
        
        Args:
            analysis_result: Full analysis result dictionary
            rule_name_prefix: Prefix for rule names
            
        Returns:
            List of generated YARA rules
        """
        rules = []
        
        email = analysis_result.get('email', {})
        detection = analysis_result.get('detection', {})
        
        # Get classification for rule naming
        classification = detection.get('primary_classification', 'unknown')
        if hasattr(classification, 'value'):
            classification = classification.value
        classification = str(classification).replace(' ', '_')
        
        # Generate email pattern rule
        email_rule = cls._generate_email_pattern_rule(
            email, detection, rule_name_prefix, classification
        )
        if email_rule:
            rules.append(email_rule)
        
        # Generate attachment rule if attachments present
        attachments = email.get('attachments', [])
        if attachments:
            att_rule = cls._generate_attachment_rule(
                attachments, rule_name_prefix, classification
            )
            if att_rule:
                rules.append(att_rule)
        
        # Generate URL pattern rule
        urls = email.get('urls', [])
        if urls:
            url_rule = cls._generate_url_pattern_rule(
                urls, rule_name_prefix, classification
            )
            if url_rule:
                rules.append(url_rule)
        
        return rules
    
    @classmethod
    def _generate_email_pattern_rule(
        cls,
        email: Dict[str, Any],
        detection: Dict[str, Any],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate YARA rule for email patterns."""
        
        conditions = []
        strings_section = []
        string_idx = 0
        
        # Subject patterns
        subject = email.get('subject', '')
        if subject and len(subject) > 10:
            # Extract key words from subject
            key_words = cls._extract_key_patterns(subject)
            for word in key_words[:3]:
                strings_section.append(f'        $subj{string_idx} = "{word}" nocase')
                conditions.append(f'$subj{string_idx}')
                string_idx += 1
        
        # Sender patterns
        sender = email.get('sender', {})
        if isinstance(sender, dict):
            sender_domain = sender.get('domain', '')
            if sender_domain:
                strings_section.append(f'        $sender_domain = "{sender_domain}" nocase')
                conditions.append('$sender_domain')
        
        # Body patterns (key phrases)
        body = email.get('body_text', '')
        if body:
            key_phrases = cls._extract_key_patterns(body)
            for phrase in key_phrases[:5]:
                if len(phrase) > 5:
                    strings_section.append(f'        $body{string_idx} = "{phrase}" nocase')
                    string_idx += 1
        
        if not strings_section:
            return None
        
        # Build rule
        timestamp = datetime.utcnow().strftime('%Y-%m-%d')
        rule_name = f"{prefix}_{classification}_{timestamp.replace('-', '')}"
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
        
        rule_content = f'''rule {rule_name} {{
    meta:
        description = "Detects {classification} email pattern"
        author = "NiksES Auto-Generated"
        date = "{timestamp}"
        severity = "{detection.get('risk_level', 'medium')}"
        classification = "{classification}"
        
    strings:
{chr(10).join(strings_section)}
        
    condition:
        {' or '.join(conditions[:3]) if len(conditions) <= 3 else f"any of them"}
}}'''
        
        return GeneratedRule(
            rule_type="yara",
            rule_name=rule_name,
            rule_content=rule_content,
            description=f"Detects {classification} emails with similar patterns",
            tags=["email", "phishing", classification],
            mitre_techniques=["T1566.001"],
            severity=str(detection.get('risk_level', 'medium')),
        )
    
    @classmethod
    def _generate_attachment_rule(
        cls,
        attachments: List[Dict[str, Any]],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate YARA rule for attachment patterns."""
        
        strings_section = []
        
        for att in attachments[:3]:
            if isinstance(att, dict):
                # Filename pattern
                filename = att.get('filename', '')
                if filename:
                    # Extract extension
                    ext = filename.rsplit('.', 1)[-1] if '.' in filename else ''
                    if ext:
                        strings_section.append(f'        $ext_{ext} = ".{ext}" nocase')
                
                # Hash
                sha256 = att.get('sha256', '')
                if sha256:
                    strings_section.append(f'        // SHA256: {sha256}')
        
        if not strings_section:
            return None
        
        timestamp = datetime.utcnow().strftime('%Y-%m-%d')
        rule_name = f"{prefix}_attachment_{classification}_{timestamp.replace('-', '')}"
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
        
        rule_content = f'''rule {rule_name} {{
    meta:
        description = "Detects suspicious attachment from {classification} email"
        author = "NiksES Auto-Generated"
        date = "{timestamp}"
        
    strings:
{chr(10).join(strings_section)}
        
    condition:
        any of them
}}'''
        
        return GeneratedRule(
            rule_type="yara",
            rule_name=rule_name,
            rule_content=rule_content,
            description=f"Detects attachments from {classification} emails",
            tags=["attachment", "malware", classification],
            mitre_techniques=["T1566.001"],
            severity="high",
        )
    
    @classmethod
    def _generate_url_pattern_rule(
        cls,
        urls: List[Dict[str, Any]],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate YARA rule for URL patterns."""
        
        strings_section = []
        domains = set()
        
        for url_data in urls[:10]:
            if isinstance(url_data, dict):
                domain = url_data.get('domain', '')
                url = url_data.get('url', '')
            else:
                url = str(url_data)
                # Extract domain from URL
                match = re.search(r'https?://([^/]+)', url)
                domain = match.group(1) if match else ''
            
            if domain and domain not in domains:
                domains.add(domain)
                safe_domain = domain.replace('.', '_')
                strings_section.append(f'        $domain_{safe_domain} = "{domain}" nocase')
        
        if not strings_section:
            return None
        
        timestamp = datetime.utcnow().strftime('%Y-%m-%d')
        rule_name = f"{prefix}_url_{classification}_{timestamp.replace('-', '')}"
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
        
        rule_content = f'''rule {rule_name} {{
    meta:
        description = "Detects URLs/domains from {classification} email"
        author = "NiksES Auto-Generated"
        date = "{timestamp}"
        
    strings:
{chr(10).join(strings_section)}
        
    condition:
        any of them
}}'''
        
        return GeneratedRule(
            rule_type="yara",
            rule_name=rule_name,
            rule_content=rule_content,
            description=f"Detects malicious URLs from {classification} emails",
            tags=["url", "phishing", classification],
            mitre_techniques=["T1566.002"],
            severity="high",
        )
    
    @staticmethod
    def _extract_key_patterns(text: str) -> List[str]:
        """Extract key patterns/phrases from text."""
        # Common phishing/suspicious keywords
        suspicious_keywords = [
            'urgent', 'immediate', 'action required', 'verify', 'confirm',
            'suspended', 'blocked', 'unusual activity', 'security alert',
            'click here', 'sign in', 'log in', 'password', 'account',
            'invoice', 'payment', 'wire transfer', 'gift card'
        ]
        
        found = []
        text_lower = text.lower()
        
        for keyword in suspicious_keywords:
            if keyword in text_lower:
                found.append(keyword)
        
        return found[:5]


class SigmaRuleGenerator:
    """
    Generate Sigma rules from email analysis.
    
    Creates rules for SIEM detection of:
    - Email gateway logs
    - DNS queries to malicious domains
    - Network connections to malicious IPs
    - File creation events for attachments
    """
    
    @classmethod
    def generate_from_analysis(
        cls,
        analysis_result: Dict[str, Any],
        rule_name_prefix: str = "NiksES",
    ) -> List[GeneratedRule]:
        """
        Generate Sigma rules from analysis result.
        
        Args:
            analysis_result: Full analysis result dictionary
            rule_name_prefix: Prefix for rule names
            
        Returns:
            List of generated Sigma rules
        """
        rules = []
        
        email = analysis_result.get('email', {})
        detection = analysis_result.get('detection', {})
        iocs = analysis_result.get('iocs', {})
        
        classification = detection.get('primary_classification', 'unknown')
        if hasattr(classification, 'value'):
            classification = classification.value
        
        # Domain-based detection rule
        domains = iocs.get('domains', [])
        if domains:
            domain_rule = cls._generate_dns_rule(domains, rule_name_prefix, classification)
            if domain_rule:
                rules.append(domain_rule)
        
        # IP-based detection rule
        ips = iocs.get('ips', [])
        if ips:
            ip_rule = cls._generate_network_rule(ips, rule_name_prefix, classification)
            if ip_rule:
                rules.append(ip_rule)
        
        # Email sender rule
        sender = email.get('sender', {})
        if isinstance(sender, dict) and sender.get('email'):
            email_rule = cls._generate_email_gateway_rule(
                sender, email.get('subject', ''), rule_name_prefix, classification
            )
            if email_rule:
                rules.append(email_rule)
        
        # URL-based proxy rule
        urls = email.get('urls', [])
        if urls:
            proxy_rule = cls._generate_proxy_rule(urls, rule_name_prefix, classification)
            if proxy_rule:
                rules.append(proxy_rule)
        
        return rules
    
    @classmethod
    def _generate_dns_rule(
        cls,
        domains: List[str],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate Sigma rule for DNS queries."""
        
        if not domains:
            return None
        
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        rule_id = f"{prefix.lower()}-dns-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        domain_list = "\n".join(f"            - '{d}'" for d in domains[:20])
        
        rule_content = f'''title: {prefix} - Malicious Domain DNS Query ({classification})
id: {rule_id}
status: experimental
description: Detects DNS queries to domains identified in {classification} email analysis
author: NiksES Auto-Generated
date: {timestamp}
tags:
    - attack.initial_access
    - attack.t1566
    - attack.phishing
logsource:
    category: dns
detection:
    selection:
        query|contains:
{domain_list}
    condition: selection
falsepositives:
    - Legitimate access to these domains (verify before blocking)
level: high'''
        
        return GeneratedRule(
            rule_type="sigma",
            rule_name=f"{prefix}_dns_{classification}",
            rule_content=rule_content,
            description=f"Detects DNS queries to malicious domains from {classification}",
            tags=["dns", "phishing", classification],
            mitre_techniques=["T1566"],
            severity="high",
        )
    
    @classmethod
    def _generate_network_rule(
        cls,
        ips: List[str],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate Sigma rule for network connections."""
        
        if not ips:
            return None
        
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        rule_id = f"{prefix.lower()}-net-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        ip_list = "\n".join(f"            - '{ip}'" for ip in ips[:20])
        
        rule_content = f'''title: {prefix} - Connection to Malicious IP ({classification})
id: {rule_id}
status: experimental
description: Detects network connections to IPs identified in {classification} email analysis
author: NiksES Auto-Generated
date: {timestamp}
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: firewall
detection:
    selection:
        dst_ip:
{ip_list}
    condition: selection
falsepositives:
    - Legitimate services using these IPs
level: high'''
        
        return GeneratedRule(
            rule_type="sigma",
            rule_name=f"{prefix}_network_{classification}",
            rule_content=rule_content,
            description=f"Detects connections to malicious IPs from {classification}",
            tags=["network", "c2", classification],
            mitre_techniques=["T1071"],
            severity="high",
        )
    
    @classmethod
    def _generate_email_gateway_rule(
        cls,
        sender: Dict[str, Any],
        subject: str,
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate Sigma rule for email gateway logs."""
        
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        rule_id = f"{prefix.lower()}-email-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        sender_email = sender.get('email', '')
        sender_domain = sender.get('domain', '')
        
        conditions = []
        if sender_email:
            conditions.append(f"            sender|contains: '{sender_email}'")
        if sender_domain:
            conditions.append(f"            sender|endswith: '@{sender_domain}'")
        
        if not conditions:
            return None
        
        rule_content = f'''title: {prefix} - Phishing Email Pattern ({classification})
id: {rule_id}
status: experimental
description: Detects emails matching {classification} pattern from sender analysis
author: NiksES Auto-Generated
date: {timestamp}
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    category: email
    product: exchange
detection:
    selection:
{chr(10).join(conditions)}
    condition: selection
falsepositives:
    - Legitimate emails from this sender
level: medium'''
        
        return GeneratedRule(
            rule_type="sigma",
            rule_name=f"{prefix}_email_{classification}",
            rule_content=rule_content,
            description=f"Detects emails from {classification} sender",
            tags=["email", "phishing", classification],
            mitre_techniques=["T1566.001"],
            severity="medium",
        )
    
    @classmethod
    def _generate_proxy_rule(
        cls,
        urls: List[Dict[str, Any]],
        prefix: str,
        classification: str,
    ) -> Optional[GeneratedRule]:
        """Generate Sigma rule for proxy logs."""
        
        domains = set()
        for url_data in urls:
            if isinstance(url_data, dict):
                domain = url_data.get('domain', '')
            else:
                match = re.search(r'https?://([^/]+)', str(url_data))
                domain = match.group(1) if match else ''
            if domain:
                domains.add(domain)
        
        if not domains:
            return None
        
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        rule_id = f"{prefix.lower()}-proxy-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        domain_list = "\n".join(f"            - '{d}'" for d in list(domains)[:20])
        
        rule_content = f'''title: {prefix} - Access to Phishing URL ({classification})
id: {rule_id}
status: experimental
description: Detects web access to URLs identified in {classification} email analysis
author: NiksES Auto-Generated
date: {timestamp}
tags:
    - attack.initial_access
    - attack.t1566.002
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
{domain_list}
    condition: selection
falsepositives:
    - Legitimate access to these domains
level: high'''
        
        return GeneratedRule(
            rule_type="sigma",
            rule_name=f"{prefix}_proxy_{classification}",
            rule_content=rule_content,
            description=f"Detects access to malicious URLs from {classification}",
            tags=["proxy", "phishing", classification],
            mitre_techniques=["T1566.002"],
            severity="high",
        )
