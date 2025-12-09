"""
NiksES Incident Ticket Generator

Generates pre-filled incident tickets for ITSM systems.
Supports ServiceNow, Jira, and generic formats.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import json


class TicketFormat(str, Enum):
    """Supported ticket formats."""
    GENERIC = "generic"
    SERVICENOW = "servicenow"
    JIRA = "jira"
    MARKDOWN = "markdown"


class IncidentTicketGenerator:
    """
    Generate incident tickets from email analysis.
    
    Creates ready-to-paste tickets with:
    - Severity and classification
    - IOC summary
    - Key findings
    - Recommended actions
    - Timeline
    """
    
    SEVERITY_MAP = {
        'critical': {'servicenow': '1', 'jira': 'Highest', 'generic': 'P1'},
        'high': {'servicenow': '2', 'jira': 'High', 'generic': 'P2'},
        'medium': {'servicenow': '3', 'jira': 'Medium', 'generic': 'P3'},
        'low': {'servicenow': '4', 'jira': 'Low', 'generic': 'P4'},
        'informational': {'servicenow': '5', 'jira': 'Lowest', 'generic': 'P5'},
    }
    
    CATEGORY_MAP = {
        'phishing': 'Phishing Attack',
        'spear_phishing': 'Spear Phishing Attack',
        'credential_harvesting': 'Credential Harvesting',
        'bec': 'Business Email Compromise',
        'invoice_fraud': 'Invoice Fraud',
        'gift_card_scam': 'Gift Card Scam',
        'malware_delivery': 'Malware Delivery',
        'ransomware': 'Ransomware Delivery',
        'brand_impersonation': 'Brand Impersonation',
        'spam': 'Spam',
        'benign': 'False Positive',
    }
    
    @classmethod
    def generate(
        cls,
        analysis_result: Dict[str, Any],
        format: TicketFormat = TicketFormat.GENERIC,
        analyst_name: str = "",
        additional_notes: str = "",
    ) -> Dict[str, Any]:
        """
        Generate an incident ticket from analysis result.
        
        Args:
            analysis_result: Full analysis result
            format: Ticket format
            analyst_name: Analyst name for assignment
            additional_notes: Extra notes to include
            
        Returns:
            Dictionary with ticket content
        """
        if format == TicketFormat.SERVICENOW:
            return cls._generate_servicenow(analysis_result, analyst_name, additional_notes)
        elif format == TicketFormat.JIRA:
            return cls._generate_jira(analysis_result, analyst_name, additional_notes)
        elif format == TicketFormat.MARKDOWN:
            return cls._generate_markdown(analysis_result, analyst_name, additional_notes)
        else:
            return cls._generate_generic(analysis_result, analyst_name, additional_notes)
    
    @classmethod
    def _extract_fields(cls, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract common fields from analysis result."""
        email = analysis_result.get('email', {})
        detection = analysis_result.get('detection', {})
        ai_triage = analysis_result.get('ai_triage', {})
        iocs = analysis_result.get('iocs', {})
        
        # Get classification
        classification = detection.get('primary_classification', 'unknown')
        if hasattr(classification, 'value'):
            classification = classification.value
        
        # Get risk level
        risk_level = detection.get('risk_level', 'medium')
        if hasattr(risk_level, 'value'):
            risk_level = risk_level.value
        
        # Get sender info
        sender = email.get('sender', {})
        sender_email = sender.get('email', 'unknown') if isinstance(sender, dict) else str(sender)
        sender_domain = sender.get('domain', 'unknown') if isinstance(sender, dict) else 'unknown'
        
        # Get recipients
        recipients = []
        for r in email.get('to_recipients', [])[:5]:
            if isinstance(r, dict):
                recipients.append(r.get('email', 'unknown'))
            else:
                recipients.append(str(r))
        
        # Get triggered rules
        rules_triggered = []
        for rule in detection.get('rules_triggered', [])[:10]:
            if isinstance(rule, dict):
                rules_triggered.append({
                    'name': rule.get('rule_name', 'Unknown'),
                    'severity': rule.get('severity', 'medium'),
                    'description': rule.get('description', ''),
                })
        
        # Get AI findings
        key_findings = []
        if isinstance(ai_triage, dict):
            key_findings = ai_triage.get('key_findings', [])
        
        # Get recommendations
        recommendations = []
        if isinstance(ai_triage, dict):
            for action in ai_triage.get('recommended_actions', []):
                if isinstance(action, dict):
                    recommendations.append(action.get('action', '') + ': ' + action.get('description', ''))
        
        return {
            'analysis_id': analysis_result.get('analysis_id', 'N/A'),
            'analyzed_at': analysis_result.get('analyzed_at', datetime.utcnow().isoformat()),
            'classification': classification,
            'classification_display': cls.CATEGORY_MAP.get(classification, classification),
            'risk_level': risk_level,
            'risk_score': detection.get('risk_score', 0),
            'sender_email': sender_email,
            'sender_domain': sender_domain,
            'recipients': recipients,
            'subject': email.get('subject', '(No Subject)'),
            'rules_triggered': rules_triggered,
            'rules_count': len(detection.get('rules_triggered', [])),
            'key_findings': key_findings,
            'recommendations': recommendations,
            'summary': ai_triage.get('summary', '') if isinstance(ai_triage, dict) else '',
            'iocs': {
                'domains': iocs.get('domains', []),
                'urls': iocs.get('urls', []),
                'ips': iocs.get('ips', []),
                'hashes': iocs.get('hashes', []) or iocs.get('file_hashes_sha256', []),
            },
            'has_attachments': len(email.get('attachments', [])) > 0,
            'attachment_count': len(email.get('attachments', [])),
            'url_count': len(email.get('urls', [])),
            # Static analysis fields
            'attachment_analysis': cls._extract_attachment_analysis(email.get('attachments', [])),
        }
    
    @classmethod
    def _extract_attachment_analysis(cls, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract static analysis summary from attachments."""
        if not attachments:
            return {'has_threats': False, 'details': []}
        
        details = []
        has_threats = False
        total_threat_score = 0
        max_threat_level = 'clean'
        threat_level_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'clean': 0, 'unknown': 0}
        
        for att in attachments:
            threat_level = att.get('threat_level', 'unknown')
            threat_score = att.get('threat_score', 0)
            
            if threat_score > 0:
                has_threats = True
                total_threat_score += threat_score
                
                if threat_level_priority.get(threat_level, 0) > threat_level_priority.get(max_threat_level, 0):
                    max_threat_level = threat_level
            
            # Build indicators list
            indicators = []
            if att.get('has_macros'):
                indicators.append('VBA Macros')
            if att.get('has_auto_exec_macros'):
                indicators.append('Auto-Execute Macros')
            if att.get('has_dde'):
                indicators.append('DDE Links')
            if att.get('has_ole_objects'):
                indicators.append('OLE Objects')
            if att.get('has_javascript'):
                indicators.append('JavaScript')
            if att.get('has_embedded_files'):
                indicators.append('Embedded Files')
            if att.get('is_packed'):
                indicators.append('Packed Executable')
            if att.get('has_suspicious_imports'):
                indicators.append('Suspicious API Imports')
            if att.get('type_mismatch'):
                indicators.append('Type Mismatch')
            if att.get('has_double_extension'):
                indicators.append('Double Extension')
            if att.get('is_executable'):
                indicators.append('Executable')
            
            detail = {
                'filename': att.get('filename', 'unknown'),
                'size_bytes': att.get('size_bytes', 0),
                'threat_level': threat_level,
                'threat_score': threat_score,
                'threat_summary': att.get('threat_summary', ''),
                'indicators': indicators,
                'sha256': att.get('sha256', ''),
                'md5': att.get('md5', ''),
                'extracted_urls': att.get('extracted_urls', []),
                'extracted_ips': att.get('extracted_ips', []),
                'suspicious_strings': att.get('suspicious_strings', []),
            }
            details.append(detail)
        
        return {
            'has_threats': has_threats,
            'max_threat_level': max_threat_level,
            'total_threat_score': total_threat_score,
            'details': details,
        }
    
    @classmethod
    def _generate_generic(
        cls,
        analysis_result: Dict[str, Any],
        analyst_name: str,
        additional_notes: str,
    ) -> Dict[str, Any]:
        """Generate generic incident ticket."""
        fields = cls._extract_fields(analysis_result)
        severity = cls.SEVERITY_MAP.get(fields['risk_level'], {}).get('generic', 'P3')
        
        # Build description
        description_lines = [
            "=" * 60,
            "INCIDENT SUMMARY",
            "=" * 60,
            "",
            f"Classification: {fields['classification_display']}",
            f"Risk Score: {fields['risk_score']}/100 ({fields['risk_level'].upper()})",
            f"Analysis ID: {fields['analysis_id']}",
            "",
            "--- EMAIL DETAILS ---",
            f"Subject: {fields['subject']}",
            f"Sender: {fields['sender_email']}",
            f"Sender Domain: {fields['sender_domain']}",
            f"Recipients: {', '.join(fields['recipients'][:3])}",
            f"Attachments: {fields['attachment_count']}",
            f"URLs: {fields['url_count']}",
            "",
        ]
        
        if fields['summary']:
            description_lines.extend([
                "--- AI SUMMARY ---",
                fields['summary'],
                "",
            ])
        
        if fields['key_findings']:
            description_lines.extend([
                "--- KEY FINDINGS ---",
            ])
            for i, finding in enumerate(fields['key_findings'][:5], 1):
                description_lines.append(f"{i}. {finding}")
            description_lines.append("")
        
        if fields['rules_triggered']:
            description_lines.extend([
                "--- DETECTION RULES TRIGGERED ---",
            ])
            for rule in fields['rules_triggered'][:5]:
                description_lines.append(f"• [{rule['severity'].upper()}] {rule['name']}")
            description_lines.append("")
        
        # IOC Summary
        description_lines.extend([
            "--- INDICATORS OF COMPROMISE ---",
        ])
        if fields['iocs']['domains']:
            description_lines.append(f"Domains: {', '.join(fields['iocs']['domains'][:5])}")
        if fields['iocs']['urls']:
            description_lines.append(f"URLs: {len(fields['iocs']['urls'])} found")
        if fields['iocs']['ips']:
            description_lines.append(f"IPs: {', '.join(fields['iocs']['ips'][:5])}")
        description_lines.append("")
        
        # Attachment Analysis (Static Analysis)
        att_analysis = fields.get('attachment_analysis', {})
        if att_analysis.get('has_threats') or att_analysis.get('details'):
            description_lines.extend([
                "--- ATTACHMENT ANALYSIS ---",
            ])
            if att_analysis.get('has_threats'):
                description_lines.append(f"⚠️ THREATS DETECTED - Max Level: {att_analysis.get('max_threat_level', 'unknown').upper()}")
            
            for att in att_analysis.get('details', []):
                description_lines.append("")
                description_lines.append(f"File: {att.get('filename', 'unknown')}")
                if att.get('threat_score', 0) > 0:
                    description_lines.append(f"  Threat Score: {att['threat_score']}/100 ({att.get('threat_level', 'unknown').upper()})")
                if att.get('indicators'):
                    description_lines.append(f"  Indicators: {', '.join(att['indicators'])}")
                if att.get('threat_summary'):
                    description_lines.append(f"  Summary: {att['threat_summary']}")
                if att.get('sha256'):
                    description_lines.append(f"  SHA256: {att['sha256']}")
                if att.get('extracted_urls'):
                    description_lines.append(f"  Embedded URLs: {', '.join(att['extracted_urls'][:3])}")
                if att.get('extracted_ips'):
                    description_lines.append(f"  Embedded IPs: {', '.join(att['extracted_ips'][:3])}")
                if att.get('suspicious_strings'):
                    description_lines.append(f"  Suspicious Strings: {', '.join(att['suspicious_strings'][:3])}")
            description_lines.append("")
        
        if fields['recommendations']:
            description_lines.extend([
                "--- RECOMMENDED ACTIONS ---",
            ])
            for i, rec in enumerate(fields['recommendations'][:5], 1):
                description_lines.append(f"{i}. {rec}")
            description_lines.append("")
        
        if additional_notes:
            description_lines.extend([
                "--- ADDITIONAL NOTES ---",
                additional_notes,
                "",
            ])
        
        return {
            'format': 'generic',
            'title': f"[{severity}] {fields['classification_display']} - {fields['subject'][:50]}",
            'priority': severity,
            'category': 'Security Incident',
            'subcategory': 'Email Threat',
            'description': "\n".join(description_lines),
            'assigned_to': analyst_name,
            'fields': fields,
        }
    
    @classmethod
    def _generate_servicenow(
        cls,
        analysis_result: Dict[str, Any],
        analyst_name: str,
        additional_notes: str,
    ) -> Dict[str, Any]:
        """Generate ServiceNow incident format."""
        fields = cls._extract_fields(analysis_result)
        severity = cls.SEVERITY_MAP.get(fields['risk_level'], {}).get('servicenow', '3')
        
        # ServiceNow work notes format
        work_notes = [
            "[code]",
            f"NiksES Analysis ID: {fields['analysis_id']}",
            f"Risk Score: {fields['risk_score']}/100",
            "",
            "Email Details:",
            f"  From: {fields['sender_email']}",
            f"  Subject: {fields['subject']}",
            f"  Recipients: {', '.join(fields['recipients'][:3])}",
            "",
            "IOCs Extracted:",
        ]
        
        for domain in fields['iocs']['domains'][:5]:
            work_notes.append(f"  [Domain] {domain}")
        for ip in fields['iocs']['ips'][:5]:
            work_notes.append(f"  [IP] {ip}")
        
        work_notes.append("[/code]")
        
        return {
            'format': 'servicenow',
            'short_description': f"{fields['classification_display']} - {fields['subject'][:80]}",
            'impact': severity,
            'urgency': severity,
            'priority': severity,
            'category': 'Security',
            'subcategory': 'Email Threat',
            'assignment_group': 'Security Operations',
            'assigned_to': analyst_name,
            'description': cls._generate_generic(analysis_result, analyst_name, additional_notes)['description'],
            'work_notes': "\n".join(work_notes),
            'fields': fields,
        }
    
    @classmethod
    def _generate_jira(
        cls,
        analysis_result: Dict[str, Any],
        analyst_name: str,
        additional_notes: str,
    ) -> Dict[str, Any]:
        """Generate Jira issue format."""
        fields = cls._extract_fields(analysis_result)
        priority = cls.SEVERITY_MAP.get(fields['risk_level'], {}).get('jira', 'Medium')
        
        # Jira description with markup
        description_lines = [
            f"h2. {fields['classification_display']}",
            "",
            f"*Risk Score:* {fields['risk_score']}/100 ({fields['risk_level'].upper()})",
            f"*Analysis ID:* {fields['analysis_id']}",
            "",
            "h3. Email Details",
            "||Field||Value||",
            f"|Subject|{fields['subject']}|",
            f"|Sender|{fields['sender_email']}|",
            f"|Recipients|{', '.join(fields['recipients'][:3])}|",
            "",
        ]
        
        if fields['summary']:
            description_lines.extend([
                "h3. Summary",
                fields['summary'],
                "",
            ])
        
        if fields['key_findings']:
            description_lines.extend([
                "h3. Key Findings",
            ])
            for finding in fields['key_findings'][:5]:
                description_lines.append(f"* {finding}")
            description_lines.append("")
        
        if fields['iocs']['domains'] or fields['iocs']['ips']:
            description_lines.extend([
                "h3. IOCs",
                "{code:none}",
            ])
            for domain in fields['iocs']['domains'][:5]:
                description_lines.append(f"Domain: {domain}")
            for ip in fields['iocs']['ips'][:5]:
                description_lines.append(f"IP: {ip}")
            description_lines.extend(["{code}", ""])
        
        return {
            'format': 'jira',
            'summary': f"[Security] {fields['classification_display']} - {fields['subject'][:60]}",
            'priority': priority,
            'issue_type': 'Incident',
            'labels': ['security', 'email-threat', fields['classification']],
            'assignee': analyst_name,
            'description': "\n".join(description_lines),
            'fields': fields,
        }
    
    @classmethod
    def _generate_markdown(
        cls,
        analysis_result: Dict[str, Any],
        analyst_name: str,
        additional_notes: str,
    ) -> Dict[str, Any]:
        """Generate Markdown format for wiki/documentation."""
        fields = cls._extract_fields(analysis_result)
        
        md_lines = [
            f"# Security Incident: {fields['classification_display']}",
            "",
            "## Overview",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Risk Score** | {fields['risk_score']}/100 ({fields['risk_level'].upper()}) |",
            f"| **Classification** | {fields['classification_display']} |",
            f"| **Analysis ID** | `{fields['analysis_id']}` |",
            f"| **Analyzed** | {fields['analyzed_at']} |",
            f"| **Analyst** | {analyst_name or 'Unassigned'} |",
            "",
            "## Email Details",
            "",
            f"- **Subject:** {fields['subject']}",
            f"- **Sender:** `{fields['sender_email']}`",
            f"- **Sender Domain:** `{fields['sender_domain']}`",
            f"- **Recipients:** {', '.join(f'`{r}`' for r in fields['recipients'][:3])}",
            f"- **Attachments:** {fields['attachment_count']}",
            f"- **URLs Found:** {fields['url_count']}",
            "",
        ]
        
        if fields['summary']:
            md_lines.extend([
                "## Summary",
                "",
                fields['summary'],
                "",
            ])
        
        if fields['key_findings']:
            md_lines.extend([
                "## Key Findings",
                "",
            ])
            for i, finding in enumerate(fields['key_findings'], 1):
                md_lines.append(f"{i}. {finding}")
            md_lines.append("")
        
        if fields['rules_triggered']:
            md_lines.extend([
                "## Detection Rules Triggered",
                "",
                "| Severity | Rule |",
                "|----------|------|",
            ])
            for rule in fields['rules_triggered'][:10]:
                md_lines.append(f"| {rule['severity'].upper()} | {rule['name']} |")
            md_lines.append("")
        
        # IOCs
        md_lines.extend([
            "## Indicators of Compromise",
            "",
        ])
        
        if fields['iocs']['domains']:
            md_lines.append("### Domains")
            md_lines.append("```")
            for d in fields['iocs']['domains'][:10]:
                md_lines.append(d)
            md_lines.extend(["```", ""])
        
        if fields['iocs']['ips']:
            md_lines.append("### IP Addresses")
            md_lines.append("```")
            for ip in fields['iocs']['ips'][:10]:
                md_lines.append(ip)
            md_lines.extend(["```", ""])
        
        if fields['iocs']['urls']:
            md_lines.append("### URLs")
            md_lines.append(f"*{len(fields['iocs']['urls'])} URLs extracted - see IOC export*")
            md_lines.append("")
        
        # Attachment Analysis (Static Analysis)
        att_analysis = fields.get('attachment_analysis', {})
        if att_analysis.get('details'):
            md_lines.extend([
                "## Attachment Analysis",
                "",
            ])
            if att_analysis.get('has_threats'):
                md_lines.append(f"⚠️ **THREATS DETECTED** - Maximum Threat Level: **{att_analysis.get('max_threat_level', 'unknown').upper()}**")
                md_lines.append("")
            
            for att in att_analysis.get('details', []):
                md_lines.append(f"### {att.get('filename', 'unknown')}")
                md_lines.append("")
                if att.get('threat_score', 0) > 0:
                    md_lines.append(f"- **Threat Score:** {att['threat_score']}/100 ({att.get('threat_level', 'unknown').upper()})")
                if att.get('indicators'):
                    md_lines.append(f"- **Indicators:** {', '.join(att['indicators'])}")
                if att.get('threat_summary'):
                    md_lines.append(f"- **Summary:** {att['threat_summary']}")
                if att.get('sha256'):
                    md_lines.append(f"- **SHA256:** `{att['sha256']}`")
                if att.get('md5'):
                    md_lines.append(f"- **MD5:** `{att['md5']}`")
                if att.get('extracted_urls'):
                    md_lines.append(f"- **Embedded URLs:**")
                    for url in att['extracted_urls'][:5]:
                        md_lines.append(f"  - `{url}`")
                if att.get('extracted_ips'):
                    md_lines.append(f"- **Embedded IPs:** {', '.join(f'`{ip}`' for ip in att['extracted_ips'][:5])}")
                if att.get('suspicious_strings'):
                    md_lines.append(f"- **Suspicious Strings:** {', '.join(f'`{s}`' for s in att['suspicious_strings'][:5])}")
                md_lines.append("")
        
        if fields['recommendations']:
            md_lines.extend([
                "## Recommended Actions",
                "",
            ])
            for i, rec in enumerate(fields['recommendations'], 1):
                md_lines.append(f"{i}. {rec}")
            md_lines.append("")
        
        if additional_notes:
            md_lines.extend([
                "## Additional Notes",
                "",
                additional_notes,
                "",
            ])
        
        md_lines.extend([
            "---",
            f"*Generated by NiksES at {datetime.utcnow().isoformat()}Z*",
        ])
        
        return {
            'format': 'markdown',
            'content': "\n".join(md_lines),
            'fields': fields,
        }
