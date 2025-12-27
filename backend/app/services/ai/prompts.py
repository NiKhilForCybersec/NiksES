"""
NiksES AI Prompt Templates

Structured prompts for email security analysis with LLMs.
"""

from typing import Dict, Any, List, Optional


# System prompt for email security analysis
SYSTEM_PROMPT = """You are a senior email security analyst with 15+ years of experience in SOC operations and threat intelligence. Your role is to provide detailed, actionable analysis for junior SOC analysts investigating email threats.

You specialize in:
- Phishing and credential harvesting campaigns
- Business Email Compromise (BEC) and CEO fraud
- Malware delivery via email (attachments, links)
- Social engineering tactics (urgency, fear, authority exploitation)
- Brand impersonation and domain spoofing
- Invoice fraud and payment redirection
- Gift card scams and callback phishing

Analysis Guidelines:
1. ALWAYS provide 5+ specific key findings with concrete evidence
2. Explain the "why" behind each finding - what makes it suspicious
3. Reference specific elements: sender address, URLs, headers, language patterns
4. Note both malicious indicators AND any legitimate/clean indicators (for context)
5. Consider false positive scenarios - could this be legitimate?
6. Provide actionable, prioritized recommendations
7. Map to relevant MITRE ATT&CK techniques with explanations

Your analysis should help a junior analyst understand:
- What type of attack this is (or isn't)
- What evidence supports this conclusion
- What immediate actions to take
- How to prevent similar threats

Always respond with valid JSON matching the requested schema. Be thorough and specific."""


# Output schema for AI analysis
OUTPUT_SCHEMA = """{
  "summary": "2-3 sentence executive summary of the threat for SOC management",
  "detailed_analysis": "Comprehensive 2-3 paragraph analysis explaining what the email is, what attack technique it uses, why it's suspicious/malicious, and what the attacker's objectives are",
  "key_findings": [
    "Finding 1: Specific suspicious element with evidence",
    "Finding 2: Another indicator with details",
    "Finding 3: Technical evidence (e.g., header anomaly, URL analysis)",
    "Finding 4: Social engineering technique identified",
    "Finding 5: Reputation/TI findings"
  ],
  "classification_reasoning": "Detailed explanation of why this email was classified as this specific threat type",
  "risk_reasoning": "Explanation of factors contributing to the risk score, including both aggravating and mitigating factors",
  "recommended_actions": [
    {
      "action": "Block Sender Domain",
      "priority": 1,
      "description": "Detailed description of what to do and why",
      "automated": true
    },
    {
      "action": "Alert User",
      "priority": 2,
      "description": "Notify the recipient about this phishing attempt",
      "automated": false
    }
  ],
  "mitre_tactics": ["Initial Access", "Execution"],
  "mitre_techniques": [
    {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
    {"id": "T1204.002", "name": "User Execution: Malicious File"}
  ]
}"""


def build_analysis_prompt(
    email_data: Dict[str, Any],
    enrichment_data: Dict[str, Any],
    detection_data: Dict[str, Any],
) -> str:
    """
    Build the main analysis prompt with all context.
    
    Args:
        email_data: Parsed email information
        enrichment_data: Threat intelligence enrichment
        detection_data: Detection engine results
        
    Returns:
        Formatted prompt string
    """
    # Format sender info
    sender_info = "Unknown"
    if email_data.get('sender'):
        sender = email_data['sender']
        if isinstance(sender, dict):
            sender_info = f"{sender.get('display_name', '')} <{sender.get('email', 'unknown')}>"
        else:
            sender_info = str(sender)
    
    # Format recipients
    recipients = []
    for r in email_data.get('to_recipients', []):
        if isinstance(r, dict):
            recipients.append(r.get('email', 'unknown'))
        else:
            recipients.append(str(r))
    recipients_str = ', '.join(recipients[:5]) if recipients else 'Unknown'
    if len(recipients) > 5:
        recipients_str += f' (+{len(recipients) - 5} more)'
    
    # Format URLs
    urls_section = "None"
    if email_data.get('urls'):
        url_lines = []
        for url in email_data['urls'][:10]:
            if isinstance(url, dict):
                url_str = url.get('url', 'unknown')
                is_shortened = url.get('is_shortened', False)
                url_lines.append(f"  - {url_str[:100]}" + (" [SHORTENED]" if is_shortened else ""))
            else:
                url_lines.append(f"  - {str(url)[:100]}")
        urls_section = '\n'.join(url_lines)
        if len(email_data['urls']) > 10:
            urls_section += f"\n  (+{len(email_data['urls']) - 10} more URLs)"
    
    # Format attachments
    attachments_section = "None"
    if email_data.get('attachments'):
        att_lines = []
        for att in email_data['attachments']:
            if isinstance(att, dict):
                filename = att.get('filename', 'unknown')
                size = att.get('size_bytes', 0)
                is_exec = att.get('is_executable', False)
                is_macro = att.get('is_office_with_macros', False)
                flags = []
                if is_exec:
                    flags.append('EXECUTABLE')
                if is_macro:
                    flags.append('MACRO-ENABLED')
                flag_str = ' ' + ' '.join(f'[{f}]' for f in flags) if flags else ''
                att_lines.append(f"  - {filename} ({size} bytes){flag_str}")
            else:
                att_lines.append(f"  - {str(att)}")
        attachments_section = '\n'.join(att_lines)
    
    # Format authentication results
    auth_section = format_authentication(email_data)
    
    # Format enrichment summary
    enrichment_section = format_enrichment(enrichment_data)
    
    # Format detection results
    detection_section = format_detection(detection_data)
    
    # Build the prompt
    prompt = f"""Analyze this email for security threats and provide a comprehensive assessment for a SOC analyst.

## Email Details
**From:** {sender_info}
**To:** {recipients_str}
**Subject:** {email_data.get('subject', 'No subject')}
**Date:** {email_data.get('date', 'Unknown')}
**Reply-To:** {format_reply_to(email_data)}

## Email Body
{email_data.get('body_text', 'No body text')[:3000]}

## URLs Found
{urls_section}

## Attachments
{attachments_section}

## Authentication Results
{auth_section}

## Threat Intelligence Enrichment
{enrichment_section}

## Detection Engine Results
{detection_section}

---

Based on all available evidence, provide your security analysis in the following JSON format:

{OUTPUT_SCHEMA}

IMPORTANT GUIDELINES:
1. Provide at least 5 specific KEY FINDINGS with concrete evidence from the email
2. Each key finding should reference specific elements (sender domain, URL characteristics, language patterns, header anomalies)
3. Explain your classification reasoning in detail - what specific indicators led to this determination
4. Risk reasoning should explain both aggravating factors (why it's risky) and any mitigating factors (why it might be less risky)
5. Recommended actions should be prioritized and specific (not generic "investigate further")
6. Include relevant MITRE ATT&CK techniques with brief explanations of why they apply

Focus your analysis on:
1. Whether this email is a genuine threat or potential false positive
2. Specific evidence supporting your conclusion
3. What type of attack this represents (if malicious)
4. Actionable recommendations for the security team
5. Relevant MITRE ATT&CK techniques

Respond with only the JSON object, no additional text."""

    return prompt


def format_reply_to(email_data: Dict[str, Any]) -> str:
    """Format reply-to field."""
    reply_to = email_data.get('reply_to', [])
    if not reply_to:
        return "Same as From"
    
    if isinstance(reply_to, list):
        emails = []
        for r in reply_to[:3]:
            if isinstance(r, dict):
                emails.append(r.get('email', 'unknown'))
            else:
                emails.append(str(r))
        return ', '.join(emails)
    
    return str(reply_to)


def format_authentication(email_data: Dict[str, Any]) -> str:
    """Format authentication results section."""
    lines = []
    
    # Check for SPF
    spf = email_data.get('spf_result') or (email_data.get('header_analysis', {}) or {}).get('spf_result')
    if spf:
        if isinstance(spf, dict):
            lines.append(f"- SPF: {spf.get('result', 'unknown')} (domain: {spf.get('domain', 'unknown')})")
        else:
            lines.append(f"- SPF: {spf}")
    else:
        lines.append("- SPF: Not present")
    
    # Check for DKIM
    dkim = email_data.get('dkim_result') or (email_data.get('header_analysis', {}) or {}).get('dkim_result')
    if dkim:
        if isinstance(dkim, dict):
            lines.append(f"- DKIM: {dkim.get('result', 'unknown')} (domain: {dkim.get('domain', 'unknown')})")
        else:
            lines.append(f"- DKIM: {dkim}")
    else:
        lines.append("- DKIM: Not present")
    
    # Check for DMARC
    dmarc = email_data.get('dmarc_result') or (email_data.get('header_analysis', {}) or {}).get('dmarc_result')
    if dmarc:
        if isinstance(dmarc, dict):
            lines.append(f"- DMARC: {dmarc.get('result', 'unknown')} (domain: {dmarc.get('domain', 'unknown')})")
        else:
            lines.append(f"- DMARC: {dmarc}")
    else:
        lines.append("- DMARC: Not present")
    
    return '\n'.join(lines) if lines else "No authentication data available"


def format_enrichment(enrichment_data: Dict[str, Any]) -> str:
    """Format enrichment data section."""
    if not enrichment_data:
        return "No enrichment data available"
    
    lines = []
    
    # Sender domain info
    sender_domain = enrichment_data.get('sender_domain')
    if sender_domain:
        if isinstance(sender_domain, dict):
            lines.append("**Sender Domain:**")
            lines.append(f"  - Domain: {sender_domain.get('domain', 'unknown')}")
            if sender_domain.get('is_newly_registered'):
                lines.append(f"  - ⚠️ NEWLY REGISTERED (age: {sender_domain.get('age_days', '?')} days)")
            if sender_domain.get('virustotal_verdict'):
                lines.append(f"  - VirusTotal: {sender_domain.get('virustotal_verdict')}")
    
    # Originating IP
    orig_ip = enrichment_data.get('originating_ip')
    if orig_ip:
        if isinstance(orig_ip, dict):
            lines.append("**Originating IP:**")
            lines.append(f"  - IP: {orig_ip.get('ip', 'unknown')}")
            lines.append(f"  - Country: {orig_ip.get('country', 'unknown')}")
            if orig_ip.get('abuseipdb_score'):
                lines.append(f"  - AbuseIPDB Score: {orig_ip.get('abuseipdb_score')}/100")
            if orig_ip.get('is_vpn') or orig_ip.get('is_proxy') or orig_ip.get('is_tor'):
                flags = []
                if orig_ip.get('is_vpn'):
                    flags.append('VPN')
                if orig_ip.get('is_proxy'):
                    flags.append('PROXY')
                if orig_ip.get('is_tor'):
                    flags.append('TOR')
                lines.append(f"  - ⚠️ Anonymization: {', '.join(flags)}")
    
    # Malicious URLs
    urls = enrichment_data.get('urls', [])
    malicious_urls = [u for u in urls if isinstance(u, dict) and u.get('final_verdict') == 'malicious']
    suspicious_urls = [u for u in urls if isinstance(u, dict) and u.get('final_verdict') == 'suspicious']
    
    if malicious_urls:
        lines.append(f"**⚠️ {len(malicious_urls)} Malicious URL(s) detected**")
        for url in malicious_urls[:3]:
            lines.append(f"  - {url.get('url', 'unknown')[:80]}")
    
    if suspicious_urls:
        lines.append(f"**{len(suspicious_urls)} Suspicious URL(s) detected**")
    
    # Malicious attachments
    attachments = enrichment_data.get('attachments', [])
    malicious_atts = [a for a in attachments if isinstance(a, dict) and a.get('final_verdict') == 'malicious']
    
    if malicious_atts:
        lines.append(f"**⚠️ {len(malicious_atts)} Malicious Attachment(s) detected**")
        for att in malicious_atts[:3]:
            lines.append(f"  - {att.get('filename', 'unknown')}")
    
    return '\n'.join(lines) if lines else "No significant enrichment findings"


def format_detection(detection_data: Dict[str, Any]) -> str:
    """Format detection results section."""
    if not detection_data:
        return "Detection engine did not run"
    
    lines = []
    
    # Risk score
    risk_score = detection_data.get('risk_score', 0)
    risk_level = detection_data.get('risk_level', 'unknown')
    classification = detection_data.get('primary_classification', 'unknown')
    
    lines.append(f"**Risk Score:** {risk_score}/100 ({risk_level})")
    lines.append(f"**Classification:** {classification}")
    
    # Triggered rules
    triggered = detection_data.get('rules_triggered', [])
    if triggered:
        lines.append(f"**Rules Triggered:** {len(triggered)}")
        
        # Group by severity
        by_severity = {}
        for rule in triggered:
            if isinstance(rule, dict):
                sev = rule.get('severity', 'unknown')
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(rule.get('rule_name', 'unknown'))
        
        for sev in ['critical', 'high', 'medium', 'low', 'informational']:
            if sev in by_severity:
                lines.append(f"  - {sev.upper()}: {', '.join(by_severity[sev][:3])}")
    else:
        lines.append("**Rules Triggered:** None")
    
    # Social engineering scores
    urgency = detection_data.get('urgency_score', 0)
    fear = detection_data.get('fear_score', 0)
    authority = detection_data.get('authority_score', 0)
    
    if urgency > 0 or fear > 0 or authority > 0:
        lines.append(f"**Social Engineering Indicators:** Urgency={urgency}/10, Fear={fear}/10, Authority={authority}/10")
    
    # Brand impersonation
    brand = detection_data.get('impersonated_brand')
    if brand:
        conf = detection_data.get('brand_confidence', 0)
        lines.append(f"**⚠️ Brand Impersonation:** {brand} (confidence: {conf:.0%})")
    
    return '\n'.join(lines)


def build_summary_prompt(
    email_data: Dict[str, Any],
    detection_data: Dict[str, Any],
) -> str:
    """Build a prompt for generating a short summary."""
    
    subject = email_data.get('subject', 'No subject')
    sender = email_data.get('sender', {})
    if isinstance(sender, dict):
        sender_email = sender.get('email', 'unknown')
    else:
        sender_email = str(sender)
    
    risk_score = detection_data.get('risk_score', 0)
    classification = detection_data.get('primary_classification', 'unknown')
    rules_count = len(detection_data.get('rules_triggered', []))
    
    return f"""Generate a brief 1-2 sentence summary of this email security analysis for a SOC analyst:

Subject: {subject}
Sender: {sender_email}
Risk Score: {risk_score}/100
Classification: {classification}
Rules Triggered: {rules_count}

Provide only the summary text, no JSON or formatting."""


def build_recommendation_prompt(
    email_data: Dict[str, Any],
    detection_data: Dict[str, Any],
    enrichment_data: Dict[str, Any],
) -> str:
    """Build a prompt for generating recommendations."""
    
    classification = detection_data.get('primary_classification', 'unknown')
    risk_score = detection_data.get('risk_score', 0)
    risk_level = detection_data.get('risk_level', 'unknown')
    
    # Get key indicators
    indicators = []
    for rule in detection_data.get('rules_triggered', [])[:5]:
        if isinstance(rule, dict):
            indicators.append(rule.get('rule_name', 'unknown'))
    
    return f"""Based on this email analysis, provide 3-5 specific, actionable recommendations for the security team:

Classification: {classification}
Risk Level: {risk_level} ({risk_score}/100)
Key Indicators: {', '.join(indicators) if indicators else 'None'}

Format as a numbered list of recommendations. Be specific about:
1. Immediate actions (block, quarantine, alert)
2. Investigation steps
3. User notification
4. Prevention measures

Provide only the recommendations, no other text."""


# Prompt for explaining the verdict
EXPLAIN_VERDICT_PROMPT = """Explain why this email was classified as {classification} with a risk score of {risk_score}/100.

Key detection results:
{detection_summary}

Provide a clear, non-technical explanation suitable for:
1. End users who received the email
2. Security team members
3. Management reporting

Keep the explanation concise (2-3 paragraphs max)."""
