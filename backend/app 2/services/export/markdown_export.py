"""
NiksES Markdown Export

Export analysis reports to Markdown format.
"""

import logging
from datetime import datetime
from typing import Optional

from app.models.analysis import AnalysisResult
from app.models.detection import RiskLevel

logger = logging.getLogger(__name__)


def get_risk_emoji(risk_level: RiskLevel) -> str:
    """Get emoji for risk level."""
    emojis = {
        RiskLevel.CRITICAL: "🔴",
        RiskLevel.HIGH: "🟠",
        RiskLevel.MEDIUM: "🟡",
        RiskLevel.LOW: "🟢",
        RiskLevel.INFORMATIONAL: "🔵",
    }
    return emojis.get(risk_level, "⚪")


def export_to_markdown(
    analysis: AnalysisResult,
    include_raw: bool = False,
    include_evidence: bool = True,
) -> str:
    """
    Export analysis to Markdown format.
    
    Args:
        analysis: Complete analysis result
        include_raw: Include raw email content
        include_evidence: Include rule evidence
        
    Returns:
        Markdown string
    """
    lines = []
    
    # Title
    lines.append("# Email Security Analysis Report")
    lines.append("")
    
    # Summary
    risk_emoji = get_risk_emoji(analysis.detection.risk_level)
    classification = analysis.detection.primary_classification.value.replace('_', ' ').title()
    
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **Analysis ID** | `{analysis.analysis_id}` |")
    lines.append(f"| **Date** | {analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    lines.append(f"| **Risk Score** | {risk_emoji} **{analysis.detection.risk_score}/100** |")
    lines.append(f"| **Risk Level** | {analysis.detection.risk_level.value.upper()} |")
    lines.append(f"| **Classification** | {classification} |")
    lines.append(f"| **Confidence** | {analysis.detection.confidence:.0%} |")
    lines.append("")
    
    # Email Details
    email = analysis.email
    sender = email.sender.email if email.sender else "Unknown"
    sender_name = email.sender.display_name if email.sender and email.sender.display_name else ""
    
    lines.append("## Email Details")
    lines.append("")
    lines.append(f"- **From:** {sender_name} `<{sender}>`" if sender_name else f"- **From:** `{sender}`")
    lines.append(f"- **Subject:** {email.subject or '(No subject)'}")
    lines.append(f"- **Date:** {email.date or 'Unknown'}")
    
    if email.reply_to:
        reply_tos = ', '.join(r.email for r in email.reply_to)
        lines.append(f"- **Reply-To:** `{reply_tos}`")
    
    lines.append(f"- **Attachments:** {len(email.attachments)}")
    lines.append(f"- **URLs:** {len(email.urls)}")
    lines.append("")
    
    # Authentication
    lines.append("## Authentication Results")
    lines.append("")
    
    spf = email.spf_result
    dkim = email.dkim_result
    dmarc = email.dmarc_result
    
    if spf:
        status = "✅" if spf.result.lower() == "pass" else "❌"
        lines.append(f"- **SPF:** {status} {spf.result}")
    else:
        lines.append("- **SPF:** ⚠️ Not present")
    
    if dkim:
        status = "✅" if dkim.result.lower() == "pass" else "❌"
        lines.append(f"- **DKIM:** {status} {dkim.result}")
    else:
        lines.append("- **DKIM:** ⚠️ Not present")
    
    if dmarc:
        status = "✅" if dmarc.result.lower() == "pass" else "❌"
        lines.append(f"- **DMARC:** {status} {dmarc.result}")
    else:
        lines.append("- **DMARC:** ⚠️ Not present")
    
    lines.append("")
    
    # Detection Results
    lines.append("## Detection Results")
    lines.append("")
    
    triggered = analysis.detection.rules_triggered
    if triggered:
        lines.append(f"**{len(triggered)} detection rules triggered:**")
        lines.append("")
        lines.append("| Rule | Severity | Category |")
        lines.append("|------|----------|----------|")
        
        for rule in triggered:
            severity = rule.severity.value.upper() if hasattr(rule.severity, 'value') else str(rule.severity)
            lines.append(f"| {rule.rule_name} | {severity} | {rule.category} |")
        
        lines.append("")
        
        if include_evidence:
            lines.append("### Evidence")
            lines.append("")
            for rule in triggered[:10]:
                lines.append(f"**{rule.rule_name}:**")
                for evidence in rule.evidence[:3]:
                    lines.append(f"- {evidence}")
                lines.append("")
    else:
        lines.append("No detection rules triggered.")
        lines.append("")
    
    # Social Engineering Scores
    se_scores = {
        'Urgency': analysis.detection.urgency_score,
        'Fear': analysis.detection.fear_score,
        'Authority': analysis.detection.authority_score,
        'Reward': analysis.detection.reward_score,
    }
    
    if any(score > 0 for score in se_scores.values()):
        lines.append("## Social Engineering Indicators")
        lines.append("")
        lines.append("| Tactic | Score |")
        lines.append("|--------|-------|")
        for tactic, score in se_scores.items():
            bar = "█" * score + "░" * (10 - score)
            lines.append(f"| {tactic} | {bar} {score}/10 |")
        lines.append("")
    
    # Brand Impersonation
    if analysis.detection.impersonated_brand:
        lines.append("## Brand Impersonation")
        lines.append("")
        lines.append(f"⚠️ **Impersonated Brand:** {analysis.detection.impersonated_brand}")
        lines.append(f"- Confidence: {analysis.detection.brand_confidence:.0%}")
        lines.append("")
    
    # IOCs
    iocs = analysis.iocs
    total_iocs = (
        len(iocs.domains) + len(iocs.urls) + len(iocs.ips) +
        len(iocs.email_addresses) + len(iocs.file_hashes_sha256) + len(iocs.file_hashes_md5)
    )
    
    if total_iocs > 0:
        lines.append("## Indicators of Compromise (IOCs)")
        lines.append("")
        
        if iocs.domains:
            lines.append("### Domains")
            for domain in iocs.domains[:10]:
                lines.append(f"- `{domain}`")
            if len(iocs.domains) > 10:
                lines.append(f"- *...and {len(iocs.domains) - 10} more*")
            lines.append("")
        
        if iocs.urls:
            lines.append("### URLs")
            for url in iocs.urls[:10]:
                lines.append(f"- `{url[:80]}{'...' if len(url) > 80 else ''}`")
            if len(iocs.urls) > 10:
                lines.append(f"- *...and {len(iocs.urls) - 10} more*")
            lines.append("")
        
        if iocs.ips:
            lines.append("### IP Addresses")
            for ip in iocs.ips[:10]:
                lines.append(f"- `{ip}`")
            lines.append("")
        
        if iocs.file_hashes_sha256:
            lines.append("### File Hashes (SHA256)")
            for hash_val in iocs.file_hashes_sha256[:5]:
                lines.append(f"- `{hash_val}`")
            lines.append("")
    
    # AI Analysis
    if analysis.ai_triage:
        lines.append("## AI Analysis")
        lines.append("")
        lines.append(f"**Summary:** {analysis.ai_triage.summary}")
        lines.append("")
        
        if analysis.ai_triage.recommended_actions:
            lines.append("### Recommended Actions")
            lines.append("")
            for i, action in enumerate(analysis.ai_triage.recommended_actions, 1):
                lines.append(f"{i}. **{action.action}** - {action.description}")
            lines.append("")
        
        if analysis.ai_triage.mitre_techniques:
            lines.append("### MITRE ATT&CK Techniques")
            lines.append("")
            for technique in analysis.ai_triage.mitre_techniques:
                lines.append(f"- {technique}")
            lines.append("")
    
    # Attachments
    if email.attachments:
        lines.append("## Attachments")
        lines.append("")
        lines.append("| Filename | Size | Type | Flags |")
        lines.append("|----------|------|------|-------|")
        
        for att in email.attachments:
            flags = []
            if att.is_executable:
                flags.append("⚠️ Executable")
            if att.is_office_with_macros:
                flags.append("⚠️ Macros")
            if att.is_archive:
                flags.append("📦 Archive")
            
            size = f"{att.size_bytes:,}" if att.size_bytes else "?"
            lines.append(f"| {att.filename} | {size} bytes | {att.extension or '?'} | {' '.join(flags) or '-'} |")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append(f"*Generated by NiksES on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*")
    
    return "\n".join(lines)


def export_summary_to_markdown(analyses: list) -> str:
    """
    Export list of analysis summaries to Markdown table.
    
    Args:
        analyses: List of analysis summaries
        
    Returns:
        Markdown string
    """
    lines = []
    
    lines.append("# Email Analysis Summary")
    lines.append("")
    lines.append(f"*{len(analyses)} analyses*")
    lines.append("")
    
    lines.append("| Date | Subject | Sender | Risk | Classification |")
    lines.append("|------|---------|--------|------|----------------|")
    
    for analysis in analyses:
        date = analysis.analyzed_at.strftime('%Y-%m-%d %H:%M')
        subject = (analysis.subject or "(No subject)")[:30]
        sender = (analysis.sender_email or "Unknown")[:25]
        risk = f"{analysis.risk_score}/100"
        classification = analysis.classification.replace('_', ' ').title()
        
        lines.append(f"| {date} | {subject} | {sender} | {risk} | {classification} |")
    
    return "\n".join(lines)
