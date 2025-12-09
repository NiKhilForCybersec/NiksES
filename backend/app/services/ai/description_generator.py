"""
NiksES AI Description Generator

Generates detailed, human-readable threat descriptions using OpenAI.
Provides comprehensive analysis summaries for SOC analysts.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

# System prompt for generating descriptions
DESCRIPTION_SYSTEM_PROMPT = """You are a senior SOC analyst assistant. Your task is to generate clear, actionable threat analysis descriptions for email security investigations.

Your descriptions should:
1. Start with a clear verdict (e.g., "HIGH RISK - Phishing Attempt Detected")
2. Summarize key findings in 2-3 sentences
3. List specific indicators of compromise (IOCs) found
4. Explain the attack technique/tactic in plain language
5. Provide recommended actions for the analyst

Keep descriptions concise but comprehensive. Use bullet points for lists. Always maintain a professional, analytical tone."""


async def generate_ai_description(
    openai_client,
    email_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
    max_tokens: int = 800,
) -> Optional[str]:
    """
    Generate a detailed AI description of the email threat analysis.
    
    Args:
        openai_client: AsyncOpenAI client
        email_data: Parsed email information
        analysis_results: Complete analysis results
        max_tokens: Maximum tokens for response
        
    Returns:
        Generated description string or None if failed
    """
    if not openai_client:
        return None
    
    try:
        # Build the prompt with analysis data
        prompt = _build_description_prompt(email_data, analysis_results)
        
        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": DESCRIPTION_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        
        description = response.choices[0].message.content
        return description.strip() if description else None
        
    except Exception as e:
        logger.error(f"Failed to generate AI description: {e}")
        return None


def _build_description_prompt(email_data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    """Build the prompt for AI description generation."""
    
    # Extract key information
    sender = email_data.get("sender", {})
    sender_email = sender.get("email", "unknown") if isinstance(sender, dict) else str(sender)
    sender_domain = sender.get("domain", "unknown") if isinstance(sender, dict) else "unknown"
    
    subject = email_data.get("subject", "No subject")
    
    # Get risk information
    risk_score = analysis.get("overall_score", 0)
    risk_level = analysis.get("overall_level", "unknown")
    classification = analysis.get("classification", "unknown")
    
    # Get triggered rules
    rules_triggered = []
    detection = analysis.get("detection_results", {})
    if isinstance(detection, dict):
        rules_triggered = detection.get("rules_triggered", [])
    elif hasattr(detection, "rules_triggered"):
        rules_triggered = detection.rules_triggered or []
    
    # Format rules
    rules_summary = []
    for rule in rules_triggered[:10]:  # Limit to top 10
        if isinstance(rule, dict):
            rules_summary.append(f"- {rule.get('name', 'Unknown')}: {rule.get('description', '')}")
        elif hasattr(rule, 'name'):
            rules_summary.append(f"- {rule.name}: {rule.description if hasattr(rule, 'description') else ''}")
    
    # Get SE analysis
    se_analysis = analysis.get("se_analysis", {})
    se_score = 0
    se_techniques = []
    if se_analysis:
        if isinstance(se_analysis, dict):
            se_score = se_analysis.get("se_score", 0)
            se_techniques = se_analysis.get("techniques", [])
        elif hasattr(se_analysis, "to_dict"):
            se_dict = se_analysis.to_dict()
            se_score = se_dict.get("se_score", 0)
            se_techniques = se_dict.get("techniques", [])
    
    # Get TI results
    ti_results = analysis.get("ti_results", {})
    ti_summary = []
    if ti_results:
        if isinstance(ti_results, dict):
            ti_verdict = ti_results.get("overall_verdict", "unknown")
            ti_summary.append(f"Overall TI verdict: {ti_verdict}")
        elif hasattr(ti_results, "overall_verdict"):
            ti_summary.append(f"Overall TI verdict: {ti_results.overall_verdict}")
    
    # Get GeoIP info
    geoip = analysis.get("geoip", {})
    geoip_info = ""
    if geoip:
        country = geoip.get("country", "Unknown")
        city = geoip.get("city", "")
        isp = geoip.get("isp", "")
        geoip_info = f"Origin: {city}, {country} (ISP: {isp})" if city else f"Origin: {country}"
    
    # Get header anomalies
    header_analysis = analysis.get("header_analysis", {})
    anomalies = []
    if isinstance(header_analysis, dict):
        anomalies = header_analysis.get("anomalies", [])
    
    # Build prompt
    prompt = f"""Analyze this email and generate a comprehensive threat assessment:

## Email Details
- **Sender**: {sender_email}
- **Sender Domain**: {sender_domain}
- **Subject**: {subject}
{f'- **GeoIP**: {geoip_info}' if geoip_info else ''}

## Risk Assessment
- **Risk Score**: {risk_score}/100
- **Risk Level**: {risk_level.upper()}
- **Classification**: {classification}
- **Social Engineering Score**: {se_score}/100

## Detection Rules Triggered ({len(rules_triggered)} total)
{chr(10).join(rules_summary) if rules_summary else '- No rules triggered'}

## Social Engineering Techniques
{', '.join(str(t) for t in se_techniques) if se_techniques else 'None detected'}

## Threat Intelligence
{chr(10).join(ti_summary) if ti_summary else '- No TI data available'}

## Header Anomalies
{chr(10).join(f'- {a}' for a in anomalies[:5]) if anomalies else '- No anomalies detected'}

Based on this analysis, generate a detailed threat description that a SOC analyst can use to understand and respond to this email threat. Include:
1. A clear verdict line
2. Key findings summary
3. Specific IOCs and indicators
4. Attack technique explanation
5. Recommended response actions"""

    return prompt


def generate_fallback_description(
    email_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
) -> str:
    """
    Generate a rule-based description when AI is unavailable.
    """
    risk_score = analysis_results.get("overall_score", 0)
    risk_level = analysis_results.get("overall_level", "low")
    classification = analysis_results.get("classification", "unknown")
    
    # Build verdict
    if risk_score >= 70:
        verdict = "⚠️ HIGH RISK - Immediate Action Required"
    elif risk_score >= 40:
        verdict = "⚡ SUSPICIOUS - Review Recommended"
    else:
        verdict = "✅ LOW RISK - Likely Safe"
    
    # Get triggered rules
    rules_triggered = []
    detection = analysis_results.get("detection_results", {})
    if isinstance(detection, dict):
        rules_triggered = detection.get("rules_triggered", [])
    elif hasattr(detection, "rules_triggered"):
        rules_triggered = detection.rules_triggered or []
    
    # Build description
    lines = [
        f"**{verdict}**",
        "",
        f"**Risk Score**: {risk_score}/100 ({risk_level.upper()})",
        f"**Classification**: {classification.replace('_', ' ').title()}",
        "",
    ]
    
    if rules_triggered:
        lines.append(f"**Detection Rules Triggered** ({len(rules_triggered)}):")
        for rule in rules_triggered[:5]:
            name = rule.get("name", "Unknown") if isinstance(rule, dict) else getattr(rule, "name", "Unknown")
            lines.append(f"  • {name}")
        if len(rules_triggered) > 5:
            lines.append(f"  ... and {len(rules_triggered) - 5} more")
    
    # Recommendations
    lines.append("")
    lines.append("**Recommended Actions**:")
    if risk_score >= 70:
        lines.extend([
            "  • Quarantine email immediately",
            "  • Block sender domain",
            "  • Alert security team",
            "  • Search for similar emails in environment",
        ])
    elif risk_score >= 40:
        lines.extend([
            "  • Review email content carefully",
            "  • Verify sender through alternate channel",
            "  • Do not click links or download attachments",
        ])
    else:
        lines.extend([
            "  • No immediate action required",
            "  • Continue standard monitoring",
        ])
    
    return "\n".join(lines)
