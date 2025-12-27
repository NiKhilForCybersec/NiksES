"""
NiksES Executive PDF Report
Professional PDF reports designed for executive forwarding with clear explanations.
"""

import io
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from app.models.analysis import AnalysisResult
from app.models.detection import RiskLevel

logger = logging.getLogger(__name__)

# Try to import reportlab
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable, ListFlowable, ListItem,
        KeepTogether, Flowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed. PDF export will not be available.")


# Professional color scheme
COLORS = {
    'primary': colors.Color(0.2, 0.4, 0.6),      # Professional blue
    'secondary': colors.Color(0.4, 0.4, 0.4),    # Dark gray
    'success': colors.Color(0.2, 0.6, 0.3),      # Green
    'warning': colors.Color(0.9, 0.6, 0.1),      # Orange
    'danger': colors.Color(0.8, 0.2, 0.2),       # Red
    'critical': colors.Color(0.6, 0.0, 0.0),     # Dark red
    'light_gray': colors.Color(0.95, 0.95, 0.95),
    'medium_gray': colors.Color(0.85, 0.85, 0.85),
    'dark_gray': colors.Color(0.3, 0.3, 0.3),
    'white': colors.white,
    'black': colors.black,
}


def get_risk_color(risk_level: RiskLevel) -> colors.Color:
    """Get color for risk level."""
    mapping = {
        RiskLevel.CRITICAL: COLORS['critical'],
        RiskLevel.HIGH: COLORS['danger'],
        RiskLevel.MEDIUM: COLORS['warning'],
        RiskLevel.LOW: COLORS['success'],
        RiskLevel.INFORMATIONAL: COLORS['primary'],
    }
    return mapping.get(risk_level, COLORS['secondary'])


def get_risk_explanation(risk_level: RiskLevel) -> str:
    """Get business-friendly explanation of risk level."""
    explanations = {
        RiskLevel.CRITICAL: "This email poses an immediate and severe threat to the organization. It should be blocked and investigated immediately.",
        RiskLevel.HIGH: "This email shows strong indicators of malicious intent and should be treated as a serious security concern.",
        RiskLevel.MEDIUM: "This email has suspicious characteristics that warrant caution and further review before any action is taken.",
        RiskLevel.LOW: "This email has minor anomalies but is likely not an immediate threat. Standard precautions are recommended.",
        RiskLevel.INFORMATIONAL: "This email appears to be legitimate with minimal security concerns.",
    }
    return explanations.get(risk_level, "Risk level could not be determined.")


def get_classification_explanation(classification: str) -> str:
    """Get business-friendly explanation of email classification."""
    explanations = {
        'phishing': "Phishing attempt - This email attempts to trick recipients into revealing sensitive information like passwords or financial data.",
        'spear_phishing': "Targeted Attack - This is a highly personalized phishing attempt specifically crafted for your organization or individual.",
        'credential_harvesting': "Credential Theft - This email is designed to steal login credentials through fake login pages or forms.",
        'bec': "Business Email Compromise - An attacker is impersonating a trusted person to manipulate business transactions.",
        'invoice_fraud': "Invoice Fraud - This email attempts to redirect payments to fraudulent accounts.",
        'gift_card_scam': "Gift Card Scam - A common fraud technique requesting gift card purchases for supposedly urgent reasons.",
        'callback_phishing': "Callback Phishing - This email urges you to call a fraudulent phone number.",
        'malware_delivery': "Malware Delivery - This email contains or links to malicious software that can harm systems.",
        'ransomware': "Ransomware - Extremely dangerous malware that encrypts files and demands payment.",
        'qr_phishing': "QR Code Phishing - Malicious QR codes that redirect to phishing sites.",
        'brand_impersonation': "Brand Impersonation - The sender is pretending to be a legitimate company.",
        'account_takeover': "Account Takeover Attempt - This email tries to gain unauthorized access to accounts.",
        'spam': "Spam - Unwanted bulk email, typically advertising or promotional in nature.",
        'marketing': "Marketing Email - Legitimate promotional content.",
        'benign': "Legitimate Email - No security concerns detected.",
    }
    return explanations.get(classification, f"Email classified as: {classification.replace('_', ' ').title()}")


def get_bottom_line(analysis) -> str:
    """Generate executive-focused bottom line summary."""
    risk_level = analysis.detection.risk_level
    risk_score = analysis.detection.risk_score
    classification = analysis.detection.primary_classification.value
    rules_count = len(analysis.detection.rules_triggered)
    
    email = analysis.email
    sender = email.sender.email if email.sender else "unknown sender"
    subject = email.subject[:50] + "..." if email.subject and len(email.subject) > 50 else (email.subject or "(no subject)")
    
    if risk_level == RiskLevel.CRITICAL:
        return (
            f"<b>DO NOT INTERACT WITH THIS EMAIL.</b> This message from '{sender}' with subject "
            f"'{subject}' is almost certainly malicious. Our analysis triggered {rules_count} security "
            f"rules and detected it as a {classification.replace('_', ' ')} attack. Block the sender immediately "
            f"and alert any users who may have received it."
        )
    elif risk_level == RiskLevel.HIGH:
        return (
            f"<b>This email should be treated as suspicious.</b> The message from '{sender}' shows "
            f"strong indicators of a {classification.replace('_', ' ')} attempt. We detected {rules_count} "
            f"security issues. Do not click any links or download attachments. Verify the sender through "
            f"an independent channel before taking any action."
        )
    elif risk_level == RiskLevel.MEDIUM:
        return (
            f"<b>Proceed with caution.</b> This email from '{sender}' has characteristics that warrant "
            f"careful review before acting. Our analysis found {rules_count} potential concerns. "
            f"Verify any requests through official channels and avoid clicking links until confirmed legitimate."
        )
    elif risk_level == RiskLevel.LOW:
        return (
            f"<b>This email appears mostly safe but has minor anomalies.</b> The message from '{sender}' "
            f"passed most security checks but triggered {rules_count} low-severity rules. Apply standard "
            f"email security practices and verify any unusual requests."
        )
    else:
        return (
            f"<b>This email appears legitimate.</b> Our analysis of the message from '{sender}' did not "
            f"detect significant security concerns. Standard email handling procedures apply."
        )


def generate_threat_narrative(analysis) -> str:
    """Generate a narrative description of the threat analysis."""
    email = analysis.email
    detection = analysis.detection
    
    sender = email.sender.email if email.sender else "an unknown sender"
    sender_domain = email.sender.domain if email.sender else "unknown"
    
    parts = []
    
    # Opening
    parts.append(f"We analyzed an email from <b>{sender}</b>")
    if email.subject:
        parts.append(f" with the subject line \"{email.subject[:60]}{'...' if len(email.subject or '') > 60 else ''}\"")
    parts.append(". ")
    
    # Key findings
    findings = []
    
    # Check authentication
    if email.spf_result and email.spf_result.result not in ['pass', 'none']:
        findings.append("failed SPF authentication (sender may be spoofed)")
    if email.dkim_result and email.dkim_result.result not in ['pass', 'none']:
        findings.append("failed DKIM validation")
    if email.dmarc_result and email.dmarc_result.result not in ['pass', 'none']:
        findings.append("failed DMARC policy checks")
    
    # Check for suspicious content
    url_count = len(email.urls or [])
    attachment_count = len(email.attachments or [])
    
    if url_count > 0:
        findings.append(f"contains {url_count} link{'s' if url_count > 1 else ''}")
    if attachment_count > 0:
        findings.append(f"includes {attachment_count} attachment{'s' if attachment_count > 1 else ''}")
    
    # Detection rules
    triggered_rules = detection.rules_triggered
    if triggered_rules:
        high_severity = [r for r in triggered_rules if r.severity.value in ['critical', 'high']]
        if high_severity:
            findings.append(f"triggered {len(high_severity)} high-severity security rules")
        elif len(triggered_rules) > 3:
            findings.append(f"triggered {len(triggered_rules)} security detection rules")
    
    if findings:
        parts.append("Our analysis found that this email ")
        parts.append(", ".join(findings[:3]))
        parts.append(". ")
    
    # AI insights if available
    if analysis.ai_triage and analysis.ai_triage.summary:
        parts.append(f"<br/><br/><b>AI Assessment:</b> {analysis.ai_triage.summary}")
    
    # Confidence statement
    confidence = detection.confidence
    if confidence >= 0.9:
        parts.append("<br/><br/>We have <b>high confidence</b> in this assessment based on multiple detection signals.")
    elif confidence >= 0.7:
        parts.append("<br/><br/>We have <b>moderate confidence</b> in this assessment.")
    
    return "".join(parts)


class RiskScoreGauge(Flowable):
    """Visual risk score gauge."""
    
    def __init__(self, score: int, width: float = 4*inch, height: float = 0.8*inch):
        super().__init__()
        self.score = min(100, max(0, score))
        self.width = width
        self.height = height
    
    def draw(self):
        # Background bar
        self.canv.setFillColor(COLORS['light_gray'])
        self.canv.roundRect(0, 0, self.width, self.height * 0.4, 5, fill=1, stroke=0)
        
        # Score fill
        fill_width = (self.score / 100) * self.width
        
        if self.score >= 75:
            fill_color = COLORS['critical']
        elif self.score >= 50:
            fill_color = COLORS['danger']
        elif self.score >= 25:
            fill_color = COLORS['warning']
        else:
            fill_color = COLORS['success']
        
        self.canv.setFillColor(fill_color)
        self.canv.roundRect(0, 0, fill_width, self.height * 0.4, 5, fill=1, stroke=0)
        
        # Score text
        self.canv.setFillColor(COLORS['dark_gray'])
        self.canv.setFont("Helvetica-Bold", 14)
        self.canv.drawString(self.width + 10, self.height * 0.1, f"{self.score}/100")
        
        # Scale markers
        self.canv.setFont("Helvetica", 8)
        self.canv.setFillColor(COLORS['secondary'])
        for i in [0, 25, 50, 75, 100]:
            x = (i / 100) * self.width
            self.canv.drawCentredString(x, -12, str(i))


def generate_executive_pdf(
    analysis: AnalysisResult,
    output_path: Optional[str] = None,
    page_size: str = "letter",
    include_technical: bool = True,
) -> bytes:
    """
    Generate a professional executive PDF report.
    
    Args:
        analysis: Complete analysis result
        output_path: Optional file path to save PDF
        page_size: Page size ("letter" or "a4")
        include_technical: Include technical appendix
        
    Returns:
        PDF content as bytes
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for PDF export. Install with: pip install reportlab")
    
    buffer = io.BytesIO()
    size = letter if page_size.lower() == "letter" else A4
    
    doc = SimpleDocTemplate(
        buffer,
        pagesize=size,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ExecutiveTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=COLORS['primary'],
        spaceAfter=10,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
    )
    
    subtitle_style = ParagraphStyle(
        'ExecutiveSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=COLORS['secondary'],
        spaceAfter=30,
        alignment=TA_CENTER,
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=COLORS['primary'],
        spaceBefore=25,
        spaceAfter=12,
        borderPadding=(0, 0, 5, 0),
        fontName='Helvetica-Bold',
    )
    
    subsection_heading = ParagraphStyle(
        'SubsectionHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=COLORS['dark_gray'],
        spaceBefore=15,
        spaceAfter=8,
        fontName='Helvetica-Bold',
    )
    
    body_style = ParagraphStyle(
        'ExecutiveBody',
        parent=styles['Normal'],
        fontSize=11,
        textColor=COLORS['dark_gray'],
        spaceAfter=8,
        leading=16,
        alignment=TA_JUSTIFY,
    )
    
    highlight_style = ParagraphStyle(
        'Highlight',
        parent=body_style,
        backColor=COLORS['light_gray'],
        borderPadding=10,
        spaceBefore=10,
        spaceAfter=10,
    )
    
    elements = []
    
    # =========================================================================
    # COVER / HEADER SECTION
    # =========================================================================
    
    elements.append(Paragraph("Email Security Analysis Report", title_style))
    elements.append(Paragraph(
        f"Analysis ID: {analysis.analysis_id}<br/>"
        f"Generated: {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
        subtitle_style
    ))
    
    # =========================================================================
    # THE BOTTOM LINE (New - Executive-focused)
    # =========================================================================
    
    risk_level = analysis.detection.risk_level
    risk_score = analysis.detection.risk_score
    classification = analysis.detection.primary_classification.value
    risk_color = get_risk_color(risk_level)
    
    # Create impactful bottom line summary
    bottom_line = get_bottom_line(analysis)
    
    bottom_line_style = ParagraphStyle(
        'BottomLine',
        parent=styles['Normal'],
        fontSize=12,
        textColor=COLORS['dark_gray'],
        spaceBefore=5,
        spaceAfter=5,
        leading=18,
    )
    
    # Verdict box with bottom line
    if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        verdict_box_color = colors.Color(0.95, 0.85, 0.85)
        verdict_text_color = COLORS['critical']
        verdict_icon = "⚠️ "
    elif risk_level == RiskLevel.MEDIUM:
        verdict_box_color = colors.Color(0.98, 0.93, 0.85)
        verdict_text_color = COLORS['warning']
        verdict_icon = "⚡ "
    else:
        verdict_box_color = colors.Color(0.85, 0.95, 0.85)
        verdict_text_color = COLORS['success']
        verdict_icon = "✓ "
    
    verdict_style = ParagraphStyle(
        'Verdict',
        parent=styles['Heading2'],
        fontSize=20,
        textColor=verdict_text_color,
        alignment=TA_CENTER,
        spaceAfter=5,
        spaceBefore=0,
    )
    
    elements.append(Paragraph("The Bottom Line", section_heading))
    
    # Summary table with verdict and bottom line
    summary_data = [
        [Paragraph(f"<b>{verdict_icon}VERDICT: {risk_level.value.upper()} RISK</b>", verdict_style)],
        [Paragraph(f"<b>Risk Score: {risk_score}/100</b>", ParagraphStyle(
            'RiskScore',
            parent=body_style,
            alignment=TA_CENTER,
            fontSize=14,
            textColor=verdict_text_color,
        ))],
        [Spacer(1, 10)],
        [Paragraph(bottom_line, bottom_line_style)],
    ]
    
    summary_table = Table(summary_data, colWidths=[6*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), verdict_box_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 20),
        ('RIGHTPADDING', (0, 0), (-1, -1), 20),
        ('ROUNDEDCORNERS', [8, 8, 8, 8]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # =========================================================================
    # WHAT WE FOUND (New narrative section)
    # =========================================================================
    
    elements.append(Paragraph("What We Found", section_heading))
    
    # Generate narrative
    narrative = generate_threat_narrative(analysis)
    elements.append(Paragraph(narrative, body_style))
    elements.append(Spacer(1, 15))
    
    # Risk Score Gauge
    elements.append(Paragraph("<b>Risk Assessment</b>", body_style))
    elements.append(RiskScoreGauge(risk_score))
    elements.append(Spacer(1, 20))
    
    # Classification explanation
    elements.append(Paragraph(f"<b>Threat Type:</b> {classification.replace('_', ' ').title()}", body_style))
    elements.append(Paragraph(get_classification_explanation(classification), body_style))
    
    # =========================================================================
    # KEY FINDINGS
    # =========================================================================
    
    elements.append(Paragraph("Key Findings", section_heading))
    
    email = analysis.email
    sender = email.sender.email if email.sender else "Unknown"
    sender_name = email.sender.display_name if email.sender and email.sender.display_name else None
    
    # Email overview
    email_overview_data = [
        ['From:', f"{sender_name} <{sender}>" if sender_name else sender],
        ['Subject:', email.subject or "(No subject)"],
        ['Date:', str(email.date) if email.date else "Unknown"],
    ]
    
    if email.reply_to and email.sender:
        reply_to_email = email.reply_to[0].email if email.reply_to else ""
        if reply_to_email and reply_to_email != email.sender.email:
            email_overview_data.append(['Reply-To:', f"⚠️ {reply_to_email} (DIFFERENT FROM SENDER)"])
    
    email_overview_data.append(['Attachments:', f"{len(email.attachments)} file(s)"])
    email_overview_data.append(['URLs:', f"{len(email.urls)} link(s)"])
    
    overview_table = Table(email_overview_data, colWidths=[1.3*inch, 5*inch])
    overview_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TEXTCOLOR', (0, 0), (0, -1), COLORS['secondary']),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(overview_table)
    elements.append(Spacer(1, 15))
    
    # Detection findings
    triggered_rules = analysis.detection.rules_triggered
    if triggered_rules:
        elements.append(Paragraph(f"<b>{len(triggered_rules)} Security Issues Detected:</b>", body_style))
        
        # Group by severity
        by_severity = {}
        for rule in triggered_rules:
            sev = rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity)
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(rule)
        
        findings_data = [['Severity', 'Finding', 'Impact']]
        
        severity_order = ['critical', 'high', 'medium', 'low', 'informational']
        for sev in severity_order:
            if sev in by_severity:
                for rule in by_severity[sev][:3]:  # Limit per severity
                    impact = "Immediate action required" if sev in ['critical', 'high'] else "Review recommended"
                    findings_data.append([sev.upper(), rule.rule_name, impact])
        
        if len(findings_data) > 1:
            findings_table = Table(findings_data, colWidths=[1*inch, 3.5*inch, 1.8*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), COLORS['white']),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, COLORS['medium_gray']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(findings_table)
    else:
        elements.append(Paragraph("✓ No critical security issues detected.", body_style))
    
    # =========================================================================
    # ATTACHMENT ANALYSIS (Static Analysis)
    # =========================================================================
    
    if email.attachments:
        threat_attachments = [
            att for att in email.attachments 
            if getattr(att, 'threat_score', 0) > 0 or 
               getattr(att, 'has_macros', False) or 
               getattr(att, 'has_javascript', False) or
               getattr(att, 'is_executable', False)
        ]
        
        if threat_attachments:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Attachment Analysis", section_heading))
            
            elements.append(Paragraph(
                f"<font color='{COLORS['critical'].hexval() if hasattr(COLORS.get('critical', colors.red), 'hexval') else '#CC3333'}'>⚠️ {len(threat_attachments)} potentially dangerous attachment(s) detected</font>",
                body_style
            ))
            
            att_data = [['File', 'Risk', 'Concerns']]
            for att in threat_attachments[:5]:
                indicators = []
                if getattr(att, 'is_executable', False):
                    indicators.append('Executable')
                if getattr(att, 'has_macros', False):
                    indicators.append('VBA Macros')
                if getattr(att, 'has_auto_exec_macros', False):
                    indicators.append('Auto-Execute')
                if getattr(att, 'has_javascript', False):
                    indicators.append('JavaScript')
                if getattr(att, 'has_dde', False):
                    indicators.append('DDE Links')
                if getattr(att, 'is_packed', False):
                    indicators.append('Packed')
                if getattr(att, 'type_mismatch', False):
                    indicators.append('Type Mismatch')
                if getattr(att, 'has_double_extension', False):
                    indicators.append('Double Extension')
                
                threat_level = getattr(att, 'threat_level', 'unknown')
                threat_score = getattr(att, 'threat_score', 0)
                risk_display = f"{threat_level.upper()} ({threat_score}/100)" if threat_score > 0 else "Review Needed"
                
                att_data.append([
                    att.filename[:30] + '...' if len(att.filename) > 30 else att.filename,
                    risk_display,
                    ', '.join(indicators[:3]) or 'Analysis required'
                ])
            
            att_table = Table(att_data, colWidths=[2.3*inch, 1.5*inch, 2.5*inch])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), COLORS['white']),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, COLORS['medium_gray']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(att_table)
            
            # Add threat summary for most dangerous attachment
            most_dangerous = max(threat_attachments, key=lambda x: getattr(x, 'threat_score', 0))
            if getattr(most_dangerous, 'threat_summary', ''):
                elements.append(Spacer(1, 8))
                elements.append(Paragraph(
                    f"<b>Analysis:</b> {most_dangerous.threat_summary[:300]}",
                    body_style
                ))
    
    # =========================================================================
    # RECOMMENDED ACTIONS
    # =========================================================================
    
    elements.append(Paragraph("Recommended Actions", section_heading))
    
    actions = []
    
    if risk_score >= 75:
        actions.extend([
            "<b>IMMEDIATE:</b> Block the sender and quarantine this email",
            "<b>IMMEDIATE:</b> Notify affected users not to interact with this email",
            "Investigate if any users clicked links or opened attachments",
            "Consider reporting to your threat intelligence team",
        ])
    elif risk_score >= 50:
        actions.extend([
            "<b>HIGH PRIORITY:</b> Quarantine this email pending investigation",
            "Verify sender identity through alternative channels",
            "Scan any attachments with additional security tools",
        ])
    elif risk_score >= 25:
        actions.extend([
            "Review email content carefully before taking action",
            "Verify any requests through official channels",
            "Be cautious with any links or attachments",
        ])
    else:
        actions.extend([
            "Standard email handling procedures apply",
            "Remain vigilant for unusual requests",
        ])
    
    # Add AI recommendations if available
    if analysis.ai_triage and analysis.ai_triage.recommended_actions:
        for rec in analysis.ai_triage.recommended_actions[:3]:
            if rec.action not in [a.split(":</b>")[-1].strip() for a in actions]:
                actions.append(f"{rec.action}: {rec.description}")
    
    for i, action in enumerate(actions[:6], 1):
        elements.append(Paragraph(f"{i}. {action}", body_style))
    
    # =========================================================================
    # THREAT INTELLIGENCE (if available)
    # =========================================================================
    
    enrichment = analysis.enrichment
    if enrichment:
        elements.append(Paragraph("Threat Intelligence", section_heading))
        
        intel_findings = []
        
        # Sender domain
        if enrichment.sender_domain:
            sd = enrichment.sender_domain
            if sd.is_newly_registered:
                intel_findings.append(f"⚠️ Sender domain is newly registered ({sd.age_days} days old) - common in phishing")
            if sd.virustotal_verdict and sd.virustotal_verdict.value == 'malicious':
                intel_findings.append("🚨 Sender domain flagged as MALICIOUS by security vendors")
            if sd.is_lookalike:
                intel_findings.append(f"⚠️ Domain appears to impersonate: {sd.lookalike_target}")
        
        # IP reputation
        if enrichment.originating_ip:
            ip = enrichment.originating_ip
            if ip.abuseipdb_score and ip.abuseipdb_score >= 50:
                intel_findings.append(f"⚠️ Sender IP has abuse score of {ip.abuseipdb_score}/100")
            if ip.is_tor:
                intel_findings.append("⚠️ Email originated from Tor network (anonymization)")
            if ip.is_vpn:
                intel_findings.append("ℹ️ Email sent through VPN service")
        
        # Malicious URLs
        malicious_urls = [u for u in (enrichment.urls or []) if u.final_verdict.value == 'malicious']
        if malicious_urls:
            intel_findings.append(f"🚨 {len(malicious_urls)} malicious URL(s) detected in email")
        
        # Malicious attachments
        malicious_atts = [a for a in (enrichment.attachments or []) if a.final_verdict.value == 'malicious']
        if malicious_atts:
            intel_findings.append(f"🚨 {len(malicious_atts)} malicious attachment(s) detected")
        
        if intel_findings:
            for finding in intel_findings:
                elements.append(Paragraph(f"• {finding}", body_style))
        else:
            elements.append(Paragraph("✓ No significant threat intelligence findings.", body_style))
    
    # =========================================================================
    # TECHNICAL APPENDIX (Optional)
    # =========================================================================
    
    if include_technical:
        elements.append(PageBreak())
        elements.append(Paragraph("Technical Appendix", section_heading))
        elements.append(Paragraph(
            "The following technical details are provided for security team reference.",
            body_style
        ))
        
        # Detection Rules Detail
        if triggered_rules:
            elements.append(Paragraph("Detection Rules Triggered", subsection_heading))
            
            for rule in triggered_rules[:10]:
                elements.append(Paragraph(
                    f"<b>{rule.rule_id}</b>: {rule.rule_name} ({rule.severity.value.upper()})",
                    body_style
                ))
                if rule.evidence:
                    for ev in rule.evidence[:3]:
                        elements.append(Paragraph(f"    • {ev}", ParagraphStyle(
                            'Evidence',
                            parent=body_style,
                            fontSize=9,
                            textColor=COLORS['secondary'],
                            leftIndent=20,
                        )))
                if rule.mitre_technique:
                    elements.append(Paragraph(
                        f"    MITRE ATT&CK: {rule.mitre_technique}",
                        ParagraphStyle(
                            'Mitre',
                            parent=body_style,
                            fontSize=9,
                            textColor=COLORS['primary'],
                            leftIndent=20,
                        )
                    ))
        
        # IOCs
        iocs = analysis.iocs
        ioc_items = []
        if iocs.domains:
            ioc_items.append(f"Domains: {', '.join(iocs.domains[:5])}")
        if iocs.urls:
            ioc_items.append(f"URLs: {len(iocs.urls)} found")
        if iocs.ips:
            ioc_items.append(f"IPs: {', '.join(iocs.ips[:5])}")
        if iocs.file_hashes_sha256:
            ioc_items.append(f"File Hashes: {len(iocs.file_hashes_sha256)} SHA256")
        
        if ioc_items:
            elements.append(Paragraph("Indicators of Compromise (IOCs)", subsection_heading))
            for item in ioc_items:
                elements.append(Paragraph(f"• {item}", body_style))
        
        # Authentication Results
        elements.append(Paragraph("Email Authentication", subsection_heading))
        
        auth_results = []
        if email.header_analysis:
            ha = email.header_analysis
            if ha.spf_result:
                auth_results.append(f"SPF: {ha.spf_result}")
            if ha.dkim_result:
                auth_results.append(f"DKIM: {ha.dkim_result}")
            if ha.dmarc_result:
                auth_results.append(f"DMARC: {ha.dmarc_result}")
        
        if auth_results:
            for ar in auth_results:
                elements.append(Paragraph(f"• {ar}", body_style))
        else:
            elements.append(Paragraph("• Authentication headers not available", body_style))
    
    # =========================================================================
    # FOOTER
    # =========================================================================
    
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['medium_gray']))
    
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=COLORS['secondary'],
        alignment=TA_CENTER,
    )
    
    elements.append(Paragraph(
        f"This report was generated by NiksES Email Security Analysis<br/>"
        f"Analysis completed in {analysis.analysis_duration_ms}ms | "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
        f"<i>This report is confidential and intended for authorized personnel only.</i>",
        footer_style
    ))
    
    # Build PDF
    doc.build(elements)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    if output_path:
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
    
    return pdf_bytes


def generate_summary_pdf(
    analysis: AnalysisResult,
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a one-page summary PDF for quick review.
    
    Args:
        analysis: Complete analysis result
        output_path: Optional file path to save PDF
        
    Returns:
        PDF content as bytes
    """
    return generate_executive_pdf(
        analysis=analysis,
        output_path=output_path,
        include_technical=False,
    )


# Export functions
__all__ = ['generate_executive_pdf', 'generate_summary_pdf', 'REPORTLAB_AVAILABLE']
