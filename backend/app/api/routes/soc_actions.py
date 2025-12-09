"""
NiksES SOC Actions API

One-click response actions, user notification templates, 
analyst verdicts, and SIEM/SOAR integration endpoints.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soc", tags=["SOC Actions"])


# =============================================================================
# ENUMS & MODELS
# =============================================================================

class ActionType(str, Enum):
    BLOCK_SENDER = "block_sender"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    RELEASE = "release"
    REPORT_PHISHING = "report_phishing"
    NOTIFY_USER = "notify_user"
    ESCALATE = "escalate"
    ADD_TO_ALLOWLIST = "add_to_allowlist"
    CREATE_TICKET = "create_ticket"


class AnalystVerdict(str, Enum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    CONFIRMED_PHISHING = "confirmed_phishing"
    CONFIRMED_BEC = "confirmed_bec"
    SUSPICIOUS = "suspicious"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class NotificationType(str, Enum):
    PHISHING_ALERT = "phishing_alert"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    MALWARE_ALERT = "malware_alert"
    BEC_ATTEMPT = "bec_attempt"
    SPAM_NOTIFICATION = "spam_notification"
    FALSE_POSITIVE = "false_positive"
    SECURITY_AWARENESS = "security_awareness"


class ActionRequest(BaseModel):
    """Request to execute a SOC action."""
    analysis_id: str
    action: ActionType
    target: Optional[str] = None  # email, domain, URL depending on action
    reason: Optional[str] = None
    analyst_id: Optional[str] = None


class ActionResponse(BaseModel):
    """Response from executing a SOC action."""
    success: bool
    action: ActionType
    target: str
    message: str
    timestamp: datetime
    integration_results: Dict[str, Any] = {}


class VerdictRequest(BaseModel):
    """Analyst verdict submission."""
    analysis_id: str
    verdict: AnalystVerdict
    confidence: int = Field(ge=1, le=100, default=80)
    notes: str = ""
    analyst_id: Optional[str] = None
    false_positive_reason: Optional[str] = None


class NotificationRequest(BaseModel):
    """Request to send user notification."""
    analysis_id: str
    notification_type: NotificationType
    recipient_email: str
    custom_message: Optional[str] = None
    include_iocs: bool = False
    analyst_id: Optional[str] = None


class PlaybookStep(BaseModel):
    """Single step in investigation playbook."""
    step_number: int
    title: str
    description: str
    action_type: Optional[ActionType] = None
    is_automated: bool = False
    is_completed: bool = False
    evidence_to_collect: List[str] = []


class InvestigationPlaybook(BaseModel):
    """Complete investigation playbook based on classification."""
    classification: str
    severity: str
    estimated_time_minutes: int
    steps: List[PlaybookStep]
    recommended_actions: List[ActionType]
    escalation_criteria: List[str]


# =============================================================================
# USER NOTIFICATION TEMPLATES
# =============================================================================

NOTIFICATION_TEMPLATES = {
    NotificationType.PHISHING_ALERT: {
        "subject": "⚠️ Security Alert: Phishing Email Detected",
        "body": """Dear {recipient_name},

Our security team has detected a phishing attempt in an email sent to your inbox.

**Email Details:**
- Subject: {email_subject}
- Sender: {sender_email}
- Received: {email_date}

**What Happened:**
This email was identified as a phishing attempt designed to steal your credentials or personal information.

**What We've Done:**
- The email has been quarantined/removed from your inbox
- The sender has been blocked
- Malicious URLs have been blocked at the network level

**What You Should Do:**
1. Do NOT click any links if you received this email
2. Do NOT download any attachments
3. If you clicked any links or entered credentials, contact IT Security immediately
4. Report any similar suspicious emails

**If You Entered Your Password:**
Please change your password immediately and enable MFA if not already active.

Questions? Contact the Security Team at {security_contact}

Stay vigilant,
{company_name} Security Team
""",
    },
    NotificationType.CREDENTIAL_COMPROMISE: {
        "subject": "🚨 URGENT: Potential Credential Compromise - Action Required",
        "body": """Dear {recipient_name},

**IMMEDIATE ACTION REQUIRED**

We have detected that you may have entered your credentials on a malicious website linked from a phishing email.

**Email Details:**
- Subject: {email_subject}
- Sender: {sender_email}
- Malicious URL: {malicious_url}

**Required Actions (Complete Within 1 Hour):**
1. ✅ Change your password immediately at {password_reset_url}
2. ✅ Enable Multi-Factor Authentication (MFA)
3. ✅ Review recent account activity for unauthorized access
4. ✅ Report any suspicious activity to IT Security

**What We're Doing:**
- Monitoring your account for unauthorized access
- Blocking the malicious domain across our network
- Investigating the scope of this attack

Please confirm completion of these steps by replying to this email.

This is time-sensitive - attackers may already have access to your credentials.

{company_name} Security Team
Contact: {security_contact}
""",
    },
    NotificationType.BEC_ATTEMPT: {
        "subject": "⚠️ Business Email Compromise Attempt Blocked",
        "body": """Dear {recipient_name},

We have intercepted a Business Email Compromise (BEC) attempt targeting you.

**Attack Details:**
- Impersonated: {impersonated_entity}
- Request Type: {attack_type}
- Sender: {sender_email} (fraudulent)

**What the Attacker Wanted:**
{attack_objective}

**Why This Was Blocked:**
{detection_reason}

**Important Reminders:**
- Always verify wire transfer/payment requests via phone using known numbers
- Be suspicious of urgent financial requests, especially from executives
- Check sender email addresses carefully for slight misspellings
- When in doubt, verify through a separate communication channel

If you received similar emails that weren't caught, please forward them to {security_email}.

{company_name} Security Team
""",
    },
    NotificationType.MALWARE_ALERT: {
        "subject": "🛡️ Malware Blocked: Suspicious Attachment Detected",
        "body": """Dear {recipient_name},

Our security systems blocked a malicious attachment in an email sent to you.

**Email Details:**
- Subject: {email_subject}
- Sender: {sender_email}
- Attachment: {attachment_name}
- Threat Type: {malware_type}

**What Was Blocked:**
The attachment contained malicious code that could have:
{potential_impact}

**Your Action Items:**
1. Do NOT attempt to retrieve or open the original email
2. If you downloaded the attachment, contact IT Security immediately
3. Report any unusual system behavior

**If You Opened the Attachment:**
- Disconnect from the network immediately
- Contact IT Security at {security_contact}
- Do not attempt to "fix" anything yourself

{company_name} Security Team
""",
    },
    NotificationType.FALSE_POSITIVE: {
        "subject": "✅ Email Released: False Positive Confirmed",
        "body": """Dear {recipient_name},

An email that was previously quarantined has been reviewed and released to your inbox.

**Email Details:**
- Subject: {email_subject}
- Sender: {sender_email}
- Original Detection: {original_detection}

**Review Result:**
Our security team has confirmed this email is legitimate and safe. It has been released to your inbox.

**Why Was It Flagged?**
{flag_reason}

We apologize for any inconvenience. Our systems are designed to be cautious to protect you from threats.

If you have questions, contact {security_contact}.

{company_name} Security Team
""",
    },
    NotificationType.SECURITY_AWARENESS: {
        "subject": "📚 Security Tip: Recognizing {threat_type}",
        "body": """Dear {recipient_name},

Based on a recent security event, we wanted to share some tips on recognizing {threat_type}.

**What to Look For:**
{warning_signs}

**Red Flags in This Attack:**
{specific_indicators}

**Best Practices:**
1. Verify unexpected requests through a separate channel
2. Hover over links before clicking to see the actual URL
3. Be suspicious of urgency and pressure tactics
4. When in doubt, ask IT Security

**Resources