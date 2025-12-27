"""
NiksES User Notification Templates

Pre-written email templates to notify users about email threats.
Customizable based on threat type and actions taken.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class NotificationType(str, Enum):
    """Types of user notifications."""
    PHISHING_WARNING = "phishing_warning"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    MALWARE_WARNING = "malware_warning"
    BEC_ATTEMPT = "bec_attempt"
    ACCOUNT_SECURED = "account_secured"
    GENERAL_WARNING = "general_warning"


class UserNotificationGenerator:
    """
    Generate user notification emails for security incidents.
    
    Creates professional, clear notifications for:
    - Phishing attempts
    - Credential compromise
    - Malware delivery attempts
    - BEC attempts
    """
    
    @classmethod
    def generate(
        cls,
        notification_type: NotificationType,
        analysis_result: Dict[str, Any],
        recipient_name: str = "User",
        recipient_email: str = "",
        additional_context: str = "",
        include_iocs: bool = False,
        security_team_contact: str = "security@company.com",
        company_name: str = "Security Team",
    ) -> Dict[str, str]:
        """
        Generate a user notification email.
        
        Args:
            notification_type: Type of notification
            analysis_result: Analysis result for context
            recipient_name: Name of recipient
            recipient_email: Email of recipient
            additional_context: Extra context to include
            include_iocs: Whether to include IOC details
            security_team_contact: Contact for security team
            company_name: Company/team name
            
        Returns:
            Dictionary with 'subject' and 'body' keys
        """
        generators = {
            NotificationType.PHISHING_WARNING: cls._phishing_warning,
            NotificationType.CREDENTIAL_COMPROMISE: cls._credential_compromise,
            NotificationType.MALWARE_WARNING: cls._malware_warning,
            NotificationType.BEC_ATTEMPT: cls._bec_attempt,
            NotificationType.ACCOUNT_SECURED: cls._account_secured,
            NotificationType.GENERAL_WARNING: cls._general_warning,
        }
        
        generator = generators.get(notification_type, cls._general_warning)
        return generator(
            analysis_result=analysis_result,
            recipient_name=recipient_name,
            recipient_email=recipient_email,
            additional_context=additional_context,
            include_iocs=include_iocs,
            security_team_contact=security_team_contact,
            company_name=company_name,
        )
    
    @classmethod
    def _extract_email_details(cls, analysis_result: Dict[str, Any]) -> Dict[str, str]:
        """Extract email details for template."""
        email = analysis_result.get('email', {})
        sender = email.get('sender', {})
        
        return {
            'subject': email.get('subject', '(No Subject)'),
            'sender_email': sender.get('email', 'Unknown') if isinstance(sender, dict) else str(sender),
            'sender_domain': sender.get('domain', 'Unknown') if isinstance(sender, dict) else 'Unknown',
            'received_date': email.get('date', datetime.utcnow().isoformat()),
        }
    
    @classmethod
    def _phishing_warning(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate phishing warning notification."""
        details = cls._extract_email_details(analysis_result)
        
        subject = f"[Security Alert] Phishing Email Detected - Action Required"
        
        body = f"""Dear {recipient_name},

Our security systems have detected a phishing email that was sent to your inbox. We have taken action to remove this threat, but we wanted to make you aware of this attempt.

═══════════════════════════════════════════════════════════
PHISHING EMAIL DETAILS
═══════════════════════════════════════════════════════════

Subject: {details['subject']}
From: {details['sender_email']}
Received: {details['received_date']}

═══════════════════════════════════════════════════════════
WHAT THIS MEANS
═══════════════════════════════════════════════════════════

This email was designed to trick you into:
• Clicking a malicious link
• Entering your login credentials on a fake website
• Downloading harmful attachments
• Sharing sensitive information

═══════════════════════════════════════════════════════════
WHAT WE'VE DONE
═══════════════════════════════════════════════════════════

✓ Removed the phishing email from your mailbox
✓ Blocked the sender
✓ Added malicious URLs to our blocklist

═══════════════════════════════════════════════════════════
WHAT YOU SHOULD DO
═══════════════════════════════════════════════════════════

1. DO NOT click any links if you still see this email
2. DO NOT download or open any attachments
3. If you clicked any links or entered any information:
   → Change your password IMMEDIATELY
   → Contact the security team at {security_team_contact}
4. Be extra vigilant for similar emails

═══════════════════════════════════════════════════════════
HOW TO IDENTIFY PHISHING EMAILS
═══════════════════════════════════════════════════════════

• Urgent or threatening language
• Requests for login credentials or personal info
• Suspicious sender addresses
• Mismatched or suspicious URLs
• Poor grammar or spelling
• Unexpected attachments

{additional_context}

If you have any questions or concerns, please contact us at {security_team_contact}.

Stay safe,
{company_name}

---
This is an automated security notification. Please do not reply to this email.
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def _credential_compromise(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate credential compromise notification."""
        details = cls._extract_email_details(analysis_result)
        
        subject = f"[URGENT] Your Credentials May Be Compromised - Immediate Action Required"
        
        body = f"""Dear {recipient_name},

⚠️ URGENT SECURITY NOTICE ⚠️

Our security team has identified that you may have entered your credentials on a phishing website. Your account security may be at risk.

═══════════════════════════════════════════════════════════
INCIDENT DETAILS
═══════════════════════════════════════════════════════════

A phishing email was sent to you with subject:
"{details['subject']}"

Our logs indicate you may have interacted with this email.

═══════════════════════════════════════════════════════════
IMMEDIATE ACTIONS REQUIRED
═══════════════════════════════════════════════════════════

🔴 ACTION 1: Change your password NOW
   Go to [your password reset portal] and change your password immediately.
   Choose a strong, unique password you haven't used before.

🔴 ACTION 2: Enable Multi-Factor Authentication (MFA)
   If not already enabled, set up MFA on your account.

🔴 ACTION 3: Check your account activity
   Review recent login activity for any suspicious access.
   Look for logins from unknown locations or devices.

🔴 ACTION 4: Report any suspicious activity
   Contact {security_team_contact} if you notice anything unusual.

═══════════════════════════════════════════════════════════
WHAT WE'VE DONE
═══════════════════════════════════════════════════════════

✓ Blocked the phishing website
✓ Monitored your account for suspicious activity
✓ Invalidated any potentially compromised sessions

═══════════════════════════════════════════════════════════
ADDITIONAL PRECAUTIONS
═══════════════════════════════════════════════════════════

• If you used the same password on other accounts, change those too
• Watch for suspicious emails claiming to be from IT or security
• Never share your new password with anyone

{additional_context}

This is a serious security incident. Please complete the required actions as soon as possible.

For assistance, contact: {security_team_contact}

{company_name}

---
This is an automated security notification.
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def _malware_warning(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate malware warning notification."""
        details = cls._extract_email_details(analysis_result)
        email = analysis_result.get('email', {})
        attachments = email.get('attachments', [])
        
        attachment_names = []
        for att in attachments[:3]:
            if isinstance(att, dict):
                attachment_names.append(att.get('filename', 'Unknown'))
        
        subject = f"[Security Alert] Malicious Email Attachment Detected"
        
        body = f"""Dear {recipient_name},

Our security systems have detected a malicious attachment in an email sent to you.

═══════════════════════════════════════════════════════════
THREAT DETAILS
═══════════════════════════════════════════════════════════

Email Subject: {details['subject']}
From: {details['sender_email']}
Malicious Attachment(s): {', '.join(attachment_names) if attachment_names else 'See details below'}

═══════════════════════════════════════════════════════════
WHAT WE'VE DONE
═══════════════════════════════════════════════════════════

✓ Blocked and removed the malicious email
✓ Added the malware signature to our detection systems
✓ Blocked the sender address

═══════════════════════════════════════════════════════════
IMPORTANT: DID YOU OPEN THE ATTACHMENT?
═══════════════════════════════════════════════════════════

If you DID NOT open the attachment:
• No further action is required
• The threat has been neutralized

If you DID open the attachment:
🔴 STOP - Do not use your computer for sensitive activities
🔴 Contact security immediately: {security_team_contact}
🔴 Do not attempt to delete files or "clean" your computer
🔴 Leave your computer powered on for investigation

═══════════════════════════════════════════════════════════
SIGNS YOUR COMPUTER MAY BE INFECTED
═══════════════════════════════════════════════════════════

• Unusual slowness or behavior
• Unexpected pop-ups or messages
• Programs opening or closing on their own
• Files that are encrypted or renamed
• Unusual network activity

If you notice any of these signs, contact security immediately.

{additional_context}

Contact: {security_team_contact}

{company_name}

---
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def _bec_attempt(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate BEC attempt notification."""
        details = cls._extract_email_details(analysis_result)
        
        subject = f"[Security Alert] Business Email Compromise Attempt Detected"
        
        body = f"""Dear {recipient_name},

Our security team has identified a Business Email Compromise (BEC) attempt targeting you.

═══════════════════════════════════════════════════════════
WHAT IS BEC?
═══════════════════════════════════════════════════════════

Business Email Compromise is a sophisticated scam where attackers impersonate executives, vendors, or trusted partners to trick employees into:
• Making unauthorized wire transfers
• Changing payment details
• Purchasing gift cards
• Sharing sensitive information

═══════════════════════════════════════════════════════════
THE FRAUDULENT EMAIL
═══════════════════════════════════════════════════════════

Subject: {details['subject']}
Sender: {details['sender_email']}

This email attempted to impersonate a trusted party to manipulate you into taking action.

═══════════════════════════════════════════════════════════
WHAT YOU SHOULD DO
═══════════════════════════════════════════════════════════

1. DO NOT respond to the email
2. DO NOT make any payments or transfers
3. DO NOT purchase gift cards
4. ALWAYS verify financial requests through a known phone number
   (not one provided in the suspicious email)

═══════════════════════════════════════════════════════════
DID YOU ALREADY TAKE ACTION?
═══════════════════════════════════════════════════════════

If you made a payment, purchased gift cards, or shared sensitive information:

🔴 Contact {security_team_contact} IMMEDIATELY
🔴 Contact your bank/financial institution
🔴 Preserve all email communications

Time is critical for recovering funds.

═══════════════════════════════════════════════════════════
PREVENTION TIPS
═══════════════════════════════════════════════════════════

• Always verify unusual financial requests by phone
• Be suspicious of urgent payment requests
• Check email addresses carefully for slight misspellings
• Never share gift card codes via email

{additional_context}

If you have questions, contact: {security_team_contact}

{company_name}

---
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def _account_secured(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate account secured confirmation."""
        subject = f"[Security Update] Your Account Has Been Secured"
        
        body = f"""Dear {recipient_name},

Good news! We have completed securing your account following the recent security incident.

═══════════════════════════════════════════════════════════
ACTIONS COMPLETED
═══════════════════════════════════════════════════════════

✓ Password has been reset
✓ All active sessions have been terminated
✓ Multi-factor authentication verified/enabled
✓ Account activity has been reviewed
✓ No unauthorized access was detected

═══════════════════════════════════════════════════════════
RECOMMENDED NEXT STEPS
═══════════════════════════════════════════════════════════

1. Log in with your new credentials
2. Review your account settings and activity
3. Ensure MFA is enabled for all your accounts
4. Update passwords on any other accounts where you used the same password

═══════════════════════════════════════════════════════════
STAYING SECURE
═══════════════════════════════════════════════════════════

• Use unique passwords for each account
• Enable MFA wherever possible
• Be cautious of unexpected emails asking for credentials
• Report suspicious emails to {security_team_contact}

{additional_context}

Thank you for your cooperation in resolving this incident.

{company_name}

---
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def _general_warning(
        cls,
        analysis_result: Dict[str, Any],
        recipient_name: str,
        recipient_email: str,
        additional_context: str,
        include_iocs: bool,
        security_team_contact: str,
        company_name: str,
    ) -> Dict[str, str]:
        """Generate general security warning."""
        details = cls._extract_email_details(analysis_result)
        detection = analysis_result.get('detection', {})
        
        classification = detection.get('primary_classification', 'suspicious')
        if hasattr(classification, 'value'):
            classification = classification.value
        
        subject = f"[Security Notice] Suspicious Email Detected"
        
        body = f"""Dear {recipient_name},

Our security systems have flagged a suspicious email that was sent to you.

═══════════════════════════════════════════════════════════
EMAIL DETAILS
═══════════════════════════════════════════════════════════

Subject: {details['subject']}
From: {details['sender_email']}
Classification: {classification}

═══════════════════════════════════════════════════════════
RECOMMENDED ACTIONS
═══════════════════════════════════════════════════════════

• Do not click any links in the email
• Do not download or open attachments
• Do not reply to the email
• If you already interacted with this email, contact security

═══════════════════════════════════════════════════════════
WHAT WE'VE DONE
═══════════════════════════════════════════════════════════

✓ Flagged the email for review
✓ Added sender to monitoring list
✓ Updated our detection systems

{additional_context}

If you have any concerns, please contact: {security_team_contact}

{company_name}

---
Incident ID: {analysis_result.get('analysis_id', 'N/A')}
"""
        
        return {'subject': subject, 'body': body}
    
    @classmethod
    def get_available_templates(cls) -> List[Dict[str, str]]:
        """Get list of available notification templates."""
        return [
            {
                'type': NotificationType.PHISHING_WARNING.value,
                'name': 'Phishing Warning',
                'description': 'Standard warning for phishing emails',
            },
            {
                'type': NotificationType.CREDENTIAL_COMPROMISE.value,
                'name': 'Credential Compromise',
                'description': 'Urgent notice when credentials may be compromised',
            },
            {
                'type': NotificationType.MALWARE_WARNING.value,
                'name': 'Malware Warning',
                'description': 'Warning about malicious attachments',
            },
            {
                'type': NotificationType.BEC_ATTEMPT.value,
                'name': 'BEC Attempt',
                'description': 'Business Email Compromise attempt warning',
            },
            {
                'type': NotificationType.ACCOUNT_SECURED.value,
                'name': 'Account Secured',
                'description': 'Confirmation after account has been secured',
            },
            {
                'type': NotificationType.GENERAL_WARNING.value,
                'name': 'General Warning',
                'description': 'Generic suspicious email warning',
            },
        ]
