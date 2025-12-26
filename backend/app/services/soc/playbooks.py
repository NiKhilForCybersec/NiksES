"""
NiksES Response Playbooks

Pre-defined response playbooks for different threat types.
Includes checklists, escalation criteria, and automation flags.
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime


class PlaybookType(str, Enum):
    """Types of playbooks."""
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    BEC = "bec"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    INVOICE_FRAUD = "invoice_fraud"
    BRAND_IMPERSONATION = "brand_impersonation"
    URL_THREAT = "url_threat"
    SMS_SMISHING = "sms_smishing"
    CLEAN = "clean"
    GENERIC = "generic"


@dataclass
class PlaybookStep:
    """Individual step in a playbook."""
    id: str
    title: str
    description: str
    category: str  # containment, eradication, recovery, lessons_learned
    priority: int  # 1 = immediate, 2 = short-term, 3 = long-term
    automated: bool = False
    automation_command: Optional[str] = None
    responsible_team: str = "SOC"
    estimated_time_minutes: int = 5
    completed: bool = False
    completed_at: Optional[str] = None
    completed_by: Optional[str] = None
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'priority': self.priority,
            'automated': self.automated,
            'automation_command': self.automation_command,
            'responsible_team': self.responsible_team,
            'estimated_time_minutes': self.estimated_time_minutes,
            'completed': self.completed,
            'completed_at': self.completed_at,
            'completed_by': self.completed_by,
            'notes': self.notes,
        }


@dataclass
class EscalationCriteria:
    """Criteria for escalation."""
    condition: str
    escalate_to: str
    timeframe_minutes: int
    notification_method: str = "email"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'condition': self.condition,
            'escalate_to': self.escalate_to,
            'timeframe_minutes': self.timeframe_minutes,
            'notification_method': self.notification_method,
        }


@dataclass
class ResponsePlaybook:
    """Complete response playbook."""
    playbook_type: PlaybookType
    title: str
    description: str
    severity: str
    steps: List[PlaybookStep] = field(default_factory=list)
    escalation_criteria: List[EscalationCriteria] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'playbook_type': self.playbook_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'steps': [s.to_dict() for s in self.steps],
            'escalation_criteria': [e.to_dict() for e in self.escalation_criteria],
            'created_at': self.created_at,
            'total_steps': len(self.steps),
            'completed_steps': len([s for s in self.steps if s.completed]),
            'progress_percent': int(len([s for s in self.steps if s.completed]) / len(self.steps) * 100) if self.steps else 0,
        }
    
    def mark_step_complete(self, step_id: str, analyst: str) -> bool:
        """Mark a step as complete."""
        for step in self.steps:
            if step.id == step_id:
                step.completed = True
                step.completed_at = datetime.utcnow().isoformat()
                step.completed_by = analyst
                return True
        return False


class PlaybookGenerator:
    """Generate playbooks based on threat classification."""
    
    @classmethod
    def get_playbook(
        cls,
        classification: str,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]] = None,
    ) -> ResponsePlaybook:
        """
        Get appropriate playbook for threat classification.
        
        Args:
            classification: Threat classification
            risk_level: Risk level (critical, high, medium, low)
            analysis_result: Optional analysis result for customization
            
        Returns:
            ResponsePlaybook with steps
        """
        classification_lower = classification.lower().replace(' ', '_')
        risk_lower = risk_level.lower() if risk_level else 'medium'
        
        # Check for clean/legitimate results - return minimal playbook
        clean_classifications = ['legitimate', 'clean', 'safe', 'benign', 'none', 'unknown']
        if classification_lower in clean_classifications or risk_lower in ['low', 'minimal', 'none']:
            # Check score if available
            score = 0
            if analysis_result:
                detection = analysis_result.get('detection', {})
                score = detection.get('risk_score', 0)
                if isinstance(score, dict):
                    score = score.get('overall_score', 0)
            
            # If clean or low score, return minimal playbook
            if classification_lower in clean_classifications or score < 30:
                return cls._clean_playbook(risk_lower, analysis_result)
        
        # URL/SMS specific classifications
        url_sms_classifications = [
            'phishing_url', 'malicious_url', 'suspicious_url', 'url_threat',
            'smishing_financial', 'smishing_delivery', 'smishing_prize',
            'smishing_government', 'smishing_tech_support', 'sms_smishing'
        ]
        if classification_lower in url_sms_classifications:
            if 'smishing' in classification_lower or 'sms' in classification_lower:
                return cls._sms_smishing_playbook(risk_lower, analysis_result)
            else:
                return cls._url_threat_playbook(risk_lower, analysis_result)
        
        playbook_map = {
            'phishing': cls._phishing_playbook,
            'spear_phishing': cls._spear_phishing_playbook,
            'bec': cls._bec_playbook,
            'credential_harvesting': cls._credential_harvesting_playbook,
            'malware_delivery': cls._malware_playbook,
            'malware': cls._malware_playbook,
            'ransomware': cls._ransomware_playbook,
            'invoice_fraud': cls._invoice_fraud_playbook,
            'brand_impersonation': cls._brand_impersonation_playbook,
        }
        
        generator = playbook_map.get(classification_lower, cls._generic_playbook)
        playbook = generator(risk_lower, analysis_result)
        
        return playbook
    
    @classmethod
    def _phishing_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Standard phishing response playbook."""
        
        steps = [
            # IMMEDIATE CONTAINMENT
            PlaybookStep(
                id="ph-1",
                title="Quarantine the email",
                description="Move the phishing email to quarantine in email gateway. Remove from all recipient mailboxes.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Invoke-QuarantineEmail -MessageId '<message_id>'",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="ph-2",
                title="Block sender domain/address",
                description="Add sender domain to email blocklist. Consider blocking sender email address if domain is legitimate but compromised.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Add-EmailBlocklist -Domain '<sender_domain>'",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="ph-3",
                title="Block malicious URLs",
                description="Add all extracted URLs to proxy/firewall blocklist. Include redirector domains if identified.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Add-URLBlocklist -URLs @('<url_list>')",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="ph-4",
                title="Block malicious IPs",
                description="Add originating IP and any malicious IPs to firewall blocklist.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            
            # USER NOTIFICATION
            PlaybookStep(
                id="ph-5",
                title="Identify all recipients",
                description="Search email logs to identify all users who received this email or similar variants.",
                category="containment",
                priority=1,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=15,
            ),
            PlaybookStep(
                id="ph-6",
                title="Check for clicks/interactions",
                description="Review proxy logs and EDR data to identify users who clicked links or downloaded attachments.",
                category="containment",
                priority=1,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=20,
            ),
            PlaybookStep(
                id="ph-7",
                title="Notify affected users",
                description="Send notification to all recipients warning about the phishing attempt. Include guidance on what to do if they clicked.",
                category="containment",
                priority=2,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=15,
            ),
            
            # INVESTIGATION
            PlaybookStep(
                id="ph-8",
                title="Investigate compromised users",
                description="For users who clicked: force password reset, review login history, check for email forwarding rules.",
                category="eradication",
                priority=2,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="ph-9",
                title="Search for similar emails",
                description="Search email gateway for similar phishing emails from same sender, domain, or with similar subject/content.",
                category="eradication",
                priority=2,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=20,
            ),
            PlaybookStep(
                id="ph-10",
                title="Hunt for IOCs across environment",
                description="Search SIEM/EDR for connections to identified malicious domains/IPs. Check for malware downloads.",
                category="eradication",
                priority=2,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            
            # RECOVERY
            PlaybookStep(
                id="ph-11",
                title="Reset credentials for compromised users",
                description="Force password reset and MFA re-enrollment for any users who entered credentials.",
                category="recovery",
                priority=2,
                automated=False,
                responsible_team="Identity Team",
                estimated_time_minutes=15,
            ),
            PlaybookStep(
                id="ph-12",
                title="Review and revoke sessions",
                description="Revoke active sessions for compromised accounts. Force re-authentication.",
                category="recovery",
                priority=2,
                automated=False,
                responsible_team="Identity Team",
                estimated_time_minutes=10,
            ),
            
            # LESSONS LEARNED
            PlaybookStep(
                id="ph-13",
                title="Update detection rules",
                description="Create/update SIEM rules to detect similar phishing attempts. Add YARA/Sigma rules.",
                category="lessons_learned",
                priority=3,
                automated=False,
                responsible_team="Detection Engineering",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="ph-14",
                title="Document incident",
                description="Complete incident documentation including timeline, IOCs, affected users, and actions taken.",
                category="lessons_learned",
                priority=3,
                automated=False,
                responsible_team="SOC",
                estimated_time_minutes=20,
            ),
            PlaybookStep(
                id="ph-15",
                title="Report to threat intel",
                description="Share IOCs with threat intel team for tracking. Submit to community feeds if appropriate.",
                category="lessons_learned",
                priority=3,
                automated=False,
                responsible_team="Threat Intel",
                estimated_time_minutes=15,
            ),
        ]
        
        escalation = [
            EscalationCriteria(
                condition="More than 10 users clicked the phishing link",
                escalate_to="SOC Manager",
                timeframe_minutes=30,
            ),
            EscalationCriteria(
                condition="Credentials were entered on phishing page",
                escalate_to="Identity Team Lead",
                timeframe_minutes=15,
            ),
            EscalationCriteria(
                condition="Malware was downloaded/executed",
                escalate_to="Incident Commander",
                timeframe_minutes=15,
            ),
            EscalationCriteria(
                condition="Executive or privileged user affected",
                escalate_to="CISO",
                timeframe_minutes=30,
            ),
        ]
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.PHISHING,
            title="Phishing Response Playbook",
            description="Standard response procedure for phishing email incidents",
            severity=risk_level,
            steps=steps,
            escalation_criteria=escalation,
        )
    
    @classmethod
    def _spear_phishing_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Spear phishing response - more targeted investigation."""
        playbook = cls._phishing_playbook(risk_level, analysis_result)
        playbook.playbook_type = PlaybookType.SPEAR_PHISHING
        playbook.title = "Spear Phishing Response Playbook"
        playbook.description = "Response for targeted spear phishing attacks"
        
        # Add spear-phishing specific steps
        additional_steps = [
            PlaybookStep(
                id="sp-1",
                title="Identify targeting pattern",
                description="Determine why this user/department was targeted. Check if part of larger campaign.",
                category="investigation",
                priority=1,
                responsible_team="Threat Intel",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="sp-2",
                title="Check for reconnaissance",
                description="Look for prior reconnaissance emails, social engineering attempts, or LinkedIn scraping.",
                category="investigation",
                priority=2,
                responsible_team="Threat Intel",
                estimated_time_minutes=45,
            ),
            PlaybookStep(
                id="sp-3",
                title="Alert similar targets",
                description="Notify other users in same department/role who may be targeted next.",
                category="containment",
                priority=2,
                responsible_team="SOC",
                estimated_time_minutes=20,
            ),
        ]
        
        playbook.steps.extend(additional_steps)
        return playbook
    
    @classmethod
    def _bec_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Business Email Compromise playbook."""
        
        steps = [
            # IMMEDIATE
            PlaybookStep(
                id="bec-1",
                title="URGENT: Halt any pending transactions",
                description="Immediately contact Finance/AP to halt any wire transfers, payments, or transactions related to this email.",
                category="containment",
                priority=1,
                responsible_team="SOC + Finance",
                estimated_time_minutes=10,
            ),
            PlaybookStep(
                id="bec-2",
                title="Quarantine the email",
                description="Remove email from recipient mailbox. Search for and quarantine related emails.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="bec-3",
                title="Verify with impersonated party",
                description="Contact the person being impersonated via known-good contact method to verify legitimacy.",
                category="containment",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=15,
            ),
            PlaybookStep(
                id="bec-4",
                title="Check account compromise",
                description="If internal account impersonated: check for signs of compromise, MFA bypass, or email forwarding rules.",
                category="containment",
                priority=1,
                responsible_team="Identity Team",
                estimated_time_minutes=20,
            ),
            
            # FINANCIAL INVESTIGATION
            PlaybookStep(
                id="bec-5",
                title="Document financial requests",
                description="Capture all financial details: amounts, bank accounts, dates, reference numbers mentioned in the email.",
                category="investigation",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=15,
            ),
            PlaybookStep(
                id="bec-6",
                title="Check for prior communication",
                description="Search for any prior emails from same sender or about same transaction. Identify when compromise began.",
                category="investigation",
                priority=2,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="bec-7",
                title="Review vendor/partner communication",
                description="If vendor impersonation: contact vendor to verify banking details. Check for vendor email compromise.",
                category="investigation",
                priority=2,
                responsible_team="Procurement",
                estimated_time_minutes=30,
            ),
            
            # RECOVERY
            PlaybookStep(
                id="bec-8",
                title="Initiate fund recovery (if applicable)",
                description="If funds were transferred: Contact bank immediately for wire recall. Document all attempts.",
                category="recovery",
                priority=1,
                responsible_team="Finance + Legal",
                estimated_time_minutes=60,
            ),
            PlaybookStep(
                id="bec-9",
                title="File IC3 complaint (if applicable)",
                description="For US-based wire fraud: File complaint with FBI Internet Crime Complaint Center.",
                category="recovery",
                priority=2,
                responsible_team="Legal",
                estimated_time_minutes=30,
            ),
            
            # PREVENTION
            PlaybookStep(
                id="bec-10",
                title="Review financial controls",
                description="Ensure dual-approval exists for wire transfers. Verify callback procedures are in place.",
                category="lessons_learned",
                priority=3,
                responsible_team="Finance + Security",
                estimated_time_minutes=60,
            ),
            PlaybookStep(
                id="bec-11",
                title="Executive awareness briefing",
                description="Brief executives on BEC attempt and reinforce verification procedures for financial requests.",
                category="lessons_learned",
                priority=3,
                responsible_team="SOC Manager",
                estimated_time_minutes=30,
            ),
        ]
        
        escalation = [
            EscalationCriteria(
                condition="Funds have already been transferred",
                escalate_to="CISO + CFO",
                timeframe_minutes=5,
            ),
            EscalationCriteria(
                condition="Amount exceeds $50,000",
                escalate_to="Executive Leadership",
                timeframe_minutes=15,
            ),
            EscalationCriteria(
                condition="Executive account compromised",
                escalate_to="Incident Commander + Legal",
                timeframe_minutes=15,
            ),
        ]
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.BEC,
            title="Business Email Compromise Response",
            description="Response procedure for BEC/CEO fraud attempts",
            severity=risk_level,
            steps=steps,
            escalation_criteria=escalation,
        )
    
    @classmethod
    def _credential_harvesting_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Credential harvesting response."""
        playbook = cls._phishing_playbook(risk_level, analysis_result)
        playbook.playbook_type = PlaybookType.CREDENTIAL_HARVESTING
        playbook.title = "Credential Harvesting Response"
        playbook.description = "Response for credential harvesting phishing attacks"
        
        # Add credential-specific steps at high priority
        cred_steps = [
            PlaybookStep(
                id="cred-1",
                title="Force password reset for clickers",
                description="Any user who submitted credentials must have password reset immediately.",
                category="containment",
                priority=1,
                responsible_team="Identity Team",
                estimated_time_minutes=10,
            ),
            PlaybookStep(
                id="cred-2",
                title="Invalidate all sessions",
                description="Revoke all active sessions for affected accounts. Invalidate refresh tokens.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="Identity Team",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="cred-3",
                title="Check for credential reuse",
                description="Search for login attempts from unusual locations/IPs using compromised credentials.",
                category="investigation",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=20,
            ),
            PlaybookStep(
                id="cred-4",
                title="Monitor dark web",
                description="Check threat intel feeds for appearance of compromised credentials.",
                category="investigation",
                priority=2,
                responsible_team="Threat Intel",
                estimated_time_minutes=15,
            ),
        ]
        
        # Insert credential steps at beginning
        playbook.steps = cred_steps + playbook.steps
        return playbook
    
    @classmethod
    def _malware_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Malware delivery response."""
        
        steps = [
            # IMMEDIATE CONTAINMENT
            PlaybookStep(
                id="mal-1",
                title="Quarantine email",
                description="Immediately quarantine the email. Remove from all mailboxes.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="mal-2",
                title="Block attachment hash",
                description="Add file hash (SHA256) to EDR blocklist to prevent execution.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Add-EDRBlocklist -Hash '<sha256>'",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="mal-3",
                title="Block download URLs",
                description="Block any URLs used for payload download or C2 communication.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="mal-4",
                title="Identify file downloads",
                description="Search EDR/proxy logs for any users who downloaded the attachment.",
                category="containment",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=15,
            ),
            PlaybookStep(
                id="mal-5",
                title="Isolate infected endpoints",
                description="Network isolate any endpoint where malware was executed.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Invoke-NetworkIsolate -Hostname '<hostname>'",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            
            # ANALYSIS
            PlaybookStep(
                id="mal-6",
                title="Submit to sandbox",
                description="Detonate attachment in sandbox environment. Capture IOCs and behavior.",
                category="investigation",
                priority=1,
                responsible_team="Malware Analysis",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="mal-7",
                title="Identify malware family",
                description="Determine malware type, family, capabilities, and known TTPs.",
                category="investigation",
                priority=2,
                responsible_team="Threat Intel",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="mal-8",
                title="Hunt for C2 communication",
                description="Search network logs for C2 beaconing. Identify any data exfiltration.",
                category="investigation",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            
            # ERADICATION
            PlaybookStep(
                id="mal-9",
                title="Remove malware",
                description="Use EDR to remove malware from infected endpoints. Verify complete removal.",
                category="eradication",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="mal-10",
                title="Check for persistence",
                description="Scan for persistence mechanisms: scheduled tasks, services, registry keys.",
                category="eradication",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=30,
            ),
            PlaybookStep(
                id="mal-11",
                title="Check for lateral movement",
                description="Hunt for signs of lateral movement from infected endpoints.",
                category="eradication",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=45,
            ),
            
            # RECOVERY
            PlaybookStep(
                id="mal-12",
                title="Reimage if necessary",
                description="If malware cannot be fully removed, reimage affected endpoints.",
                category="recovery",
                priority=2,
                responsible_team="IT Operations",
                estimated_time_minutes=120,
            ),
            PlaybookStep(
                id="mal-13",
                title="Restore from backup",
                description="Restore any encrypted or deleted files from backup.",
                category="recovery",
                priority=2,
                responsible_team="IT Operations",
                estimated_time_minutes=60,
            ),
        ]
        
        escalation = [
            EscalationCriteria(
                condition="Malware executed on more than 5 endpoints",
                escalate_to="Incident Commander",
                timeframe_minutes=15,
            ),
            EscalationCriteria(
                condition="Ransomware detected",
                escalate_to="CISO + Incident Commander",
                timeframe_minutes=5,
            ),
            EscalationCriteria(
                condition="Data exfiltration detected",
                escalate_to="CISO + Legal",
                timeframe_minutes=15,
            ),
            EscalationCriteria(
                condition="Domain controller affected",
                escalate_to="Incident Commander + Identity Team Lead",
                timeframe_minutes=5,
            ),
        ]
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.MALWARE,
            title="Malware Delivery Response",
            description="Response for malware delivery via email attachment",
            severity=risk_level,
            steps=steps,
            escalation_criteria=escalation,
        )
    
    @classmethod
    def _ransomware_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Ransomware response - highest priority."""
        playbook = cls._malware_playbook(risk_level, analysis_result)
        playbook.playbook_type = PlaybookType.RANSOMWARE
        playbook.title = "RANSOMWARE Response Playbook"
        playbook.description = "CRITICAL: Response for ransomware delivery/execution"
        
        # Add ransomware-specific steps at beginning
        ransomware_steps = [
            PlaybookStep(
                id="rans-0",
                title="ACTIVATE INCIDENT RESPONSE TEAM",
                description="Immediately activate IR team and establish war room. This is a critical incident.",
                category="containment",
                priority=1,
                responsible_team="Incident Commander",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="rans-1",
                title="Disconnect from network segments",
                description="Consider disconnecting affected network segments to prevent spread.",
                category="containment",
                priority=1,
                responsible_team="Network Team",
                estimated_time_minutes=10,
            ),
            PlaybookStep(
                id="rans-2",
                title="Preserve evidence",
                description="Capture memory dumps and disk images before remediation for forensics.",
                category="containment",
                priority=1,
                responsible_team="Forensics",
                estimated_time_minutes=60,
            ),
        ]
        
        playbook.steps = ransomware_steps + playbook.steps
        return playbook
    
    @classmethod
    def _invoice_fraud_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Invoice fraud response."""
        playbook = cls._bec_playbook(risk_level, analysis_result)
        playbook.playbook_type = PlaybookType.INVOICE_FRAUD
        playbook.title = "Invoice Fraud Response"
        playbook.description = "Response for fraudulent invoice/payment redirect attacks"
        return playbook
    
    @classmethod
    def _brand_impersonation_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Brand impersonation response."""
        playbook = cls._phishing_playbook(risk_level, analysis_result)
        playbook.playbook_type = PlaybookType.BRAND_IMPERSONATION
        playbook.title = "Brand Impersonation Response"
        playbook.description = "Response for brand impersonation phishing"
        
        # Add brand-specific step
        playbook.steps.append(PlaybookStep(
            id="brand-1",
            title="Report to impersonated brand",
            description="Report the impersonation to the legitimate brand's abuse/security team.",
            category="lessons_learned",
            priority=3,
            responsible_team="Threat Intel",
            estimated_time_minutes=15,
        ))
        
        return playbook
    
    @classmethod
    def _generic_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Generic response for unknown classifications."""
        return cls._phishing_playbook(risk_level, analysis_result)
    
    @classmethod
    def _clean_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Minimal playbook for clean/legitimate results."""
        
        steps = [
            PlaybookStep(
                id="clean-1",
                title="Verify analysis results",
                description="Review the analysis to confirm no threats were detected. Check for any edge cases or false negatives.",
                category="verification",
                priority=3,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="clean-2",
                title="Document and close",
                description="Mark the analysis as reviewed. No further action required for clean results.",
                category="documentation",
                priority=3,
                responsible_team="SOC",
                estimated_time_minutes=2,
            ),
        ]
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.CLEAN,
            title="Clean Result - No Action Required",
            description="This analysis found no significant threats. Minimal verification steps only.",
            severity="low",
            steps=steps,
            escalation_criteria=[],
        )
    
    @classmethod
    def _url_threat_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Playbook for URL-based threats (phishing URLs, malicious links)."""
        
        # Determine step count based on risk level
        is_high_risk = risk_level.lower() in ['high', 'critical']
        
        steps = [
            # IMMEDIATE CONTAINMENT
            PlaybookStep(
                id="url-1",
                title="Block malicious URL(s)",
                description="Add URL(s) to proxy/firewall blocklist immediately. Include domain-level blocks if needed.",
                category="containment",
                priority=1,
                automated=True,
                automation_command="Add-URLBlocklist -URLs @('<url_list>')",
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="url-2",
                title="Check for user access",
                description="Search proxy/firewall logs for any users who accessed the malicious URL(s).",
                category="containment",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=10,
            ),
        ]
        
        if is_high_risk:
            steps.extend([
                PlaybookStep(
                    id="url-3",
                    title="Notify affected users",
                    description="If users clicked the link, notify them and security awareness team.",
                    category="containment",
                    priority=1,
                    responsible_team="SOC",
                    estimated_time_minutes=15,
                ),
                PlaybookStep(
                    id="url-4",
                    title="Check for credential submission",
                    description="If phishing page, check if users submitted credentials. Reset passwords if necessary.",
                    category="eradication",
                    priority=1,
                    responsible_team="SOC + Identity Team",
                    estimated_time_minutes=20,
                ),
                PlaybookStep(
                    id="url-5",
                    title="Report to threat intel",
                    description="Submit URL(s) to PhishTank, VirusTotal, and relevant threat feeds.",
                    category="recovery",
                    priority=2,
                    responsible_team="SOC",
                    estimated_time_minutes=10,
                ),
            ])
        
        # Final documentation step
        steps.append(
            PlaybookStep(
                id="url-final",
                title="Document and close",
                description="Document all actions taken and close the incident.",
                category="documentation",
                priority=3,
                responsible_team="SOC",
                estimated_time_minutes=5,
            )
        )
        
        escalation = []
        if is_high_risk:
            escalation = [
                EscalationCriteria(
                    condition="More than 10 users accessed the URL",
                    escalate_to="SOC Manager",
                    timeframe_minutes=30,
                ),
                EscalationCriteria(
                    condition="Credentials were submitted",
                    escalate_to="Identity Team Lead + SOC Manager",
                    timeframe_minutes=15,
                ),
            ]
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.URL_THREAT,
            title="URL Threat Response",
            description="Response for malicious/phishing URL detection",
            severity=risk_level,
            steps=steps,
            escalation_criteria=escalation,
        )
    
    @classmethod
    def _sms_smishing_playbook(
        cls,
        risk_level: str,
        analysis_result: Optional[Dict[str, Any]],
    ) -> ResponsePlaybook:
        """Playbook for SMS smishing attacks."""
        
        is_high_risk = risk_level.lower() in ['high', 'critical']
        
        steps = [
            PlaybookStep(
                id="sms-1",
                title="Block sender number",
                description="Block the sender phone number in mobile device management (MDM) if applicable.",
                category="containment",
                priority=1,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
            PlaybookStep(
                id="sms-2",
                title="Block embedded URLs",
                description="Add any URLs from the SMS to proxy/firewall blocklist.",
                category="containment",
                priority=1,
                automated=True,
                responsible_team="SOC",
                estimated_time_minutes=5,
            ),
        ]
        
        if is_high_risk:
            steps.extend([
                PlaybookStep(
                    id="sms-3",
                    title="Alert affected users",
                    description="Send security alert to users who may have received similar messages.",
                    category="containment",
                    priority=1,
                    responsible_team="Security Awareness",
                    estimated_time_minutes=15,
                ),
                PlaybookStep(
                    id="sms-4",
                    title="Check for corporate impact",
                    description="Determine if corporate phones or accounts were targeted.",
                    category="eradication",
                    priority=2,
                    responsible_team="SOC",
                    estimated_time_minutes=20,
                ),
                PlaybookStep(
                    id="sms-5",
                    title="Report to carrier",
                    description="Report the smishing number to mobile carrier abuse teams.",
                    category="recovery",
                    priority=3,
                    responsible_team="SOC",
                    estimated_time_minutes=10,
                ),
            ])
        
        steps.append(
            PlaybookStep(
                id="sms-final",
                title="Document and close",
                description="Document findings and close the case.",
                category="documentation",
                priority=3,
                responsible_team="SOC",
                estimated_time_minutes=5,
            )
        )
        
        return ResponsePlaybook(
            playbook_type=PlaybookType.SMS_SMISHING,
            title="SMS Smishing Response",
            description="Response for SMS/text message phishing (smishing) attacks",
            severity=risk_level,
            steps=steps,
            escalation_criteria=[],
        )
