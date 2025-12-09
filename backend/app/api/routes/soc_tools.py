"""
NiksES SOC Tools API Routes

Endpoints for SOC analyst utilities:
- IOC export
- YARA/Sigma rule generation
- Incident ticket generation
- Response playbooks
- User notifications
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

from app.services.soc.ioc_formatter import IOCFormatter, DefangMode, ExtractedIOCs
from app.services.soc.rule_generator import YARARuleGenerator, SigmaRuleGenerator
from app.services.soc.ticket_generator import IncidentTicketGenerator, TicketFormat
from app.services.soc.playbooks import PlaybookGenerator, PlaybookType
from app.services.soc.notification_templates import UserNotificationGenerator, NotificationType

router = APIRouter(prefix="/soc", tags=["SOC Tools"])


# ============================================================================
# Request/Response Models
# ============================================================================

class IOCExportRequest(BaseModel):
    """Request for IOC export."""
    analysis_result: Dict[str, Any] = Field(..., description="Analysis result to extract IOCs from")
    defang_mode: str = Field("brackets", description="Defanging mode: none, brackets, full")
    format: str = Field("text", description="Export format: text, csv, json")
    siem_format: str = Field("generic", description="SIEM format: generic, splunk, elastic, sentinel")
    include_types: Optional[List[str]] = Field(None, description="IOC types to include")


class IOCExportResponse(BaseModel):
    """Response for IOC export."""
    content: str
    format: str
    total_iocs: int
    ioc_counts: Dict[str, int]


class RuleGenerationRequest(BaseModel):
    """Request for detection rule generation."""
    analysis_result: Dict[str, Any] = Field(..., description="Analysis result")
    rule_types: List[str] = Field(["yara", "sigma"], description="Rule types to generate")
    rule_name_prefix: str = Field("NiksES", description="Prefix for rule names")


class RuleGenerationResponse(BaseModel):
    """Response for rule generation."""
    rules: List[Dict[str, Any]]
    total_rules: int


class TicketGenerationRequest(BaseModel):
    """Request for incident ticket generation."""
    analysis_result: Dict[str, Any] = Field(..., description="Analysis result")
    format: str = Field("generic", description="Ticket format: generic, servicenow, jira, markdown")
    analyst_name: str = Field("", description="Analyst name for assignment")
    additional_notes: str = Field("", description="Additional notes to include")


class PlaybookRequest(BaseModel):
    """Request for response playbook."""
    classification: str = Field(..., description="Threat classification")
    risk_level: str = Field("medium", description="Risk level")
    analysis_result: Optional[Dict[str, Any]] = Field(None, description="Analysis result for customization")


class NotificationRequest(BaseModel):
    """Request for user notification."""
    notification_type: str = Field(..., description="Notification type")
    analysis_result: Dict[str, Any] = Field(..., description="Analysis result")
    recipient_name: str = Field("User", description="Recipient name")
    recipient_email: str = Field("", description="Recipient email")
    additional_context: str = Field("", description="Additional context")
    include_iocs: bool = Field(False, description="Include IOC details")
    security_team_contact: str = Field("security@company.com", description="Security team contact")
    company_name: str = Field("Security Team", description="Company name")


# ============================================================================
# IOC Endpoints
# ============================================================================

@router.post("/iocs/extract", response_model=IOCExportResponse)
async def extract_iocs(request: IOCExportRequest):
    """
    Extract and format IOCs from analysis result.
    
    Supports multiple export formats and defanging options.
    """
    try:
        # Extract IOCs
        iocs = IOCFormatter.extract_from_analysis(request.analysis_result)
        
        # Get defang mode
        defang_mode_map = {
            'none': DefangMode.NONE,
            'brackets': DefangMode.BRACKETS,
            'full': DefangMode.FULL,
        }
        defang_mode = defang_mode_map.get(request.defang_mode.lower(), DefangMode.BRACKETS)
        
        # Format based on requested format
        if request.format.lower() == 'csv':
            content = IOCFormatter.export_csv(iocs, defang_mode)
        elif request.format.lower() == 'json':
            content = IOCFormatter.export_json(iocs, defang_mode, request.siem_format)
        else:
            content = IOCFormatter.format_for_copy(iocs, defang_mode, request.include_types)
        
        return IOCExportResponse(
            content=content,
            format=request.format,
            total_iocs=iocs.total_count(),
            ioc_counts={
                'domains': len(iocs.domains),
                'urls': len(iocs.urls),
                'ips': len(iocs.ips),
                'email_addresses': len(iocs.email_addresses),
                'hashes_sha256': len(iocs.hashes_sha256),
                'hashes_sha1': len(iocs.hashes_sha1),
                'hashes_md5': len(iocs.hashes_md5),
                'file_names': len(iocs.file_names),
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/iocs/blocklist")
async def generate_blocklist(request: IOCExportRequest):
    """
    Generate blocklist for firewall/proxy.
    """
    try:
        iocs = IOCFormatter.extract_from_analysis(request.analysis_result)
        
        blocklists = {
            'domains': IOCFormatter.format_for_block_list(iocs, 'domain'),
            'urls': IOCFormatter.format_for_block_list(iocs, 'url'),
            'ips': IOCFormatter.format_for_block_list(iocs, 'ip'),
            'all': IOCFormatter.format_for_block_list(iocs, 'all'),
        }
        
        return {
            'blocklists': blocklists,
            'counts': {
                'domains': len(iocs.domains),
                'urls': len(iocs.urls),
                'ips': len(iocs.ips),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Detection Rule Endpoints
# ============================================================================

@router.post("/rules/generate", response_model=RuleGenerationResponse)
async def generate_rules(request: RuleGenerationRequest):
    """
    Generate YARA and/or Sigma detection rules from analysis.
    """
    try:
        all_rules = []
        
        if 'yara' in request.rule_types:
            yara_rules = YARARuleGenerator.generate_from_analysis(
                request.analysis_result,
                request.rule_name_prefix,
            )
            all_rules.extend([r.to_dict() for r in yara_rules])
        
        if 'sigma' in request.rule_types:
            sigma_rules = SigmaRuleGenerator.generate_from_analysis(
                request.analysis_result,
                request.rule_name_prefix,
            )
            all_rules.extend([r.to_dict() for r in sigma_rules])
        
        return RuleGenerationResponse(
            rules=all_rules,
            total_rules=len(all_rules),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Incident Ticket Endpoints
# ============================================================================

@router.post("/ticket/generate")
async def generate_ticket(request: TicketGenerationRequest):
    """
    Generate incident ticket from analysis result.
    """
    try:
        format_map = {
            'generic': TicketFormat.GENERIC,
            'servicenow': TicketFormat.SERVICENOW,
            'jira': TicketFormat.JIRA,
            'markdown': TicketFormat.MARKDOWN,
        }
        ticket_format = format_map.get(request.format.lower(), TicketFormat.GENERIC)
        
        ticket = IncidentTicketGenerator.generate(
            analysis_result=request.analysis_result,
            format=ticket_format,
            analyst_name=request.analyst_name,
            additional_notes=request.additional_notes,
        )
        
        return ticket
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ticket/formats")
async def get_ticket_formats():
    """Get available ticket formats."""
    return {
        'formats': [
            {'id': 'generic', 'name': 'Generic', 'description': 'Universal ticket format'},
            {'id': 'servicenow', 'name': 'ServiceNow', 'description': 'ServiceNow incident format'},
            {'id': 'jira', 'name': 'Jira', 'description': 'Jira issue format'},
            {'id': 'markdown', 'name': 'Markdown', 'description': 'Markdown for wiki/docs'},
        ]
    }


# ============================================================================
# Playbook Endpoints
# ============================================================================

@router.post("/playbook/get")
async def get_playbook(request: PlaybookRequest):
    """
    Get response playbook for threat classification.
    """
    try:
        playbook = PlaybookGenerator.get_playbook(
            classification=request.classification,
            risk_level=request.risk_level,
            analysis_result=request.analysis_result,
        )
        
        return playbook.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/playbook/types")
async def get_playbook_types():
    """Get available playbook types."""
    return {
        'types': [
            {'id': 'phishing', 'name': 'Phishing', 'description': 'Standard phishing response'},
            {'id': 'spear_phishing', 'name': 'Spear Phishing', 'description': 'Targeted phishing response'},
            {'id': 'bec', 'name': 'BEC', 'description': 'Business Email Compromise'},
            {'id': 'credential_harvesting', 'name': 'Credential Harvesting', 'description': 'Credential theft response'},
            {'id': 'malware', 'name': 'Malware', 'description': 'Malware delivery response'},
            {'id': 'ransomware', 'name': 'Ransomware', 'description': 'Ransomware response'},
            {'id': 'invoice_fraud', 'name': 'Invoice Fraud', 'description': 'Invoice/payment fraud'},
            {'id': 'brand_impersonation', 'name': 'Brand Impersonation', 'description': 'Brand spoofing'},
        ]
    }


# ============================================================================
# User Notification Endpoints
# ============================================================================

@router.post("/notification/generate")
async def generate_notification(request: NotificationRequest):
    """
    Generate user notification email.
    """
    try:
        notif_type_map = {
            'phishing_warning': NotificationType.PHISHING_WARNING,
            'credential_compromise': NotificationType.CREDENTIAL_COMPROMISE,
            'malware_warning': NotificationType.MALWARE_WARNING,
            'bec_attempt': NotificationType.BEC_ATTEMPT,
            'account_secured': NotificationType.ACCOUNT_SECURED,
            'general_warning': NotificationType.GENERAL_WARNING,
        }
        
        notif_type = notif_type_map.get(
            request.notification_type.lower(),
            NotificationType.GENERAL_WARNING,
        )
        
        notification = UserNotificationGenerator.generate(
            notification_type=notif_type,
            analysis_result=request.analysis_result,
            recipient_name=request.recipient_name,
            recipient_email=request.recipient_email,
            additional_context=request.additional_context,
            include_iocs=request.include_iocs,
            security_team_contact=request.security_team_contact,
            company_name=request.company_name,
        )
        
        return notification
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/notification/templates")
async def get_notification_templates():
    """Get available notification templates."""
    return {
        'templates': UserNotificationGenerator.get_available_templates()
    }


# ============================================================================
# Quick Actions Endpoints
# ============================================================================

@router.post("/quick-actions")
async def get_quick_actions(analysis_result: Dict[str, Any]):
    """
    Get all quick action data for an analysis result.
    
    Returns IOCs, rules, ticket, playbook, and notification in one call.
    """
    try:
        # Extract IOCs
        iocs = IOCFormatter.extract_from_analysis(analysis_result)
        
        # Get classification
        detection = analysis_result.get('detection', {})
        classification = detection.get('primary_classification', 'unknown')
        if hasattr(classification, 'value'):
            classification = classification.value
        risk_level = detection.get('risk_level', 'medium')
        if hasattr(risk_level, 'value'):
            risk_level = risk_level.value
        
        # Generate all outputs
        yara_rules = YARARuleGenerator.generate_from_analysis(analysis_result)
        sigma_rules = SigmaRuleGenerator.generate_from_analysis(analysis_result)
        
        playbook = PlaybookGenerator.get_playbook(
            classification=classification,
            risk_level=risk_level,
            analysis_result=analysis_result,
        )
        
        ticket = IncidentTicketGenerator.generate(
            analysis_result=analysis_result,
            format=TicketFormat.GENERIC,
        )
        
        return {
            'iocs': {
                'data': iocs.to_dict(),
                'formatted': {
                    'text': IOCFormatter.format_for_copy(iocs, DefangMode.BRACKETS),
                    'defanged_full': IOCFormatter.format_for_copy(iocs, DefangMode.FULL),
                    'csv': IOCFormatter.export_csv(iocs),
                    'json': IOCFormatter.export_json(iocs),
                },
                'blocklist': {
                    'domains': IOCFormatter.format_for_block_list(iocs, 'domain'),
                    'ips': IOCFormatter.format_for_block_list(iocs, 'ip'),
                },
                'counts': {
                    'domains': len(iocs.domains),
                    'urls': len(iocs.urls),
                    'ips': len(iocs.ips),
                    'hashes': len(iocs.hashes_sha256) + len(iocs.hashes_md5),
                    'total': iocs.total_count(),
                }
            },
            'rules': {
                'yara': [r.to_dict() for r in yara_rules],
                'sigma': [r.to_dict() for r in sigma_rules],
            },
            'playbook': playbook.to_dict(),
            'ticket': ticket,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
