"""
NiksES Custom Rules API Routes

Endpoints for managing custom detection rules.
Supports both simple and advanced rule formats.
"""

import logging
from typing import List, Optional, Any, Dict

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.services.detection.custom_rules import (
    get_custom_rule_engine,
    CustomRule,
    MatchType,
    FieldTarget,
)
from app.models.detection import RiskLevel as Severity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rules", tags=["rules"])


# Request/Response Models

class ConditionCreate(BaseModel):
    """Condition for rule creation - supports both old and new formats."""
    id: Optional[str] = None
    field: str = Field(..., description="Target field")
    operator: Optional[str] = Field(None, description="Operator (new format)")
    match_type: Optional[str] = Field(None, description="Match type (old format)")
    value: str = Field("", description="Value to match")
    value2: Optional[str] = Field(None, description="Second value for 'between' operator")
    case_sensitive: bool = Field(False, description="Case sensitive matching")


class ConditionGroupCreate(BaseModel):
    """Group of conditions with logic."""
    id: Optional[str] = None
    logic: str = Field("AND", description="Logic within group (AND/OR)")
    conditions: List[ConditionCreate] = Field(default_factory=list)


class RuleCreate(BaseModel):
    """Request model for creating a custom rule - supports both formats."""
    id: Optional[str] = Field(None, description="Rule ID (for updates)")
    name: str = Field(..., min_length=1, max_length=100, description="Rule name")
    description: str = Field("", max_length=500, description="Rule description")
    category: str = Field("custom", description="Rule category")
    severity: str = Field("medium", description="Severity level")
    
    # Old format (flat conditions)
    conditions: Optional[List[ConditionCreate]] = Field(None, description="Rule conditions (old format)")
    logic: str = Field("AND", description="Logic operator (AND/OR)")
    
    # New format (grouped conditions)
    conditionGroups: Optional[List[ConditionGroupCreate]] = Field(None, description="Condition groups (new format)")
    groupLogic: str = Field("AND", description="Logic between groups")
    
    # Metadata
    tags: List[str] = Field(default_factory=list, description="Rule tags")
    mitre_technique: Optional[str] = Field(None, description="MITRE technique (old format)")
    mitreTechniques: List[str] = Field(default_factory=list, description="MITRE techniques (new format)")
    
    enabled: bool = Field(True, description="Rule enabled")
    score: Optional[int] = Field(None, description="Score impact")
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class RuleCreate(BaseModel):
    """Request model for creating a custom rule."""
    name: str = Field(..., min_length=3, max_length=100, description="Rule name")
    description: str = Field(..., max_length=500, description="Rule description")
    category: str = Field(..., description="Rule category")
    severity: str = Field(..., description="Severity level")
    conditions: List[ConditionCreate] = Field(..., min_length=1, description="Rule conditions")
    logic: str = Field("AND", description="Logic operator (AND/OR)")
    tags: List[str] = Field(default=[], description="Rule tags")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")


class RuleUpdate(BaseModel):
    """Request model for updating a custom rule."""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    conditions: Optional[List[ConditionCreate]] = None
    logic: Optional[str] = None
    enabled: Optional[bool] = None
    tags: Optional[List[str]] = None
    mitre_technique: Optional[str] = None


class RuleResponse(BaseModel):
    """Response model for a rule."""
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    conditions: List[dict]
    logic: str
    enabled: bool
    created_at: str
    updated_at: str
    author: str
    tags: List[str]
    mitre_technique: Optional[str]


class RuleListResponse(BaseModel):
    """Response model for rule list."""
    total: int
    rules: List[RuleResponse]


# Endpoints

@router.get("", response_model=RuleListResponse)
async def list_rules(
    enabled_only: bool = False,
    category: Optional[str] = None,
):
    """
    List all custom detection rules.
    
    Args:
        enabled_only: Only return enabled rules
        category: Filter by category
    """
    engine = get_custom_rule_engine()
    rules = engine.list_rules(enabled_only=enabled_only)
    
    if category:
        rules = [r for r in rules if r.category == category]
    
    return RuleListResponse(
        total=len(rules),
        rules=[RuleResponse(**r.to_dict()) for r in rules],
    )


@router.get("/categories")
async def list_categories():
    """Get available rule categories and field targets."""
    return {
        "categories": [
            "authentication",
            "phishing",
            "malware",
            "bec",
            "lookalike",
            "social_engineering",
            "data_protection",
            "spam",
            "custom",
        ],
        "field_targets": [f.value for f in FieldTarget],
        "match_types": [m.value for m in MatchType],
        "severities": [s.value for s in Severity],
    }


@router.get("/templates")
async def get_rule_templates():
    """Get example rule templates for common use cases."""
    return {
        "templates": [
            {
                "name": "Keyword in Subject",
                "description": "Detect specific keywords in email subject",
                "category": "custom",
                "severity": "medium",
                "conditions": [
                    {"field": "subject", "match_type": "contains", "value": "YOUR_KEYWORD"}
                ],
                "logic": "AND",
            },
            {
                "name": "Suspicious Sender Domain",
                "description": "Block emails from specific domains",
                "category": "phishing",
                "severity": "high",
                "conditions": [
                    {"field": "sender_domain", "match_type": "equals", "value": "suspicious.com"}
                ],
                "logic": "AND",
            },
            {
                "name": "Dangerous Attachment Extension",
                "description": "Detect dangerous file extensions",
                "category": "malware",
                "severity": "critical",
                "conditions": [
                    {"field": "attachment_extensions", "match_type": "equals", "value": ".iso"},
                    {"field": "attachment_extensions", "match_type": "equals", "value": ".img"},
                ],
                "logic": "OR",
            },
            {
                "name": "URL Pattern Detection",
                "description": "Detect URLs matching a pattern",
                "category": "phishing",
                "severity": "high",
                "conditions": [
                    {"field": "urls", "match_type": "regex", "value": r"https?://[^/]*login[^/]*\."}
                ],
                "logic": "AND",
            },
            {
                "name": "Reply-To Mismatch",
                "description": "Different domain in reply-to header",
                "category": "bec",
                "severity": "medium",
                "conditions": [
                    {"field": "reply_to", "match_type": "not_contains", "value": "@company.com"}
                ],
                "logic": "AND",
            },
        ]
    }


@router.post("")
async def create_rule(rule: RuleCreate):
    """
    Create a new custom detection rule.
    
    Supports both old format (flat conditions) and new format (conditionGroups).
    The rule will be immediately active and applied to future analyses.
    """
    engine = get_custom_rule_engine()
    
    # Validate severity
    severity_map = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFORMATIONAL,
        'informational': Severity.INFORMATIONAL,
    }
    severity = severity_map.get(rule.severity.lower(), Severity.MEDIUM)
    
    # Convert new format (conditionGroups) to old format if needed
    flat_conditions = []
    logic = rule.logic
    
    if rule.conditionGroups:
        # New format with condition groups
        for group in rule.conditionGroups:
            for cond in group.conditions:
                if cond.field:  # Only add non-empty conditions
                    flat_conditions.append({
                        'field': cond.field,
                        'match_type': cond.operator or cond.match_type or 'contains',
                        'value': cond.value or '',
                        'case_sensitive': cond.case_sensitive,
                    })
        # Use the first group's logic, or groupLogic
        if rule.conditionGroups and rule.conditionGroups[0].conditions:
            logic = rule.conditionGroups[0].logic or rule.groupLogic
    elif rule.conditions:
        # Old format with flat conditions
        for cond in rule.conditions:
            if cond.field:
                flat_conditions.append({
                    'field': cond.field,
                    'match_type': cond.operator or cond.match_type or 'contains',
                    'value': cond.value or '',
                    'case_sensitive': cond.case_sensitive,
                })
    
    if not flat_conditions:
        raise HTTPException(status_code=400, detail="At least one condition is required")
    
    # Handle MITRE techniques (new format is array, old format is single string)
    mitre = rule.mitreTechniques[0] if rule.mitreTechniques else rule.mitre_technique
    
    # Create the rule
    new_rule = engine.create_rule(
        name=rule.name,
        description=rule.description or '',
        category=rule.category or 'custom',
        severity=severity,
        conditions=flat_conditions,
        logic=logic,
        tags=rule.tags or [],
        mitre_technique=mitre,
    )
    
    # Return in a format the frontend expects
    response_data = new_rule.to_dict()
    
    # Add fields the advanced frontend expects
    response_data['id'] = response_data['rule_id']
    response_data['conditionGroups'] = [{
        'id': '1',
        'logic': new_rule.logic,
        'conditions': [
            {
                'id': str(i),
                'field': c.field.value,
                'operator': c.match_type.value,
                'value': c.value,
            }
            for i, c in enumerate(new_rule.conditions)
        ]
    }]
    response_data['groupLogic'] = new_rule.logic
    response_data['mitreTechniques'] = [new_rule.mitre_technique] if new_rule.mitre_technique else []
    response_data['score'] = rule.score or _get_severity_score(severity)
    
    return response_data


def _get_severity_score(severity: Severity) -> int:
    """Get score for severity level."""
    scores = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 25,
        Severity.MEDIUM: 15,
        Severity.LOW: 5,
        Severity.INFORMATIONAL: 0,
    }
    return scores.get(severity, 10)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str):
    """Get a specific rule by ID."""
    engine = get_custom_rule_engine()
    rule = engine.get_rule(rule_id)
    
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return RuleResponse(**rule.to_dict())


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: str, updates: RuleUpdate):
    """Update an existing rule."""
    engine = get_custom_rule_engine()
    
    # Build update dict
    update_dict = {}
    if updates.name is not None:
        update_dict["name"] = updates.name
    if updates.description is not None:
        update_dict["description"] = updates.description
    if updates.category is not None:
        update_dict["category"] = updates.category
    if updates.severity is not None:
        update_dict["severity"] = updates.severity
    if updates.conditions is not None:
        update_dict["conditions"] = [c.model_dump() for c in updates.conditions]
    if updates.logic is not None:
        update_dict["logic"] = updates.logic
    if updates.enabled is not None:
        update_dict["enabled"] = updates.enabled
    if updates.tags is not None:
        update_dict["tags"] = updates.tags
    if updates.mitre_technique is not None:
        update_dict["mitre_technique"] = updates.mitre_technique
    
    rule = engine.update_rule(rule_id, update_dict)
    
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return RuleResponse(**rule.to_dict())


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a custom rule."""
    engine = get_custom_rule_engine()
    
    if not engine.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return {"message": "Rule deleted", "rule_id": rule_id}


@router.post("/{rule_id}/toggle")
async def toggle_rule(rule_id: str, enabled: bool = True):
    """Enable or disable a rule."""
    engine = get_custom_rule_engine()
    
    if not engine.toggle_rule(rule_id, enabled):
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return {"message": f"Rule {'enabled' if enabled else 'disabled'}", "rule_id": rule_id}


@router.get("/export/json")
async def export_rules():
    """Export all rules to JSON format."""
    engine = get_custom_rule_engine()
    return {"rules_json": engine.export_rules()}


@router.post("/import/json")
async def import_rules(data: dict):
    """
    Import rules from JSON.
    
    Expected format: {"rules": [...]}
    """
    import json
    engine = get_custom_rule_engine()
    
    if "rules" not in data:
        raise HTTPException(status_code=400, detail="Missing 'rules' field")
    
    try:
        count = engine.import_rules(json.dumps(data["rules"]))
        return {"message": f"Imported {count} rules", "count": count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


@router.post("/test")
async def test_rule(rule: RuleCreate, email_sample: dict):
    """
    Test a rule against a sample email without saving it.
    
    Useful for validating rule logic before creating.
    """
    from app.models.email import ParsedEmail, EmailAddress
    
    engine = get_custom_rule_engine()
    
    # Create temporary rule
    try:
        severity = Severity(rule.severity)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {rule.severity}")
    
    temp_rule = CustomRule(
        rule_id="TEST-001",
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=severity,
        conditions=[],
        logic=rule.logic,
    )
    
    # Add conditions
    from app.services.detection.custom_rules import RuleCondition
    for cond in rule.conditions:
        temp_rule.conditions.append(RuleCondition(
            field=FieldTarget(cond.field),
            match_type=MatchType(cond.match_type),
            value=cond.value,
            case_sensitive=cond.case_sensitive,
        ))
    
    # Create minimal email from sample
    email = ParsedEmail(
        message_id="test",
        subject=email_sample.get("subject", ""),
        body_text=email_sample.get("body", ""),
        sender=EmailAddress(email=email_sample.get("sender_email", "test@test.com")),
    )
    
    # Evaluate
    match = engine.evaluate_rule(temp_rule, email)
    
    return {
        "triggered": match is not None,
        "match": match.model_dump() if match else None,
    }
