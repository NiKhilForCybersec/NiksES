"""
NiksES SOC Tools Module

Provides SOC analyst utilities:
- IOC extraction and formatting
- YARA/Sigma rule generation
- Incident ticket templates
- Response playbooks
- User notification templates
"""

from .ioc_formatter import IOCFormatter, DefangMode
from .rule_generator import YARARuleGenerator, SigmaRuleGenerator
from .ticket_generator import IncidentTicketGenerator
from .playbooks import ResponsePlaybook, PlaybookType, PlaybookGenerator
from .notification_templates import UserNotificationGenerator

__all__ = [
    'IOCFormatter',
    'DefangMode',
    'YARARuleGenerator',
    'SigmaRuleGenerator',
    'IncidentTicketGenerator',
    'ResponsePlaybook',
    'PlaybookType',
    'PlaybookGenerator',
    'UserNotificationGenerator',
]
