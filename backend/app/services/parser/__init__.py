"""
NiksES Email Parsing Services

Provides email parsing for EML, MSG formats and header analysis.
"""

from .eml_parser import parse_eml_file, parse_eml_bytes
from .msg_parser import parse_msg_file, parse_msg_bytes
from .header_analyzer import analyze_headers
from .qr_decoder import decode_qr_codes
from .attachment_processor import process_attachments

__all__ = [
    'parse_eml_file',
    'parse_eml_bytes',
    'parse_msg_file',
    'parse_msg_bytes',
    'analyze_headers',
    'decode_qr_codes',
    'process_attachments',
]
