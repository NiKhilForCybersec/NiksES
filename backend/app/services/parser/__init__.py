"""
NiksES Email Parser Module

Provides email parsing functionality for .eml, .msg, and raw email formats.
"""

# Parser functions - these raise NotImplementedError until Session 4 full implementation
from .eml_parser import parse_eml_file, parse_eml_bytes
from .msg_parser import parse_msg_file, parse_msg_bytes
from .raw_parser import parse_raw_email
from .header_analyzer import analyze_headers, extract_received_chain, extract_auth_results
from .url_extractor import extract_urls, normalize_url
from .attachment_processor import process_attachments, hash_attachment
from .qr_decoder import decode_qr_codes, find_qr_in_image

__all__ = [
    'parse_eml_file',
    'parse_eml_bytes',
    'parse_msg_file',
    'parse_msg_bytes',
    'parse_raw_email',
    'analyze_headers',
    'extract_received_chain',
    'extract_auth_results',
    'extract_urls',
    'normalize_url',
    'process_attachments',
    'hash_attachment',
    'decode_qr_codes',
    'find_qr_in_image',
]
