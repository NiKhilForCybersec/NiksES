"""
NiksES Email Data Models

Pydantic models for parsed email data structures.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class EmailDirection(str, Enum):
    """Email direction classification."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class EmailAddress(BaseModel):
    """Parsed email address with display name."""
    raw: str = Field(..., description="Original raw address string")
    email: str = Field(..., description="Normalized email address")
    display_name: Optional[str] = Field(None, description="Display name if present")
    domain: str = Field(..., description="Domain part of email")
    local_part: str = Field(..., description="Local part before @")


class ReceivedHop(BaseModel):
    """Single hop in the Received header chain."""
    hop_number: int = Field(..., description="Hop number (1 = first hop)")
    from_host: Optional[str] = Field(None, description="Sending host")
    from_ip: Optional[str] = Field(None, description="Sending IP")
    by_host: Optional[str] = Field(None, description="Receiving host")
    by_ip: Optional[str] = Field(None, description="Receiving IP")
    protocol: Optional[str] = Field(None, description="Protocol (SMTP, ESMTP, etc.)")
    timestamp: Optional[datetime] = Field(None, description="Timestamp of hop")
    delay_seconds: Optional[float] = Field(None, description="Delay from previous hop")
    raw_header: str = Field(..., description="Raw Received header value")


class AuthenticationResult(BaseModel):
    """Email authentication check result."""
    mechanism: str = Field(..., description="SPF, DKIM, or DMARC")
    result: str = Field(..., description="pass, fail, softfail, neutral, none, etc.")
    details: Optional[str] = Field(None, description="Additional details")
    domain: Optional[str] = Field(None, description="Domain checked")
    selector: Optional[str] = Field(None, description="DKIM selector if applicable")


class ExtractedURL(BaseModel):
    """URL extracted from email."""
    url: str = Field(..., description="Original URL")
    normalized_url: str = Field(..., description="Normalized URL for comparison")
    domain: str = Field(..., description="Domain from URL")
    scheme: str = Field(..., description="URL scheme (http, https)")
    path: Optional[str] = Field(None, description="URL path")
    query_params: Optional[Dict[str, Any]] = Field(None, description="Query parameters")
    source: str = Field(..., description="Where URL was found: body_text, body_html, attachment, qr_code")
    is_shortened: bool = Field(False, description="Is from URL shortener")
    final_url: Optional[str] = Field(None, description="Final URL after redirect resolution")


class AttachmentInfo(BaseModel):
    """Email attachment metadata."""
    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(..., description="File size in bytes")
    md5: str = Field(..., description="MD5 hash")
    sha256: str = Field(..., description="SHA256 hash")
    sha1: Optional[str] = Field(None, description="SHA1 hash")
    is_executable: bool = Field(False, description="Has executable extension")
    is_archive: bool = Field(False, description="Is archive file")
    is_office_with_macros: bool = Field(False, description="Office file with macro extension")
    is_script: bool = Field(False, description="Is script file")
    extension: str = Field(..., description="File extension")
    magic_type: Optional[str] = Field(None, description="Detected file type by magic bytes")
    
    # Static analysis fields
    has_macros: bool = Field(False, description="Contains VBA macros")
    has_auto_exec_macros: bool = Field(False, description="Has auto-execute macro triggers")
    has_dde: bool = Field(False, description="Contains DDE links")
    has_ole_objects: bool = Field(False, description="Contains embedded OLE objects")
    has_javascript: bool = Field(False, description="Contains JavaScript (PDF)")
    has_embedded_files: bool = Field(False, description="Contains embedded files")
    is_packed: bool = Field(False, description="Executable appears packed")
    has_suspicious_imports: bool = Field(False, description="Has suspicious API imports")
    type_mismatch: bool = Field(False, description="Extension doesn't match content")
    has_double_extension: bool = Field(False, description="Has double extension trick")
    entropy: Optional[float] = Field(None, description="File entropy (0-8)")
    threat_score: int = Field(0, ge=0, le=100, description="Static analysis threat score")
    threat_level: str = Field("unknown", description="clean/low/medium/high/critical")
    threat_summary: Optional[str] = Field(None, description="Human-readable threat summary")
    
    # Extracted IOCs from static analysis
    extracted_urls: List[str] = Field(default_factory=list, description="URLs found in file")
    extracted_ips: List[str] = Field(default_factory=list, description="IPs found in file")
    suspicious_strings: List[str] = Field(default_factory=list, description="Suspicious strings found")


class QRCodeInfo(BaseModel):
    """Extracted QR code data."""
    source_attachment: str = Field(..., description="Filename containing QR code")
    decoded_data: str = Field(..., description="Decoded QR code content")
    data_type: str = Field(..., description="Type of data: url, text, vcard, etc.")
    extracted_url: Optional[str] = Field(None, description="URL if QR contains URL")


class HeaderAnalysis(BaseModel):
    """Analyzed email headers."""
    received_chain: List[ReceivedHop] = Field(default_factory=list)
    originating_ip: Optional[str] = Field(None, description="Originating IP address")
    auth_results: List[AuthenticationResult] = Field(default_factory=list)
    spf_result: Optional[AuthenticationResult] = Field(None)
    dkim_result: Optional[AuthenticationResult] = Field(None)
    dmarc_result: Optional[AuthenticationResult] = Field(None)
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies")


class ParsedEmail(BaseModel):
    """Complete parsed email structure."""
    # Metadata
    message_id: Optional[str] = Field(None, description="Message-ID header")
    date: Optional[datetime] = Field(None, description="Email date")
    subject: Optional[str] = Field(None, description="Email subject")
    
    # Addresses
    sender: Optional[EmailAddress] = Field(None, description="From header")
    envelope_from: Optional[EmailAddress] = Field(None, description="Return-Path/Envelope-From")
    reply_to: List[EmailAddress] = Field(default_factory=list, description="Reply-To addresses")
    to_recipients: List[EmailAddress] = Field(default_factory=list)
    cc_recipients: List[EmailAddress] = Field(default_factory=list)
    bcc_recipients: List[EmailAddress] = Field(default_factory=list)
    
    # Header analysis (routing, auth)
    header_analysis: Optional[HeaderAnalysis] = Field(None, description="Analyzed headers")
    
    # Legacy fields for backwards compatibility
    received_chain: List[ReceivedHop] = Field(default_factory=list)
    originating_ip: Optional[str] = Field(None, description="Originating IP address")
    auth_results: List[AuthenticationResult] = Field(default_factory=list)
    spf_result: Optional[AuthenticationResult] = Field(None)
    dkim_result: Optional[AuthenticationResult] = Field(None)
    dmarc_result: Optional[AuthenticationResult] = Field(None)
    
    # Content
    body_text: Optional[str] = Field(None, description="Plain text body")
    body_html: Optional[str] = Field(None, description="HTML body")
    
    # Extracted indicators
    urls: List[ExtractedURL] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    qr_codes: List[QRCodeInfo] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)
    
    # Raw data
    raw_headers: Dict[str, Any] = Field(default_factory=dict)
    raw_email: Optional[str] = Field(None, description="Complete raw email")
