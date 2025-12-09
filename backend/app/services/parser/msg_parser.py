"""
NiksES MSG Parser

Parse Outlook .msg files using extract-msg library.
"""

import logging
import tempfile
import os
from pathlib import Path

from app.models.email import (
    ParsedEmail, EmailAddress, AttachmentInfo, ExtractedURL,
    AuthenticationResult, HeaderAnalysis
)
from app.utils.exceptions import ParsingError

logger = logging.getLogger(__name__)

# Try to import extract-msg
try:
    import extract_msg
    EXTRACT_MSG_AVAILABLE = True
except ImportError:
    EXTRACT_MSG_AVAILABLE = False
    logger.warning("extract-msg not installed. MSG parsing will not be available.")


async def parse_msg_file(file_path: Path) -> ParsedEmail:
    """Parse .msg file from disk."""
    if not EXTRACT_MSG_AVAILABLE:
        raise ParsingError("MSG parsing not available. Install extract-msg package.")
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return await parse_msg_bytes(content)
    except Exception as e:
        logger.error(f"Failed to parse MSG file: {e}")
        raise ParsingError(f"Failed to parse MSG file: {e}")


async def parse_msg_bytes(content: bytes) -> ParsedEmail:
    """Parse .msg content from bytes."""
    if not EXTRACT_MSG_AVAILABLE:
        raise ParsingError("MSG parsing not available. Install extract-msg package.")
    
    temp_file = None
    try:
        # Write to temp file (extract-msg needs a file)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msg') as f:
            f.write(content)
            temp_file = f.name
        
        # Parse MSG file
        msg = extract_msg.Message(temp_file)
        
        # Import helpers from eml_parser
        from .eml_parser import (
            _extract_urls,
            _extract_phone_numbers,
            _detect_magic_type,
        )
        import hashlib
        
        # Extract sender
        sender = None
        if msg.sender:
            sender = _parse_msg_address(msg.sender)
        
        # Extract recipients
        to_recipients = []
        if msg.to:
            for addr in str(msg.to).split(';'):
                parsed = _parse_msg_address(addr.strip())
                if parsed:
                    to_recipients.append(parsed)
        
        cc_recipients = []
        if msg.cc:
            for addr in str(msg.cc).split(';'):
                parsed = _parse_msg_address(addr.strip())
                if parsed:
                    cc_recipients.append(parsed)
        
        # Extract body
        body_text = msg.body or ''
        body_html = ''
        try:
            body_html = msg.htmlBody or ''
            if isinstance(body_html, bytes):
                body_html = body_html.decode('utf-8', errors='replace')
        except:
            pass
        
        # Extract URLs
        urls = _extract_urls(body_text, body_html)
        
        # Extract attachments
        attachments = _extract_msg_attachments(msg)
        
        # Extract date
        email_date = None
        try:
            if msg.date:
                email_date = msg.date
        except:
            pass
        
        # Extract phone numbers
        phone_numbers = _extract_phone_numbers(body_text)
        
        # Build raw headers
        raw_headers = {}
        try:
            if hasattr(msg, 'header') and msg.header:
                raw_headers = dict(msg.header)
        except:
            pass
        
        # MSG files don't have auth results
        header_analysis = HeaderAnalysis(
            received_chain=[],
            originating_ip=None,
            auth_results=[],
            spf_result=None,
            dkim_result=None,
            dmarc_result=None,
            anomalies=['Authentication results not available in MSG format'],
        )
        
        return ParsedEmail(
            message_id=msg.messageId or '',
            subject=msg.subject or '',
            sender=sender,
            envelope_from=None,
            to_recipients=to_recipients,
            cc_recipients=cc_recipients,
            bcc_recipients=[],
            reply_to=[],
            date=email_date,
            body_text=body_text,
            body_html=body_html,
            raw_headers=raw_headers,
            urls=urls,
            attachments=attachments,
            qr_codes=[],
            header_analysis=header_analysis,
            received_chain=[],
            originating_ip=None,
            auth_results=[],
            spf_result=None,
            dkim_result=None,
            dmarc_result=None,
            phone_numbers=phone_numbers,
            raw_email=None,
        )
        
    except Exception as e:
        logger.error(f"Failed to parse MSG content: {e}")
        raise ParsingError(f"Failed to parse MSG content: {e}")
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except:
                pass


def _parse_msg_address(addr_str: str) -> EmailAddress:
    """Parse email address from MSG format."""
    import re
    
    if not addr_str:
        return None
    
    # Try to extract email
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', addr_str)
    if email_match:
        email_addr = email_match.group()
        
        # Split into local_part and domain
        if '@' in email_addr:
            local_part, domain = email_addr.split('@', 1)
        else:
            local_part = email_addr
            domain = ''
        
        # Extract display name (everything before the email)
        display_name = addr_str.replace(email_addr, '').strip(' <>"\'')
        
        return EmailAddress(
            raw=addr_str,
            display_name=display_name,
            email=email_addr,
            domain=domain,
            local_part=local_part,
        )
    
    return None


def _extract_msg_attachments(msg, perform_static_analysis: bool = True) -> list:
    """
    Extract attachments from MSG file with optional static analysis.
    
    Args:
        msg: MSG message object
        perform_static_analysis: Whether to run full static analysis on attachments
        
    Returns:
        List of AttachmentInfo objects with analysis results
    """
    import hashlib
    from pathlib import Path
    
    attachments = []
    
    executable_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.com'}
    archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz'}
    macro_exts = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm'}
    script_exts = {'.ps1', '.vbs', '.js', '.wsf', '.hta'}
    
    # Lazy import static analyzer to avoid circular imports
    static_analyzer = None
    if perform_static_analysis:
        try:
            from app.services.static_analysis import StaticAnalyzer
            static_analyzer = StaticAnalyzer()
        except ImportError as e:
            logger.warning(f"Static analysis module not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to initialize static analyzer: {e}")
    
    try:
        for att in msg.attachments:
            try:
                att_content = att.data
                if att_content:
                    filename = att.longFilename or att.shortFilename or 'unnamed'
                    content_type = getattr(att, 'mimetype', None) or 'application/octet-stream'
                    
                    md5_hash = hashlib.md5(att_content).hexdigest()
                    sha256_hash = hashlib.sha256(att_content).hexdigest()
                    sha1_hash = hashlib.sha1(att_content).hexdigest()
                    
                    ext = Path(filename).suffix.lower()
                    
                    # Create base attachment info
                    attachment_info = AttachmentInfo(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(att_content),
                        md5=md5_hash,
                        sha256=sha256_hash,
                        sha1=sha1_hash,
                        is_executable=ext in executable_exts,
                        is_archive=ext in archive_exts,
                        is_office_with_macros=ext in macro_exts,
                        is_script=ext in script_exts,
                        extension=ext,
                        magic_type=None,
                    )
                    
                    # Run static analysis if available
                    if static_analyzer and len(att_content) > 0:
                        try:
                            static_result = static_analyzer.analyze(
                                content=att_content,
                                filename=filename,
                                claimed_content_type=content_type
                            )
                            
                            # Update attachment info with static analysis results
                            attachment_info.type_mismatch = static_result.type_mismatch
                            attachment_info.has_double_extension = static_result.has_double_extension
                            attachment_info.entropy = static_result.entropy.overall_entropy
                            attachment_info.threat_score = static_result.threat_score
                            attachment_info.threat_level = static_result.threat_level.value
                            attachment_info.threat_summary = static_result.threat_summary
                            attachment_info.extracted_urls = static_result.urls_found[:20]
                            attachment_info.extracted_ips = static_result.ips_found[:20]
                            attachment_info.suspicious_strings = [
                                s.value for s in static_result.interesting_strings[:10] 
                                if s.string_type.startswith('suspicious')
                            ]
                            
                            # Use more accurate magic type from static analysis
                            attachment_info.magic_type = static_result.detected_type
                            
                            # Office-specific analysis
                            if static_result.office_analysis:
                                attachment_info.has_macros = static_result.office_analysis.has_macros
                                attachment_info.has_auto_exec_macros = any(
                                    m.has_auto_exec for m in static_result.office_analysis.macros
                                )
                                attachment_info.has_dde = static_result.office_analysis.has_dde
                                attachment_info.has_ole_objects = static_result.office_analysis.has_ole_objects
                            
                            # PDF-specific analysis
                            if static_result.pdf_analysis:
                                attachment_info.has_javascript = static_result.pdf_analysis.has_javascript
                                attachment_info.has_embedded_files = static_result.pdf_analysis.has_embedded_files
                            
                            # PE-specific analysis
                            if static_result.pe_analysis:
                                attachment_info.is_packed = static_result.pe_analysis.is_packed
                                attachment_info.has_suspicious_imports = len(
                                    static_result.pe_analysis.suspicious_imports
                                ) > 0
                            
                            # Archive-specific analysis
                            if static_result.archive_analysis:
                                if static_result.archive_analysis.has_executables:
                                    attachment_info.has_embedded_files = True
                            
                            logger.info(f"Static analysis complete for '{filename}': threat_level={attachment_info.threat_level}, score={attachment_info.threat_score}")
                            
                        except Exception as e:
                            logger.warning(f"Static analysis failed for '{filename}': {e}")
                            attachment_info.threat_summary = f"Static analysis error: {str(e)}"
                    
                    attachments.append(attachment_info)
                    
            except Exception as e:
                logger.warning(f"Failed to process MSG attachment: {e}")
    except Exception as e:
        logger.warning(f"Failed to iterate MSG attachments: {e}")
    
    return attachments
