"""
NiksES EML Parser

Parse .eml files using Python's email library.
"""

import logging
import email
import email.utils
import email.policy
import re
import hashlib
from typing import Optional, List
from datetime import datetime
from pathlib import Path
from email import message_from_bytes
from email.message import EmailMessage
from urllib.parse import urlparse, parse_qs

from app.models.email import (
    ParsedEmail, EmailAddress, AttachmentInfo, ExtractedURL, 
    AuthenticationResult, HeaderAnalysis, ReceivedHop
)
from app.utils.exceptions import ParsingError

logger = logging.getLogger(__name__)

# URL regex pattern
URL_PATTERN = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\']*',
    re.IGNORECASE
)

# IP address pattern
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

# Phone number pattern
PHONE_PATTERN = re.compile(
    r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
)

# Shortener domains
SHORTENER_DOMAINS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'short.io'}


async def parse_eml_file(file_path: Path) -> ParsedEmail:
    """Parse .eml file from disk."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return await parse_eml_bytes(content)
    except Exception as e:
        logger.error(f"Failed to parse EML file: {e}")
        raise ParsingError(f"Failed to parse EML file: {e}")


async def parse_eml_bytes(content: bytes) -> ParsedEmail:
    """Parse .eml content from bytes."""
    try:
        # Parse email with policy for better handling
        msg = message_from_bytes(content, policy=email.policy.default)
        
        # Extract raw headers
        raw_headers = {}
        for key in msg.keys():
            value = msg.get(key)
            if value:
                raw_headers[key.lower()] = str(value)
        
        # Extract message ID
        message_id = msg.get('Message-ID', '') or msg.get('Message-Id', '') or ''
        
        # Extract subject
        subject = msg.get('Subject', '') or ''
        
        # Extract sender
        from_header = msg.get('From', '') or ''
        sender = _extract_email_address(from_header)
        
        # Extract envelope-from (Return-Path)
        return_path = msg.get('Return-Path', '') or ''
        envelope_from = _extract_email_address(return_path) if return_path else None
        
        # Extract recipients
        to_header = msg.get('To', '') or ''
        cc_header = msg.get('Cc', '') or ''
        bcc_header = msg.get('Bcc', '') or ''
        
        to_recipients = _extract_multiple_addresses(to_header)
        cc_recipients = _extract_multiple_addresses(cc_header)
        bcc_recipients = _extract_multiple_addresses(bcc_header)
        
        # Extract reply-to
        reply_to_header = msg.get('Reply-To', '')
        reply_to = _extract_multiple_addresses(reply_to_header) if reply_to_header else []
        
        # Extract date
        date_header = msg.get('Date', '')
        email_date = _parse_date(date_header)
        
        # Extract body
        body_text, body_html = _extract_body(msg)
        
        # Extract URLs from body
        urls = _extract_urls(body_text, body_html)
        
        # Extract attachments
        attachments = _extract_attachments(msg)
        
        # Parse authentication results
        spf_result, dkim_result, dmarc_result, auth_results = _parse_authentication_results(msg)
        
        # Extract phone numbers
        phone_numbers = _extract_phone_numbers(body_text)
        
        # Parse received chain and get originating IP
        received_chain, originating_ip = _parse_received_chain(msg)
        
        # Build header analysis
        header_analysis = HeaderAnalysis(
            received_chain=received_chain,
            originating_ip=originating_ip,
            auth_results=auth_results,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            anomalies=[],
        )
        
        return ParsedEmail(
            message_id=message_id,
            subject=subject,
            sender=sender,
            envelope_from=envelope_from,
            to_recipients=to_recipients,
            cc_recipients=cc_recipients,
            bcc_recipients=bcc_recipients,
            reply_to=reply_to,
            date=email_date,
            body_text=body_text,
            body_html=body_html,
            raw_headers=raw_headers,
            urls=urls,
            attachments=attachments,
            qr_codes=[],
            header_analysis=header_analysis,
            received_chain=received_chain,
            originating_ip=originating_ip,
            auth_results=auth_results,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            phone_numbers=phone_numbers,
            raw_email=content.decode('utf-8', errors='replace')[:50000],  # Limit size
        )
        
    except Exception as e:
        logger.error(f"Failed to parse EML content: {e}")
        raise ParsingError(f"Failed to parse EML content: {e}")


def _extract_email_address(address_str: str) -> Optional[EmailAddress]:
    """Extract EmailAddress from raw address string."""
    if not address_str:
        return None
    
    try:
        name, addr = email.utils.parseaddr(address_str)
        
        if not addr:
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', address_str)
            if match:
                addr = match.group()
            else:
                return None
        
        # Split email into local_part and domain
        if '@' in addr:
            local_part, domain = addr.split('@', 1)
        else:
            local_part = addr
            domain = ''
        
        return EmailAddress(
            raw=address_str,
            display_name=name or '',
            email=addr,
            domain=domain,
            local_part=local_part,
        )
    except Exception as e:
        logger.warning(f"Failed to parse email address '{address_str}': {e}")
        return None


def _extract_multiple_addresses(header: str) -> List[EmailAddress]:
    """Extract multiple email addresses from a header."""
    if not header:
        return []
    
    addresses = []
    parts = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', header)
    
    for part in parts:
        addr = _extract_email_address(part.strip())
        if addr:
            addresses.append(addr)
    
    return addresses


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parse email date string to datetime."""
    if not date_str:
        return None
    
    try:
        parsed = email.utils.parsedate_to_datetime(date_str)
        return parsed
    except Exception:
        formats = [
            '%a, %d %b %Y %H:%M:%S %z',
            '%d %b %Y %H:%M:%S %z',
            '%a, %d %b %Y %H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except:
                continue
    return None


def _extract_body(msg: EmailMessage) -> tuple:
    """Extract text and HTML body from email."""
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))
            
            if 'attachment' in content_disposition:
                continue
            
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        decoded = payload.decode(charset, errors='replace')
                    except:
                        decoded = payload.decode('utf-8', errors='replace')
                    
                    if content_type == 'text/plain' and not body_text:
                        body_text = decoded
                    elif content_type == 'text/html' and not body_html:
                        body_html = decoded
            except Exception as e:
                logger.warning(f"Failed to decode part: {e}")
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    decoded = payload.decode(charset, errors='replace')
                except:
                    decoded = payload.decode('utf-8', errors='replace')
                
                if content_type == 'text/html':
                    body_html = decoded
                else:
                    body_text = decoded
        except:
            body_text = str(msg.get_payload())
    
    return body_text, body_html


def _extract_urls(body_text: str, body_html: str) -> List[ExtractedURL]:
    """Extract URLs from email body."""
    urls_found = set()
    
    if body_text:
        urls_found.update(URL_PATTERN.findall(body_text))
    
    if body_html:
        urls_found.update(URL_PATTERN.findall(body_html))
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.findall(body_html):
            if match.startswith(('http://', 'https://')):
                urls_found.add(match)
    
    extracted = []
    for url in urls_found:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            is_shortened = any(short in domain for short in SHORTENER_DOMAINS)
            
            query_params = parse_qs(parsed.query) if parsed.query else None
            
            extracted.append(ExtractedURL(
                url=url,
                normalized_url=f"{parsed.scheme}://{domain}{parsed.path}".rstrip('/').lower(),
                domain=domain,
                scheme=parsed.scheme,
                path=parsed.path or None,
                query_params=query_params,
                source='body_html' if body_html and url in body_html else 'body_text',
                is_shortened=is_shortened,
                final_url=None,
            ))
        except Exception as e:
            logger.warning(f"Failed to parse URL '{url}': {e}")
    
    return extracted


def _extract_attachments(msg: EmailMessage, perform_static_analysis: bool = True) -> List[AttachmentInfo]:
    """
    Extract attachments from email with optional static analysis.
    
    Args:
        msg: Email message object
        perform_static_analysis: Whether to run full static analysis on attachments
        
    Returns:
        List of AttachmentInfo objects with analysis results
    """
    attachments = []
    
    if not msg.is_multipart():
        return attachments
    
    executable_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.com', '.pif', '.msi'}
    archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
    macro_exts = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm'}
    script_exts = {'.ps1', '.vbs', '.js', '.wsf', '.hta', '.py', '.sh', '.pl'}
    
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
    
    for part in msg.walk():
        content_disposition = str(part.get('Content-Disposition', ''))
        
        if 'attachment' in content_disposition or part.get_filename():
            filename = part.get_filename() or 'unnamed'
            content_type = part.get_content_type() or 'application/octet-stream'
            
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    md5_hash = hashlib.md5(payload).hexdigest()
                    sha256_hash = hashlib.sha256(payload).hexdigest()
                    sha1_hash = hashlib.sha1(payload).hexdigest()
                    size = len(payload)
                    
                    ext = Path(filename).suffix.lower()
                    
                    # Detect magic bytes for common types (basic detection)
                    magic_type = _detect_magic_type(payload[:16])
                    
                    # Create base attachment info
                    attachment_info = AttachmentInfo(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=size,
                        md5=md5_hash,
                        sha256=sha256_hash,
                        sha1=sha1_hash,
                        is_executable=ext in executable_exts,
                        is_archive=ext in archive_exts,
                        is_office_with_macros=ext in macro_exts,
                        is_script=ext in script_exts,
                        extension=ext,
                        magic_type=magic_type,
                    )
                    
                    # Run static analysis if available
                    if static_analyzer and len(payload) > 0:
                        try:
                            static_result = static_analyzer.analyze(
                                content=payload,
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
                logger.warning(f"Failed to process attachment '{filename}': {e}")
    
    return attachments


def _detect_magic_type(header: bytes) -> Optional[str]:
    """Detect file type from magic bytes."""
    if not header or len(header) < 4:
        return None
    
    # Common magic bytes
    if header[:4] == b'%PDF':
        return 'application/pdf'
    elif header[:4] == b'PK\x03\x04':
        return 'application/zip'
    elif header[:2] == b'MZ':
        return 'application/x-executable'
    elif header[:4] == b'\x89PNG':
        return 'image/png'
    elif header[:2] == b'\xff\xd8':
        return 'image/jpeg'
    elif header[:4] == b'GIF8':
        return 'image/gif'
    elif header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return 'application/x-ole-storage'  # Office documents
    
    return None


def _parse_authentication_results(msg: EmailMessage) -> tuple:
    """Parse SPF, DKIM, DMARC results from headers."""
    auth_results_header = msg.get('Authentication-Results', '') or ''
    received_spf = msg.get('Received-SPF', '') or ''
    dkim_signature = msg.get('DKIM-Signature', '') or ''
    
    auth_results = []
    
    # Parse SPF
    spf_result = None
    if received_spf:
        spf_lower = received_spf.lower()
        result = 'none'
        if 'pass' in spf_lower:
            result = 'pass'
        elif 'fail' in spf_lower:
            result = 'fail'
        elif 'softfail' in spf_lower:
            result = 'softfail'
        elif 'neutral' in spf_lower:
            result = 'neutral'
        
        spf_result = AuthenticationResult(
            mechanism='SPF',
            result=result,
            details=received_spf[:200],
        )
        auth_results.append(spf_result)
    elif 'spf=' in auth_results_header.lower():
        match = re.search(r'spf=(\w+)', auth_results_header, re.IGNORECASE)
        if match:
            spf_result = AuthenticationResult(
                mechanism='SPF',
                result=match.group(1).lower(),
                details='From Authentication-Results header',
            )
            auth_results.append(spf_result)
    
    # Parse DKIM
    dkim_result = None
    if 'dkim=' in auth_results_header.lower():
        match = re.search(r'dkim=(\w+)', auth_results_header, re.IGNORECASE)
        if match:
            dkim_result = AuthenticationResult(
                mechanism='DKIM',
                result=match.group(1).lower(),
                details='From Authentication-Results header',
            )
            auth_results.append(dkim_result)
    elif dkim_signature:
        dkim_result = AuthenticationResult(
            mechanism='DKIM',
            result='present',
            details='DKIM signature present',
        )
        auth_results.append(dkim_result)
    
    # Parse DMARC
    dmarc_result = None
    if 'dmarc=' in auth_results_header.lower():
        match = re.search(r'dmarc=(\w+)', auth_results_header, re.IGNORECASE)
        if match:
            dmarc_result = AuthenticationResult(
                mechanism='DMARC',
                result=match.group(1).lower(),
                details='From Authentication-Results header',
            )
            auth_results.append(dmarc_result)
    
    return spf_result, dkim_result, dmarc_result, auth_results


def _parse_received_chain(msg: EmailMessage) -> tuple:
    """Parse Received headers to build chain and extract originating IP."""
    received_chain = []
    originating_ip = None
    
    # Get all Received headers (they're in reverse order)
    received_headers = msg.get_all('Received', [])
    
    for i, header in enumerate(reversed(received_headers)):
        try:
            # Extract IP
            ip_match = IP_PATTERN.search(header)
            ip = ip_match.group() if ip_match else None
            
            # Extract from/by
            from_match = re.search(r'from\s+([\w.-]+)', header, re.IGNORECASE)
            by_match = re.search(r'by\s+([\w.-]+)', header, re.IGNORECASE)
            
            hop = ReceivedHop(
                hop_number=i + 1,
                from_host=from_match.group(1) if from_match else None,
                from_ip=ip,
                by_host=by_match.group(1) if by_match else None,
                timestamp=None,  # Could parse timestamp if needed
                raw_header=header[:500],
            )
            received_chain.append(hop)
            
            # First non-private IP is likely originating
            if ip and not originating_ip:
                if not ip.startswith(('10.', '192.168.', '172.16.', '127.', '::1')):
                    originating_ip = ip
                    
        except Exception as e:
            logger.warning(f"Failed to parse Received header: {e}")
    
    # Also check X-Originating-IP
    x_orig = msg.get('X-Originating-IP', '')
    if x_orig and not originating_ip:
        ip_match = IP_PATTERN.search(x_orig)
        if ip_match:
            originating_ip = ip_match.group()
    
    return received_chain, originating_ip


def _extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text."""
    if not text:
        return []
    
    matches = PHONE_PATTERN.findall(text)
    return list(set(matches))
