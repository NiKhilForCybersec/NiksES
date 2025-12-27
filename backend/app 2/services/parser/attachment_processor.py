"""
NiksES Attachment Processor

Process email attachments - extract metadata, calculate hashes, detect file types,
and perform comprehensive static analysis.
"""

import logging
import hashlib
from typing import List, Tuple, Optional
from pathlib import Path

from app.models.email import AttachmentInfo
from app.utils.constants import DANGEROUS_EXTENSIONS
from app.utils.exceptions import AttachmentProcessingError
from app.services.static_analysis import StaticAnalyzer

logger = logging.getLogger(__name__)

# Initialize static analyzer (singleton-ish pattern)
_static_analyzer: Optional[StaticAnalyzer] = None


def get_static_analyzer() -> StaticAnalyzer:
    """Get or create static analyzer instance."""
    global _static_analyzer
    if _static_analyzer is None:
        _static_analyzer = StaticAnalyzer()
    return _static_analyzer


# File extension categories
EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.msc', '.cpl',
    '.msi', '.msp', '.gadget', '.application', '.appref-ms'
}

SCRIPT_EXTENSIONS = {
    '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.py', '.pl', '.sh', '.bash',
    '.rb', '.php', '.asp', '.aspx', '.jsp'
}

ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab',
    '.iso', '.img', '.arj', '.lzh', '.ace'
}

OFFICE_EXTENSIONS = {
    '.doc', '.docx', '.docm', '.dot', '.dotx', '.dotm',
    '.xls', '.xlsx', '.xlsm', '.xlt', '.xltx', '.xltm', '.xlsb',
    '.ppt', '.pptx', '.pptm', '.pot', '.potx', '.potm',
    '.rtf', '.odt', '.ods', '.odp'
}

MACRO_EXTENSIONS = {'.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'}


def process_attachments(
    attachments: List[dict],
    perform_static_analysis: bool = True
) -> List[AttachmentInfo]:
    """
    Process all email attachments.
    
    Args:
        attachments: List of attachment dictionaries from parser
        perform_static_analysis: Whether to run static analysis
        
    Returns:
        List of AttachmentInfo objects
    """
    results = []
    
    for attachment in attachments:
        try:
            filename = attachment.get('filename', 'unknown')
            content = attachment.get('content', b'')
            content_type = attachment.get('content_type', 'application/octet-stream')
            
            # Ensure content is bytes
            if isinstance(content, str):
                content = content.encode('utf-8')
            
            # Process single attachment
            info = process_single_attachment(
                filename=filename,
                content=content,
                content_type=content_type,
                perform_static_analysis=perform_static_analysis
            )
            results.append(info)
            
        except Exception as e:
            logger.warning(f"Failed to process attachment: {e}")
            # Create minimal info on failure
            results.append(AttachmentInfo(
                filename=attachment.get('filename', 'unknown'),
                content_type=attachment.get('content_type', 'application/octet-stream'),
                size_bytes=len(attachment.get('content', b'')),
                md5='error',
                sha256='error',
                extension=get_extension(attachment.get('filename', '')),
                threat_summary=f"Analysis failed: {str(e)}"
            ))
    
    return results


def process_single_attachment(
    filename: str,
    content: bytes,
    content_type: str,
    perform_static_analysis: bool = True
) -> AttachmentInfo:
    """
    Process a single attachment with full static analysis.
    
    Args:
        filename: Original filename
        content: File content as bytes
        content_type: MIME type from Content-Type header
        perform_static_analysis: Whether to run full static analysis
        
    Returns:
        AttachmentInfo with analysis results
    """
    # Calculate hashes
    md5_hash, sha256_hash = hash_attachment(content)
    sha1_hash = hashlib.sha1(content).hexdigest()
    
    # Get extension
    extension = get_extension(filename)
    ext_lower = extension.lower()
    
    # Basic classification
    is_exec = is_executable(filename, content)
    is_arch = is_archive(filename)
    is_office_macro = is_office_with_macros(filename)
    is_scr = is_script(filename)
    has_double_ext = has_double_extension(filename)
    
    # Detect file type by magic
    analyzer = get_static_analyzer()
    magic_type = analyzer.magic_detector.detect(content)
    
    # Create base info
    info = AttachmentInfo(
        filename=filename,
        content_type=content_type,
        size_bytes=len(content),
        md5=md5_hash,
        sha256=sha256_hash,
        sha1=sha1_hash,
        is_executable=is_exec,
        is_archive=is_arch,
        is_office_with_macros=is_office_macro,
        is_script=is_scr,
        extension=extension,
        magic_type=magic_type,
        has_double_extension=has_double_ext
    )
    
    # Perform static analysis if enabled
    if perform_static_analysis and len(content) > 0:
        try:
            static_result = analyzer.analyze(content, filename, content_type)
            
            # Update info with static analysis results
            info.type_mismatch = static_result.type_mismatch
            info.entropy = static_result.entropy.overall_entropy
            info.threat_score = static_result.threat_score
            info.threat_level = static_result.threat_level.value
            info.threat_summary = static_result.threat_summary
            info.extracted_urls = static_result.urls_found[:20]
            info.extracted_ips = static_result.ips_found[:20]
            info.suspicious_strings = [s.value for s in static_result.interesting_strings[:10] if s.string_type.startswith('suspicious')]
            
            # Office-specific
            if static_result.office_analysis:
                info.has_macros = static_result.office_analysis.has_macros
                info.has_auto_exec_macros = any(m.has_auto_exec for m in static_result.office_analysis.macros)
                info.has_dde = static_result.office_analysis.has_dde
                info.has_ole_objects = static_result.office_analysis.has_ole_objects
            
            # PDF-specific
            if static_result.pdf_analysis:
                info.has_javascript = static_result.pdf_analysis.has_javascript
                info.has_embedded_files = static_result.pdf_analysis.has_embedded_files
            
            # PE-specific
            if static_result.pe_analysis:
                info.is_packed = static_result.pe_analysis.is_packed
                info.has_suspicious_imports = len(static_result.pe_analysis.suspicious_imports) > 0
            
            # Archive-specific
            if static_result.archive_analysis:
                info.has_embedded_files = static_result.archive_analysis.has_executables
                
        except Exception as e:
            logger.warning(f"Static analysis failed for {filename}: {e}")
            info.threat_summary = f"Static analysis error: {str(e)}"
    
    return info


def hash_attachment(content: bytes) -> Tuple[str, str]:
    """
    Calculate MD5 and SHA256 hashes of attachment.
    
    Args:
        content: Attachment content as bytes
        
    Returns:
        Tuple of (md5_hash, sha256_hash)
    """
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    return md5_hash, sha256_hash


def detect_file_type(content: bytes, filename: str) -> str:
    """
    Detect file type using magic bytes.
    
    Args:
        content: File content
        filename: Original filename
        
    Returns:
        Detected MIME type
    """
    analyzer = get_static_analyzer()
    return analyzer.magic_detector.detect(content)


def is_executable(filename: str, content: bytes = None) -> bool:
    """Check if file is executable based on extension and/or content."""
    ext = get_extension(filename).lower()
    
    if ext in EXECUTABLE_EXTENSIONS:
        return True
    
    # Check content for executable signatures
    if content:
        if content[:2] == b'MZ':  # DOS/Windows
            return True
        if content[:4] == b'\x7fELF':  # Linux
            return True
        if content[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe']:  # macOS
            return True
    
    return False


def is_archive(filename: str) -> bool:
    """Check if file is an archive."""
    ext = get_extension(filename).lower()
    return ext in ARCHIVE_EXTENSIONS


def is_office_with_macros(filename: str) -> bool:
    """Check if file is a macro-enabled Office document."""
    ext = get_extension(filename).lower()
    return ext in MACRO_EXTENSIONS


def is_script(filename: str) -> bool:
    """Check if file is a script."""
    ext = get_extension(filename).lower()
    return ext in SCRIPT_EXTENSIONS


def has_double_extension(filename: str) -> bool:
    """Check for double extension (e.g., invoice.pdf.exe)."""
    parts = filename.lower().split('.')
    if len(parts) < 3:
        return False
    
    # Check if second-to-last looks like a document extension
    # and last is executable
    doc_exts = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'png', 'gif'}
    exec_exts = {'exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'com', 'pif'}
    
    return parts[-2] in doc_exts and parts[-1] in exec_exts


def get_extension(filename: str) -> str:
    """Get file extension from filename."""
    if '.' not in filename:
        return ''
    return '.' + filename.rsplit('.', 1)[-1]
