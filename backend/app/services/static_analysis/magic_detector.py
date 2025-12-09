"""
NiksES Magic Bytes Detector

Detect file types by examining magic bytes/file signatures.
"""

from typing import Optional


class MagicDetector:
    """
    Detect file types using magic bytes (file signatures).
    
    This is more reliable than trusting file extensions,
    which can be spoofed by attackers.
    """
    
    # Magic signatures: (offset, signature_bytes, mime_type, description)
    SIGNATURES = [
        # Executables
        (0, b'MZ', 'application/x-dosexec', 'DOS/Windows Executable'),
        (0, b'\x7fELF', 'application/x-executable', 'ELF Executable'),
        (0, b'\xfe\xed\xfa\xce', 'application/x-mach-binary', 'Mach-O 32-bit'),
        (0, b'\xfe\xed\xfa\xcf', 'application/x-mach-binary', 'Mach-O 64-bit'),
        (0, b'\xca\xfe\xba\xbe', 'application/x-mach-binary', 'Mach-O Universal'),
        
        # Archives
        (0, b'PK\x03\x04', 'application/zip', 'ZIP Archive'),
        (0, b'PK\x05\x06', 'application/zip', 'ZIP Archive (empty)'),
        (0, b'PK\x07\x08', 'application/zip', 'ZIP Archive (spanned)'),
        (0, b'Rar!\x1a\x07\x00', 'application/x-rar-compressed', 'RAR Archive v4'),
        (0, b'Rar!\x1a\x07\x01\x00', 'application/x-rar-compressed', 'RAR Archive v5'),
        (0, b'7z\xbc\xaf\x27\x1c', 'application/x-7z-compressed', '7-Zip Archive'),
        (0, b'\x1f\x8b\x08', 'application/gzip', 'GZIP Archive'),
        (0, b'BZh', 'application/x-bzip2', 'BZIP2 Archive'),
        (0, b'\xfd7zXZ\x00', 'application/x-xz', 'XZ Archive'),
        (257, b'ustar', 'application/x-tar', 'TAR Archive'),
        (0, b'MSCF', 'application/vnd.ms-cab-compressed', 'CAB Archive'),
        
        # Documents - PDF
        (0, b'%PDF', 'application/pdf', 'PDF Document'),
        
        # Documents - Office (OLE - old format)
        (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'application/x-ole-storage', 'OLE Compound Document'),
        
        # Documents - Office (OOXML - new format, actually ZIP)
        # These are detected as ZIP first, then need content inspection
        
        # Documents - RTF
        (0, b'{\\rtf', 'application/rtf', 'RTF Document'),
        
        # Images
        (0, b'\xff\xd8\xff', 'image/jpeg', 'JPEG Image'),
        (0, b'\x89PNG\r\n\x1a\n', 'image/png', 'PNG Image'),
        (0, b'GIF87a', 'image/gif', 'GIF Image'),
        (0, b'GIF89a', 'image/gif', 'GIF Image'),
        (0, b'BM', 'image/bmp', 'BMP Image'),
        (0, b'RIFF', 'image/webp', 'WebP Image'),  # Could also be AVI/WAV
        (0, b'\x00\x00\x01\x00', 'image/x-icon', 'ICO Image'),
        (0, b'II*\x00', 'image/tiff', 'TIFF Image (little-endian)'),
        (0, b'MM\x00*', 'image/tiff', 'TIFF Image (big-endian)'),
        
        # Audio/Video
        (0, b'ID3', 'audio/mpeg', 'MP3 Audio'),
        (0, b'\xff\xfb', 'audio/mpeg', 'MP3 Audio'),
        (0, b'\xff\xfa', 'audio/mpeg', 'MP3 Audio'),
        (4, b'ftyp', 'video/mp4', 'MP4 Video'),
        (0, b'\x1a\x45\xdf\xa3', 'video/webm', 'WebM/MKV Video'),
        (0, b'OggS', 'audio/ogg', 'OGG Audio'),
        (8, b'AVI ', 'video/x-msvideo', 'AVI Video'),
        (8, b'WAVE', 'audio/wav', 'WAV Audio'),
        
        # Scripts (text-based, check for shebangs)
        (0, b'#!/bin/bash', 'text/x-shellscript', 'Bash Script'),
        (0, b'#!/bin/sh', 'text/x-shellscript', 'Shell Script'),
        (0, b'#!/usr/bin/env python', 'text/x-python', 'Python Script'),
        (0, b'#!/usr/bin/python', 'text/x-python', 'Python Script'),
        (0, b'#!/usr/bin/perl', 'text/x-perl', 'Perl Script'),
        
        # Java
        (0, b'\xca\xfe\xba\xbe', 'application/java-archive', 'Java Class'),
        
        # Fonts
        (0, b'\x00\x01\x00\x00', 'font/ttf', 'TrueType Font'),
        (0, b'OTTO', 'font/otf', 'OpenType Font'),
        (0, b'wOFF', 'font/woff', 'WOFF Font'),
        (0, b'wOF2', 'font/woff2', 'WOFF2 Font'),
        
        # Database
        (0, b'SQLite format 3', 'application/x-sqlite3', 'SQLite Database'),
        
        # Email
        (0, b'From ', 'message/rfc822', 'Email Message'),
        (0, b'Return-Path:', 'message/rfc822', 'Email Message'),
    ]
    
    # OOXML content type mappings (for ZIP-based Office files)
    OOXML_TYPES = {
        'word/': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xl/': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt/': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    }
    
    def detect(self, content: bytes) -> str:
        """
        Detect file type by examining magic bytes.
        
        Args:
            content: File content as bytes
            
        Returns:
            MIME type string
        """
        if not content:
            return 'application/octet-stream'
        
        # Check all signatures
        for offset, signature, mime_type, description in self.SIGNATURES:
            if len(content) > offset + len(signature):
                if content[offset:offset + len(signature)] == signature:
                    # Special handling for ZIP (might be OOXML)
                    if mime_type == 'application/zip':
                        ooxml_type = self._check_ooxml(content)
                        if ooxml_type:
                            return ooxml_type
                    
                    # Special handling for OLE (might be specific Office format)
                    if mime_type == 'application/x-ole-storage':
                        ole_type = self._check_ole_type(content)
                        if ole_type:
                            return ole_type
                    
                    return mime_type
        
        # Check for text files
        if self._is_text(content):
            return self._detect_text_type(content)
        
        return 'application/octet-stream'
    
    def _check_ooxml(self, content: bytes) -> Optional[str]:
        """Check if ZIP is actually an OOXML Office document."""
        try:
            import zipfile
            import io
            
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                names = zf.namelist()
                
                for prefix, mime_type in self.OOXML_TYPES.items():
                    if any(name.startswith(prefix) for name in names):
                        # Check for macro-enabled versions
                        if '[Content_Types].xml' in names:
                            ct_content = zf.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                            if 'vbaProject' in ct_content or 'macro' in ct_content.lower():
                                if 'word/' in str(names):
                                    return 'application/vnd.ms-word.document.macroEnabled.12'
                                elif 'xl/' in str(names):
                                    return 'application/vnd.ms-excel.sheet.macroEnabled.12'
                                elif 'ppt/' in str(names):
                                    return 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'
                        return mime_type
                
                # Check for OpenDocument formats
                if 'mimetype' in names:
                    return zf.read('mimetype').decode('utf-8').strip()
                    
        except Exception:
            pass
        
        return None
    
    def _check_ole_type(self, content: bytes) -> Optional[str]:
        """Determine specific type of OLE document."""
        # Look for specific signatures in OLE structure
        content_lower = content[:4096].lower()
        
        if b'word' in content_lower or b'document' in content_lower:
            return 'application/msword'
        elif b'excel' in content_lower or b'workbook' in content_lower:
            return 'application/vnd.ms-excel'
        elif b'powerpoint' in content_lower or b'presentation' in content_lower:
            return 'application/vnd.ms-powerpoint'
        
        return 'application/x-ole-storage'
    
    def _is_text(self, content: bytes) -> bool:
        """Check if content is likely text."""
        # Sample first 8KB
        sample = content[:8192]
        
        # Count non-text bytes
        non_text = 0
        for byte in sample:
            # Allow printable ASCII, tabs, newlines, carriage returns
            if byte < 7 or (byte > 14 and byte < 32 and byte != 27):
                non_text += 1
        
        # If less than 10% non-text, probably text
        return non_text / len(sample) < 0.1 if sample else False
    
    def _detect_text_type(self, content: bytes) -> str:
        """Detect specific type of text file."""
        try:
            text = content[:4096].decode('utf-8', errors='ignore').lower()
            
            # HTML
            if '<html' in text or '<!doctype html' in text:
                return 'text/html'
            
            # XML
            if text.startswith('<?xml') or '<' in text[:100]:
                return 'text/xml'
            
            # JSON
            text_stripped = text.strip()
            if text_stripped.startswith('{') or text_stripped.startswith('['):
                return 'application/json'
            
            # JavaScript
            if 'function ' in text or 'var ' in text or 'const ' in text or 'let ' in text:
                return 'application/javascript'
            
            # CSS
            if '{' in text and (':' in text) and (';' in text):
                if 'color:' in text or 'font:' in text or 'margin:' in text:
                    return 'text/css'
            
            # CSV
            if ',' in text and '\n' in text:
                lines = text.split('\n')[:5]
                comma_counts = [line.count(',') for line in lines if line.strip()]
                if comma_counts and all(c == comma_counts[0] for c in comma_counts):
                    return 'text/csv'
            
        except Exception:
            pass
        
        return 'text/plain'
    
    def get_description(self, mime_type: str) -> str:
        """Get human-readable description for MIME type."""
        for _, _, mtype, description in self.SIGNATURES:
            if mtype == mime_type:
                return description
        
        # Generic descriptions
        descriptions = {
            'application/octet-stream': 'Binary Data',
            'text/plain': 'Plain Text',
            'text/html': 'HTML Document',
            'text/xml': 'XML Document',
            'application/json': 'JSON Data',
            'application/javascript': 'JavaScript',
        }
        
        return descriptions.get(mime_type, mime_type)
