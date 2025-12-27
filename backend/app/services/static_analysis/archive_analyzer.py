"""
NiksES Archive Analyzer

Analyze archive files for:
- Contents listing
- Executable files inside
- Nested archives
- Password protection
- Suspicious filenames
"""

import io
import zipfile
import tarfile
import logging
from typing import Optional, List

from app.models.static_analysis import (
    ArchiveAnalysisResult,
    ArchiveEntry,
)

logger = logging.getLogger(__name__)


class ArchiveAnalyzer:
    """
    Analyze archive files for suspicious content.
    
    Supports:
    - ZIP files
    - TAR files (including .tar.gz, .tar.bz2)
    - RAR files (if rarfile is installed)
    - 7z files (if py7zr is installed)
    """
    
    # Executable extensions
    EXECUTABLE_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.com', '.pif', '.bat', '.cmd',
        '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        '.msi', '.msp', '.jar', '.hta', '.cpl', '.application'
    }
    
    # Script extensions
    SCRIPT_EXTENSIONS = {
        '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.wsh', '.py', '.pl', '.sh', '.bash'
    }
    
    # Office macro extensions
    MACRO_EXTENSIONS = {
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'
    }
    
    # Archive extensions (for nested detection)
    ARCHIVE_EXTENSIONS = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.xz', '.cab', '.iso', '.img'
    }
    
    def analyze(self, content: bytes, filename: str) -> ArchiveAnalysisResult:
        """
        Analyze archive file.
        
        Args:
            content: Archive content as bytes
            filename: Original filename
            
        Returns:
            ArchiveAnalysisResult with findings
        """
        result = ArchiveAnalysisResult(archive_type='unknown')
        
        # Determine archive type
        if content[:2] == b'PK':
            result.archive_type = 'zip'
            self._analyze_zip(content, result)
        elif content[:6] == b'Rar!\x1a\x07':
            result.archive_type = 'rar'
            self._analyze_rar(content, result)
        elif content[:6] == b'7z\xbc\xaf\x27\x1c':
            result.archive_type = '7z'
            self._analyze_7z(content, result)
        elif content[:3] == b'\x1f\x8b\x08':
            result.archive_type = 'gzip'
            self._analyze_gzip(content, result)
        elif content[:3] == b'BZh':
            result.archive_type = 'bzip2'
            self._analyze_bzip2(content, result)
        else:
            # Try tar (may not have magic at start)
            try:
                tarfile.open(fileobj=io.BytesIO(content))
                result.archive_type = 'tar'
                self._analyze_tar(content, result)
            except Exception:
                logger.warning(f"Unknown archive format for {filename}")
        
        # Calculate statistics
        self._calculate_stats(result)
        
        return result
    
    def _analyze_zip(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze ZIP archive."""
        try:
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                for info in zf.infolist():
                    entry = self._create_entry(info.filename, info.file_size, info.compress_size)
                    
                    # Check if encrypted
                    if info.flag_bits & 0x1:
                        entry.is_encrypted = True
                        result.is_password_protected = True
                    
                    result.entries.append(entry)
                    
        except zipfile.BadZipFile as e:
            if 'password required' in str(e).lower() or 'encrypted' in str(e).lower():
                result.is_password_protected = True
        except Exception as e:
            logger.warning(f"ZIP analysis failed: {e}")
    
    def _analyze_rar(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze RAR archive."""
        try:
            import rarfile
            
            with rarfile.RarFile(io.BytesIO(content)) as rf:
                for info in rf.infolist():
                    entry = self._create_entry(
                        info.filename,
                        info.file_size,
                        info.compress_size
                    )
                    
                    if info.needs_password():
                        entry.is_encrypted = True
                        result.is_password_protected = True
                    
                    result.entries.append(entry)
                    
        except ImportError:
            logger.warning("rarfile not installed, basic RAR analysis")
            result.entries.append(ArchiveEntry(
                filename='(RAR contents unavailable - install rarfile)',
                is_suspicious=False
            ))
        except Exception as e:
            if 'password' in str(e).lower():
                result.is_password_protected = True
            logger.warning(f"RAR analysis failed: {e}")
    
    def _analyze_7z(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze 7z archive."""
        try:
            import py7zr
            
            with py7zr.SevenZipFile(io.BytesIO(content), 'r') as sz:
                for name, info in sz.archiveinfo().files.items() if hasattr(sz.archiveinfo(), 'files') else []:
                    entry = self._create_entry(name, info.get('size', 0), info.get('compressed', 0))
                    result.entries.append(entry)
                    
        except ImportError:
            logger.warning("py7zr not installed, basic 7z analysis")
            result.entries.append(ArchiveEntry(
                filename='(7z contents unavailable - install py7zr)',
                is_suspicious=False
            ))
        except Exception as e:
            if 'password' in str(e).lower():
                result.is_password_protected = True
            logger.warning(f"7z analysis failed: {e}")
    
    def _analyze_tar(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze TAR archive."""
        try:
            with tarfile.open(fileobj=io.BytesIO(content)) as tf:
                for member in tf.getmembers():
                    entry = self._create_entry(member.name, member.size, member.size)
                    entry.is_directory = member.isdir()
                    result.entries.append(entry)
                    
        except Exception as e:
            logger.warning(f"TAR analysis failed: {e}")
    
    def _analyze_gzip(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze GZIP archive."""
        try:
            import gzip
            
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                # GZIP typically contains a single file
                decompressed = gz.read()
                
                # Check if it's a tar inside (tar.gz)
                if decompressed[:5] == b'ustar' or (len(decompressed) > 257 and decompressed[257:262] == b'ustar'):
                    result.archive_type = 'tar.gz'
                    self._analyze_tar(decompressed, result)
                else:
                    # Single file
                    result.entries.append(ArchiveEntry(
                        filename='decompressed_content',
                        size_compressed=len(content),
                        size_uncompressed=len(decompressed),
                        is_encrypted=False,
                        is_directory=False,
                        is_executable=self._is_executable_content(decompressed),
                        is_suspicious=self._is_executable_content(decompressed)
                    ))
                    
        except Exception as e:
            logger.warning(f"GZIP analysis failed: {e}")
    
    def _analyze_bzip2(self, content: bytes, result: ArchiveAnalysisResult):
        """Analyze BZIP2 archive."""
        try:
            import bz2
            
            decompressed = bz2.decompress(content)
            
            # Check if it's a tar inside (tar.bz2)
            if len(decompressed) > 257 and decompressed[257:262] == b'ustar':
                result.archive_type = 'tar.bz2'
                self._analyze_tar(decompressed, result)
            else:
                result.entries.append(ArchiveEntry(
                    filename='decompressed_content',
                    size_compressed=len(content),
                    size_uncompressed=len(decompressed),
                    is_executable=self._is_executable_content(decompressed)
                ))
                
        except Exception as e:
            logger.warning(f"BZIP2 analysis failed: {e}")
    
    def _create_entry(self, filename: str, size_uncompressed: int, size_compressed: int) -> ArchiveEntry:
        """Create an ArchiveEntry with analysis."""
        ext = self._get_extension(filename).lower()
        
        entry = ArchiveEntry(
            filename=filename,
            size_compressed=size_compressed,
            size_uncompressed=size_uncompressed,
            is_encrypted=False,
            is_directory=filename.endswith('/'),
            is_executable=ext in self.EXECUTABLE_EXTENSIONS,
            is_suspicious=False
        )
        
        # Check for suspicious patterns
        if ext in self.EXECUTABLE_EXTENSIONS:
            entry.is_suspicious = True
            entry.suspicion_reason = "Executable file in archive"
        
        if ext in self.MACRO_EXTENSIONS:
            entry.is_suspicious = True
            entry.suspicion_reason = "Macro-enabled Office document"
        
        # Check for double extension
        if self._has_double_extension(filename):
            entry.is_suspicious = True
            entry.suspicion_reason = "Double extension trick"
        
        # Check for hidden file (starts with .)
        name_only = filename.rsplit('/', 1)[-1]
        if name_only.startswith('.') and ext in self.EXECUTABLE_EXTENSIONS:
            entry.is_suspicious = True
            entry.suspicion_reason = "Hidden executable"
        
        return entry
    
    def _calculate_stats(self, result: ArchiveAnalysisResult):
        """Calculate archive statistics."""
        result.total_files = sum(1 for e in result.entries if not e.is_directory)
        result.total_directories = sum(1 for e in result.entries if e.is_directory)
        result.total_size_uncompressed = sum(e.size_uncompressed for e in result.entries)
        
        if result.total_size_uncompressed > 0:
            total_compressed = sum(e.size_compressed for e in result.entries)
            result.compression_ratio = total_compressed / result.total_size_uncompressed
        
        # Count executables
        result.executable_count = sum(1 for e in result.entries if e.is_executable)
        result.has_executables = result.executable_count > 0
        
        # Check for scripts
        result.has_scripts = any(
            self._get_extension(e.filename).lower() in self.SCRIPT_EXTENSIONS
            for e in result.entries
        )
        
        # Check for Office docs
        result.has_office_docs = any(
            self._get_extension(e.filename).lower() in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'} | self.MACRO_EXTENSIONS
            for e in result.entries
        )
        
        # Check for nested archives
        nested_count = sum(
            1 for e in result.entries
            if self._get_extension(e.filename).lower() in self.ARCHIVE_EXTENSIONS
        )
        result.has_nested_archives = nested_count > 0
        result.nested_archive_count = nested_count
        
        # Collect suspicious entries
        result.suspicious_entries = [
            e.filename for e in result.entries if e.is_suspicious
        ]
    
    def _get_extension(self, filename: str) -> str:
        """Get file extension."""
        if '.' not in filename:
            return ''
        return '.' + filename.rsplit('.', 1)[-1]
    
    def _has_double_extension(self, filename: str) -> bool:
        """Check for double extension."""
        parts = filename.lower().split('.')
        if len(parts) < 3:
            return False
        
        # Check if second-to-last looks like a document extension
        doc_exts = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'png'}
        exec_exts = {'exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js'}
        
        return parts[-2] in doc_exts and parts[-1] in exec_exts
    
    def _is_executable_content(self, content: bytes) -> bool:
        """Check if content is executable by magic bytes."""
        if content[:2] == b'MZ':  # DOS/Windows
            return True
        if content[:4] == b'\x7fELF':  # Linux
            return True
        if content[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe']:  # macOS
            return True
        return False
    
    def get_indicators(self, result: ArchiveAnalysisResult) -> List[str]:
        """Get list of suspicious indicators from analysis."""
        indicators = []
        
        if result.has_executables:
            indicators.append(f"Contains {result.executable_count} executable(s)")
        
        if result.is_password_protected:
            indicators.append("Password protected")
        
        if result.has_nested_archives:
            indicators.append(f"Contains {result.nested_archive_count} nested archive(s)")
        
        if result.suspicious_entries:
            indicators.append(f"Suspicious files: {', '.join(result.suspicious_entries[:3])}")
        
        return indicators
