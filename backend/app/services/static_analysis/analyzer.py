"""
NiksES Static Analysis Engine

Main orchestrator for attachment static analysis.
Coordinates all specialized analyzers to produce comprehensive results.
"""

import logging
import hashlib
import time
import re
import math
from typing import Optional, List, Tuple
from collections import Counter

from app.models.static_analysis import (
    StaticAnalysisResult,
    ThreatLevel,
    FileCategory,
    SuspiciousIndicator,
    ExtractedString,
    EntropyAnalysis,
)
from app.services.static_analysis.magic_detector import MagicDetector
from app.services.static_analysis.string_extractor import StringExtractor
from app.services.static_analysis.office_analyzer import OfficeAnalyzer
from app.services.static_analysis.pdf_analyzer import PDFAnalyzer
from app.services.static_analysis.pe_analyzer import PEAnalyzer
from app.services.static_analysis.archive_analyzer import ArchiveAnalyzer

logger = logging.getLogger(__name__)


class StaticAnalyzer:
    """
    Main static analysis engine for email attachments.
    
    Performs comprehensive file analysis without execution:
    - File type detection (magic bytes)
    - Hash calculation (MD5, SHA1, SHA256, ssdeep)
    - Entropy analysis
    - String extraction
    - Type-specific analysis (Office, PDF, PE, Archive)
    - Suspicious indicator detection
    """
    
    # File categories by extension
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
    
    def __init__(self):
        """Initialize static analyzer with all sub-analyzers."""
        self.magic_detector = MagicDetector()
        self.string_extractor = StringExtractor()
        self.office_analyzer = OfficeAnalyzer()
        self.pdf_analyzer = PDFAnalyzer()
        self.pe_analyzer = PEAnalyzer()
        self.archive_analyzer = ArchiveAnalyzer()
    
    def analyze(
        self,
        content: bytes,
        filename: str,
        claimed_content_type: str = "application/octet-stream"
    ) -> StaticAnalysisResult:
        """
        Perform comprehensive static analysis on file content.
        
        Args:
            content: Raw file content as bytes
            filename: Original filename
            claimed_content_type: MIME type from Content-Type header
            
        Returns:
            StaticAnalysisResult with all analysis findings
        """
        start_time = time.time()
        errors: List[str] = []
        indicators: List[SuspiciousIndicator] = []
        
        # Basic info
        extension = self._get_extension(filename).lower()
        file_size = len(content)
        
        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Calculate ssdeep if available
        ssdeep_hash = self._calculate_ssdeep(content)
        
        # Detect file type by magic bytes
        detected_type = self.magic_detector.detect(content)
        type_mismatch = self._check_type_mismatch(extension, detected_type, claimed_content_type)
        
        if type_mismatch:
            indicators.append(SuspiciousIndicator(
                indicator_type="type_mismatch",
                description=f"File extension '{extension}' doesn't match detected type '{detected_type}'",
                severity=ThreatLevel.HIGH,
                evidence=f"Claimed: {claimed_content_type}, Detected: {detected_type}",
                mitre_technique="T1036.007"  # Masquerading: Double File Extension
            ))
        
        # Detect double extension
        has_double_ext, double_ext_details = self._check_double_extension(filename)
        if has_double_ext:
            indicators.append(SuspiciousIndicator(
                indicator_type="double_extension",
                description=f"Double file extension detected: {double_ext_details}",
                severity=ThreatLevel.HIGH,
                evidence=filename,
                mitre_technique="T1036.007"
            ))
        
        # Determine file category
        file_category = self._categorize_file(extension, detected_type)
        
        # Calculate entropy
        entropy_result = self._analyze_entropy(content)
        if entropy_result.is_likely_encrypted:
            indicators.append(SuspiciousIndicator(
                indicator_type="high_entropy",
                description="File has very high entropy, likely encrypted or packed",
                severity=ThreatLevel.MEDIUM,
                evidence=f"Entropy: {entropy_result.overall_entropy:.2f}",
                mitre_technique="T1027"  # Obfuscated Files or Information
            ))
        
        # Extract strings
        string_results = self.string_extractor.extract(content)
        
        # Initialize result
        result = StaticAnalysisResult(
            filename=filename,
            file_size=file_size,
            file_category=file_category,
            md5=md5_hash,
            sha1=sha1_hash,
            sha256=sha256_hash,
            ssdeep=ssdeep_hash,
            extension=extension,
            claimed_type=claimed_content_type,
            detected_type=detected_type,
            type_mismatch=type_mismatch,
            has_double_extension=has_double_ext,
            double_extension_details=double_ext_details,
            entropy=entropy_result,
            strings_summary=string_results.get('summary', {}),
            interesting_strings=string_results.get('strings', [])[:100],
            urls_found=string_results.get('urls', []),
            ips_found=string_results.get('ips', []),
            emails_found=string_results.get('emails', []),
        )
        
        # Type-specific analysis
        try:
            if file_category == FileCategory.DOCUMENT:
                if extension in self.OFFICE_EXTENSIONS or 'office' in detected_type.lower():
                    office_result = self.office_analyzer.analyze(content, filename)
                    result.office_analysis = office_result
                    indicators.extend(self._get_office_indicators(office_result))
                    
                elif extension == '.pdf' or detected_type == 'application/pdf':
                    pdf_result = self.pdf_analyzer.analyze(content)
                    result.pdf_analysis = pdf_result
                    indicators.extend(self._get_pdf_indicators(pdf_result))
            
            elif file_category == FileCategory.EXECUTABLE:
                pe_result = self.pe_analyzer.analyze(content)
                result.pe_analysis = pe_result
                result.imphash = pe_result.imports[0].dll_name if pe_result.imports else None
                indicators.extend(self._get_pe_indicators(pe_result))
            
            elif file_category == FileCategory.ARCHIVE:
                archive_result = self.archive_analyzer.analyze(content, filename)
                result.archive_analysis = archive_result
                indicators.extend(self._get_archive_indicators(archive_result))
                
        except Exception as e:
            logger.warning(f"Type-specific analysis failed for {filename}: {e}")
            errors.append(f"Analysis error: {str(e)}")
        
        # Add string-based indicators
        if len(string_results.get('urls', [])) > 0:
            indicators.append(SuspiciousIndicator(
                indicator_type="embedded_urls",
                description=f"Found {len(string_results['urls'])} URLs embedded in file",
                severity=ThreatLevel.LOW,
                evidence=', '.join(string_results['urls'][:3])
            ))
        
        # Calculate overall threat level
        result.indicators = indicators
        result.threat_level, result.threat_score = self._calculate_threat_level(indicators, result)
        result.threat_summary = self._generate_threat_summary(result)
        
        result.analysis_time_ms = int((time.time() - start_time) * 1000)
        result.analysis_errors = errors
        
        return result
    
    def _get_extension(self, filename: str) -> str:
        """Extract file extension from filename."""
        if '.' not in filename:
            return ''
        return '.' + filename.rsplit('.', 1)[-1]
    
    def _check_double_extension(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Check for double extension tricks like 'invoice.pdf.exe'."""
        parts = filename.lower().split('.')
        if len(parts) < 3:
            return False, None
        
        # Check if second-to-last looks like a document extension
        # and last is executable
        doc_exts = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.jpg', '.png'}
        exec_exts = self.EXECUTABLE_EXTENSIONS
        
        second_last = '.' + parts[-2]
        last = '.' + parts[-1]
        
        if second_last in doc_exts and last in exec_exts:
            return True, f"{second_last}{last}"
        
        return False, None
    
    def _check_type_mismatch(
        self,
        extension: str,
        detected_type: str,
        claimed_type: str
    ) -> bool:
        """Check if file extension matches detected type."""
        # Map extensions to expected MIME types
        ext_to_mime = {
            '.pdf': ['application/pdf'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.xls': ['application/vnd.ms-excel'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.exe': ['application/x-msdownload', 'application/x-executable', 'application/x-dosexec'],
            '.zip': ['application/zip', 'application/x-zip-compressed'],
            '.jpg': ['image/jpeg'],
            '.png': ['image/png'],
            '.gif': ['image/gif'],
        }
        
        expected_types = ext_to_mime.get(extension.lower(), [])
        if not expected_types:
            return False
        
        # Check if detected type matches any expected type
        detected_lower = detected_type.lower()
        for expected in expected_types:
            if expected in detected_lower or detected_lower in expected:
                return False
        
        # Special case: executable disguised as document
        if extension.lower() in {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png'}:
            if 'executable' in detected_lower or 'x-dosexec' in detected_lower:
                return True
        
        return False
    
    def _categorize_file(self, extension: str, detected_type: str) -> FileCategory:
        """Categorize file based on extension and detected type."""
        ext_lower = extension.lower()
        
        if ext_lower in self.EXECUTABLE_EXTENSIONS:
            return FileCategory.EXECUTABLE
        if 'executable' in detected_type.lower():
            return FileCategory.EXECUTABLE
        
        if ext_lower in self.SCRIPT_EXTENSIONS:
            return FileCategory.SCRIPT
        
        if ext_lower in self.ARCHIVE_EXTENSIONS:
            return FileCategory.ARCHIVE
        if 'zip' in detected_type.lower() or 'archive' in detected_type.lower():
            return FileCategory.ARCHIVE
        
        if ext_lower in self.OFFICE_EXTENSIONS or ext_lower == '.pdf':
            return FileCategory.DOCUMENT
        if 'document' in detected_type.lower() or 'pdf' in detected_type.lower():
            return FileCategory.DOCUMENT
        
        if ext_lower in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp'}:
            return FileCategory.IMAGE
        if 'image' in detected_type.lower():
            return FileCategory.IMAGE
        
        if ext_lower in {'.mp3', '.mp4', '.wav', '.avi', '.mkv', '.mov'}:
            return FileCategory.MEDIA
        
        return FileCategory.UNKNOWN
    
    def _analyze_entropy(self, content: bytes) -> EntropyAnalysis:
        """Calculate file entropy to detect encryption/packing."""
        if len(content) == 0:
            return EntropyAnalysis()
        
        # Calculate overall entropy
        byte_counts = Counter(content)
        total = len(content)
        entropy = 0.0
        
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return EntropyAnalysis(
            overall_entropy=round(entropy, 4),
            is_high_entropy=entropy > 7.0,
            is_likely_encrypted=entropy > 7.5,
            is_likely_packed=entropy > 7.0
        )
    
    def _calculate_ssdeep(self, content: bytes) -> Optional[str]:
        """Calculate ssdeep fuzzy hash."""
        try:
            import ssdeep
            return ssdeep.hash(content)
        except ImportError:
            return None
        except Exception:
            return None
    
    def _get_office_indicators(self, result) -> List[SuspiciousIndicator]:
        """Extract suspicious indicators from Office analysis."""
        indicators = []
        
        if result.has_macros:
            severity = ThreatLevel.HIGH
            for macro in result.macros:
                if macro.has_auto_exec:
                    severity = ThreatLevel.CRITICAL
                    break
            
            indicators.append(SuspiciousIndicator(
                indicator_type="vba_macros",
                description=f"Document contains {len(result.macros)} VBA macro(s)",
                severity=severity,
                evidence=', '.join(m.stream_name for m in result.macros[:3]),
                mitre_technique="T1059.005"  # Command and Scripting Interpreter: VBA
            ))
            
            # Check for auto-exec
            for macro in result.macros:
                if macro.has_auto_exec:
                    indicators.append(SuspiciousIndicator(
                        indicator_type="macro_auto_exec",
                        description=f"Macro has auto-execute triggers: {', '.join(macro.auto_exec_triggers)}",
                        severity=ThreatLevel.CRITICAL,
                        evidence=macro.stream_name,
                        mitre_technique="T1204.002"  # User Execution: Malicious File
                    ))
                    break
        
        if result.has_dde:
            indicators.append(SuspiciousIndicator(
                indicator_type="dde_link",
                description="Document contains DDE (Dynamic Data Exchange) links",
                severity=ThreatLevel.HIGH,
                evidence=result.dde_links[0] if result.dde_links else None,
                mitre_technique="T1559.002"  # DDE
            ))
        
        if result.template_injection:
            indicators.append(SuspiciousIndicator(
                indicator_type="template_injection",
                description="Remote template injection detected",
                severity=ThreatLevel.CRITICAL,
                evidence=result.template_url,
                mitre_technique="T1221"  # Template Injection
            ))
        
        if result.has_ole_objects:
            suspicious_ole = [o for o in result.ole_objects if o.is_suspicious]
            if suspicious_ole:
                indicators.append(SuspiciousIndicator(
                    indicator_type="suspicious_ole",
                    description=f"Document contains {len(suspicious_ole)} suspicious OLE object(s)",
                    severity=ThreatLevel.HIGH,
                    evidence=suspicious_ole[0].risk_reason,
                    mitre_technique="T1027.006"  # HTML Smuggling (or similar)
                ))
        
        return indicators
    
    def _get_pdf_indicators(self, result) -> List[SuspiciousIndicator]:
        """Extract suspicious indicators from PDF analysis."""
        indicators = []
        
        if result.has_javascript:
            indicators.append(SuspiciousIndicator(
                indicator_type="pdf_javascript",
                description=f"PDF contains JavaScript ({len(result.javascript)} instance(s))",
                severity=ThreatLevel.HIGH,
                evidence=result.javascript[0].code_preview[:100] if result.javascript else None,
                mitre_technique="T1059.007"  # JavaScript
            ))
        
        if result.has_auto_actions:
            indicators.append(SuspiciousIndicator(
                indicator_type="pdf_auto_action",
                description="PDF has automatic actions (OpenAction, etc.)",
                severity=ThreatLevel.MEDIUM,
                evidence=result.actions[0].action_type if result.actions else None,
                mitre_technique="T1204.002"
            ))
        
        if result.has_launch_action:
            indicators.append(SuspiciousIndicator(
                indicator_type="pdf_launch",
                description="PDF can launch external applications",
                severity=ThreatLevel.CRITICAL,
                evidence=', '.join(result.launch_targets[:3]),
                mitre_technique="T1204.002"
            ))
        
        if result.has_embedded_files:
            indicators.append(SuspiciousIndicator(
                indicator_type="pdf_embedded_files",
                description=f"PDF contains {len(result.embedded_files)} embedded file(s)",
                severity=ThreatLevel.MEDIUM,
                evidence=', '.join(result.embedded_files[:3])
            ))
        
        return indicators
    
    def _get_pe_indicators(self, result) -> List[SuspiciousIndicator]:
        """Extract suspicious indicators from PE analysis."""
        indicators = []
        
        if result.is_packed:
            indicators.append(SuspiciousIndicator(
                indicator_type="packed_executable",
                description=f"Executable appears to be packed" + (f" ({result.packer_name})" if result.packer_name else ""),
                severity=ThreatLevel.HIGH,
                evidence=', '.join(result.packing_indicators[:3]),
                mitre_technique="T1027.002"  # Software Packing
            ))
        
        if result.suspicious_imports:
            indicators.append(SuspiciousIndicator(
                indicator_type="suspicious_imports",
                description=f"Executable imports suspicious APIs",
                severity=ThreatLevel.MEDIUM,
                evidence=', '.join(result.suspicious_imports[:5]),
                mitre_technique="T1106"  # Native API
            ))
        
        if not result.is_signed:
            indicators.append(SuspiciousIndicator(
                indicator_type="unsigned_executable",
                description="Executable is not digitally signed",
                severity=ThreatLevel.LOW,
                evidence=None
            ))
        
        if result.suspicious_sections:
            indicators.append(SuspiciousIndicator(
                indicator_type="suspicious_sections",
                description=f"PE has suspicious section names",
                severity=ThreatLevel.MEDIUM,
                evidence=', '.join(result.suspicious_sections[:3]),
                mitre_technique="T1027"
            ))
        
        return indicators
    
    def _get_archive_indicators(self, result) -> List[SuspiciousIndicator]:
        """Extract suspicious indicators from archive analysis."""
        indicators = []
        
        if result.has_executables:
            indicators.append(SuspiciousIndicator(
                indicator_type="archive_with_executables",
                description=f"Archive contains {result.executable_count} executable file(s)",
                severity=ThreatLevel.HIGH,
                evidence=', '.join(result.suspicious_entries[:3]),
                mitre_technique="T1566.001"  # Spearphishing Attachment
            ))
        
        if result.is_password_protected:
            indicators.append(SuspiciousIndicator(
                indicator_type="password_protected_archive",
                description="Archive is password protected",
                severity=ThreatLevel.MEDIUM,
                evidence=None,
                mitre_technique="T1027"
            ))
        
        if result.has_nested_archives and result.nested_archive_count > 2:
            indicators.append(SuspiciousIndicator(
                indicator_type="nested_archives",
                description=f"Archive contains {result.nested_archive_count} nested archive(s)",
                severity=ThreatLevel.MEDIUM,
                evidence=None,
                mitre_technique="T1027"
            ))
        
        return indicators
    
    def _calculate_threat_level(
        self,
        indicators: List[SuspiciousIndicator],
        result: StaticAnalysisResult
    ) -> Tuple[ThreatLevel, int]:
        """Calculate overall threat level from indicators."""
        if not indicators:
            return ThreatLevel.CLEAN, 0
        
        # Weight by severity
        severity_weights = {
            ThreatLevel.CRITICAL: 40,
            ThreatLevel.HIGH: 25,
            ThreatLevel.MEDIUM: 15,
            ThreatLevel.LOW: 5,
        }
        
        score = 0
        max_severity = ThreatLevel.LOW
        
        for indicator in indicators:
            weight = severity_weights.get(indicator.severity, 5)
            score += weight
            
            if indicator.severity == ThreatLevel.CRITICAL:
                max_severity = ThreatLevel.CRITICAL
            elif indicator.severity == ThreatLevel.HIGH and max_severity != ThreatLevel.CRITICAL:
                max_severity = ThreatLevel.HIGH
            elif indicator.severity == ThreatLevel.MEDIUM and max_severity not in {ThreatLevel.CRITICAL, ThreatLevel.HIGH}:
                max_severity = ThreatLevel.MEDIUM
        
        # Cap at 100
        score = min(score, 100)
        
        # Determine level from score
        if score >= 70 or max_severity == ThreatLevel.CRITICAL:
            return ThreatLevel.CRITICAL, score
        elif score >= 50 or max_severity == ThreatLevel.HIGH:
            return ThreatLevel.HIGH, score
        elif score >= 25:
            return ThreatLevel.MEDIUM, score
        elif score > 0:
            return ThreatLevel.LOW, score
        
        return ThreatLevel.CLEAN, 0
    
    def _generate_threat_summary(self, result: StaticAnalysisResult) -> str:
        """Generate human-readable threat summary."""
        if result.threat_level == ThreatLevel.CLEAN:
            return f"File '{result.filename}' appears clean with no suspicious indicators."
        
        parts = []
        
        # Main classification
        parts.append(f"{result.threat_level.value.upper()} RISK: '{result.filename}'")
        
        # Key findings
        findings = []
        
        if result.type_mismatch:
            findings.append("file type mismatch detected")
        
        if result.has_double_extension:
            findings.append("double extension trick")
        
        if result.entropy.is_likely_encrypted:
            findings.append("high entropy (possible encryption)")
        
        if result.office_analysis:
            if result.office_analysis.has_macros:
                findings.append("contains VBA macros")
            if result.office_analysis.template_injection:
                findings.append("remote template injection")
        
        if result.pdf_analysis:
            if result.pdf_analysis.has_javascript:
                findings.append("contains JavaScript")
            if result.pdf_analysis.has_launch_action:
                findings.append("can launch external programs")
        
        if result.pe_analysis:
            if result.pe_analysis.is_packed:
                findings.append("packed executable")
        
        if result.archive_analysis:
            if result.archive_analysis.has_executables:
                findings.append(f"contains {result.archive_analysis.executable_count} executable(s)")
        
        if findings:
            parts.append("Findings: " + "; ".join(findings) + ".")
        
        parts.append(f"Risk Score: {result.threat_score}/100")
        
        return " ".join(parts)
