"""
NiksES PDF Analyzer

Analyze PDF documents for:
- Embedded JavaScript
- Auto-open actions
- Launch actions (external program execution)
- Embedded files
- Encrypted streams
- Suspicious /Names
"""

import re
import io
import logging
from typing import Optional, List

from app.models.static_analysis import (
    PDFAnalysisResult,
    PDFJavaScriptInfo,
    PDFActionInfo,
    FileMetadata,
)

logger = logging.getLogger(__name__)


class PDFAnalyzer:
    """
    Analyze PDF documents for malicious indicators.
    
    PDFs can contain:
    - JavaScript (often used for exploits)
    - OpenAction/AA (automatic execution on open)
    - Launch actions (run external programs)
    - Embedded files (can hide malware)
    - Form submission to external URLs
    """
    
    # Suspicious PDF keywords
    SUSPICIOUS_KEYWORDS = {
        '/JavaScript': 'JavaScript code',
        '/JS': 'JavaScript code',
        '/OpenAction': 'Auto-open action',
        '/AA': 'Additional actions',
        '/Launch': 'Launch external program',
        '/EmbeddedFile': 'Embedded file',
        '/EmbeddedFiles': 'Embedded files',
        '/AcroForm': 'PDF form (can submit data)',
        '/XFA': 'XML Forms Architecture',
        '/RichMedia': 'Rich media (Flash, etc.)',
        '/ObjStm': 'Object stream (can hide content)',
        '/URI': 'URL reference',
        '/GoToR': 'Go to remote PDF',
        '/GoToE': 'Go to embedded file',
        '/SubmitForm': 'Form submission',
        '/ImportData': 'Data import',
    }
    
    # Suspicious JavaScript functions
    SUSPICIOUS_JS_FUNCTIONS = {
        'eval', 'unescape', 'escape',
        'String.fromCharCode', 'charCodeAt',
        'getURL', 'loadMovie', 'getAnnots',
        'getField', 'submitForm', 'mailDoc',
        'exportDataObject', 'launchURL',
        'app.launchURL', 'this.exportDataObject',
        'spell.customDictionaryOpen',
        'util.printf', 'util.printd',
        'Collab.collectEmailInfo', 'Collab.getIcon',
    }
    
    def analyze(self, content: bytes) -> PDFAnalysisResult:
        """
        Analyze PDF document for malicious indicators.
        
        Args:
            content: PDF file content as bytes
            
        Returns:
            PDFAnalysisResult with findings
        """
        result = PDFAnalysisResult()
        
        # Verify it's a PDF
        if not content.startswith(b'%PDF'):
            return result
        
        # Get PDF version
        version_match = re.search(rb'%PDF-(\d\.\d)', content[:20])
        if version_match:
            result.pdf_version = version_match.group(1).decode('utf-8')
        
        # Try using PyPDF2/pypdf first
        try:
            self._analyze_with_pypdf(content, result)
        except ImportError:
            logger.warning("pypdf not installed, using basic PDF analysis")
            self._basic_analysis(content, result)
        except Exception as e:
            logger.warning(f"pypdf analysis failed: {e}, falling back to basic")
            self._basic_analysis(content, result)
        
        return result
    
    def _analyze_with_pypdf(self, content: bytes, result: PDFAnalysisResult):
        """Analyze PDF using pypdf library."""
        from pypdf import PdfReader
        
        reader = PdfReader(io.BytesIO(content))
        
        # Get page count
        result.page_count = len(reader.pages)
        
        # Check for JavaScript
        if reader.metadata:
            # Extract metadata
            result.metadata = FileMetadata(
                author=reader.metadata.get('/Author'),
                creator=reader.metadata.get('/Creator'),
                producer=reader.metadata.get('/Producer'),
                title=reader.metadata.get('/Title'),
                subject=reader.metadata.get('/Subject'),
            )
        
        # Check catalog for actions and JavaScript
        if hasattr(reader, 'trailer') and '/Root' in reader.trailer:
            root = reader.trailer['/Root']
            self._check_catalog(root, result)
        
        # Also do basic analysis for patterns pypdf might miss
        self._basic_analysis(content, result)
    
    def _check_catalog(self, root, result: PDFAnalysisResult):
        """Check PDF catalog for suspicious elements."""
        try:
            # Check for OpenAction
            if '/OpenAction' in root:
                result.has_auto_actions = True
                action = root['/OpenAction']
                result.actions.append(PDFActionInfo(
                    action_type='OpenAction',
                    target=str(action)[:200],
                    is_suspicious=True
                ))
            
            # Check for AA (Additional Actions)
            if '/AA' in root:
                result.has_auto_actions = True
                result.actions.append(PDFActionInfo(
                    action_type='AA',
                    target='Additional Actions defined',
                    is_suspicious=True
                ))
            
            # Check for JavaScript in Names
            if '/Names' in root:
                names = root['/Names']
                if '/JavaScript' in names:
                    result.has_javascript = True
                    result.suspicious_names.append('/JavaScript')
                if '/EmbeddedFiles' in names:
                    result.has_embedded_files = True
                    result.suspicious_names.append('/EmbeddedFiles')
                    
        except Exception as e:
            logger.debug(f"Catalog check failed: {e}")
    
    def _basic_analysis(self, content: bytes, result: PDFAnalysisResult):
        """Basic PDF analysis using regex patterns."""
        content_str = content.decode('latin-1', errors='ignore')
        
        # Check for JavaScript
        js_patterns = [
            re.compile(r'/JavaScript\s*<<', re.IGNORECASE),
            re.compile(r'/JS\s*\(', re.IGNORECASE),
            re.compile(r'/JS\s*<', re.IGNORECASE),
            re.compile(r'/S\s*/JavaScript', re.IGNORECASE),
        ]
        
        for pattern in js_patterns:
            if pattern.search(content_str):
                result.has_javascript = True
                break
        
        # Try to extract JavaScript code
        if result.has_javascript:
            self._extract_javascript(content, result)
        
        # Check for OpenAction
        if re.search(r'/OpenAction\s', content_str, re.IGNORECASE):
            result.has_auto_actions = True
            result.actions.append(PDFActionInfo(
                action_type='OpenAction',
                is_suspicious=True
            ))
        
        # Check for AA (Additional Actions)
        if re.search(r'/AA\s*<<', content_str, re.IGNORECASE):
            result.has_auto_actions = True
            result.actions.append(PDFActionInfo(
                action_type='AA',
                is_suspicious=True
            ))
        
        # Check for Launch action
        if re.search(r'/Launch\s', content_str, re.IGNORECASE):
            result.has_launch_action = True
            
            # Try to extract launch target
            launch_match = re.search(
                r'/Launch\s*<<[^>]*?/F\s*\(([^)]+)\)',
                content_str,
                re.IGNORECASE | re.DOTALL
            )
            if launch_match:
                result.launch_targets.append(launch_match.group(1))
            
            result.actions.append(PDFActionInfo(
                action_type='Launch',
                target=result.launch_targets[0] if result.launch_targets else None,
                is_suspicious=True
            ))
        
        # Check for embedded files
        if '/EmbeddedFile' in content_str or '/EmbeddedFiles' in content_str:
            result.has_embedded_files = True
            
            # Try to extract embedded file names
            name_matches = re.findall(
                r'/F\s*\(([^)]+)\)',
                content_str
            )
            result.embedded_files.extend(name_matches[:10])
        
        # Check for object streams
        if '/ObjStm' in content_str:
            result.has_object_streams = True
        
        # Check for encrypted streams
        if '/Encrypt' in content_str or '/StmF' in content_str:
            result.has_encrypted_streams = True
        
        # Check for suspicious /Names entries
        for keyword, description in self.SUSPICIOUS_KEYWORDS.items():
            if keyword in content_str:
                if keyword not in ['/JavaScript', '/JS']:  # Already handled
                    result.suspicious_names.append(f"{keyword}: {description}")
        
        # Check for URI actions (external URLs)
        uri_matches = re.findall(
            r'/URI\s*\(([^)]+)\)',
            content_str
        )
        if uri_matches:
            result.actions.append(PDFActionInfo(
                action_type='URI',
                target=uri_matches[0],
                is_suspicious='/URI' in content_str and 'http' in uri_matches[0].lower()
            ))
    
    def _extract_javascript(self, content: bytes, result: PDFAnalysisResult):
        """Extract JavaScript code from PDF."""
        content_str = content.decode('latin-1', errors='ignore')
        
        # Pattern 1: /JS (code)
        js_matches = re.findall(
            r'/JS\s*\(([^)]+)\)',
            content_str,
            re.IGNORECASE | re.DOTALL
        )
        
        # Pattern 2: /JS <hex>
        hex_matches = re.findall(
            r'/JS\s*<([^>]+)>',
            content_str,
            re.IGNORECASE
        )
        
        # Convert hex to string
        for hex_code in hex_matches:
            try:
                decoded = bytes.fromhex(hex_code.replace(' ', '')).decode('utf-8', errors='ignore')
                js_matches.append(decoded)
            except Exception:
                pass
        
        # Pattern 3: stream after /JavaScript
        stream_pattern = re.compile(
            r'/JavaScript[^>]*>>stream\s*(.*?)\s*endstream',
            re.IGNORECASE | re.DOTALL
        )
        stream_matches = stream_pattern.findall(content_str)
        js_matches.extend(stream_matches)
        
        # Process found JavaScript
        for js_code in js_matches[:5]:  # Limit to 5
            # Find suspicious functions
            suspicious = []
            js_lower = js_code.lower()
            for func in self.SUSPICIOUS_JS_FUNCTIONS:
                if func.lower() in js_lower:
                    suspicious.append(func)
            
            # Extract URLs from JS
            urls = re.findall(r'https?://[^\s"\'<>]+', js_code, re.IGNORECASE)
            
            result.javascript.append(PDFJavaScriptInfo(
                code_preview=js_code[:500] if js_code else None,
                code_size=len(js_code),
                suspicious_functions=suspicious,
                urls_found=urls[:10]
            ))
    
    def get_indicators(self, result: PDFAnalysisResult) -> List[str]:
        """Get list of suspicious indicators from analysis."""
        indicators = []
        
        if result.has_javascript:
            indicators.append(f"Contains JavaScript ({len(result.javascript)} instance(s))")
        
        if result.has_auto_actions:
            indicators.append("Has automatic actions (OpenAction/AA)")
        
        if result.has_launch_action:
            indicators.append(f"Can launch external programs: {', '.join(result.launch_targets)}")
        
        if result.has_embedded_files:
            indicators.append(f"Contains embedded files: {', '.join(result.embedded_files[:3])}")
        
        if result.has_object_streams:
            indicators.append("Uses object streams (can hide malicious content)")
        
        if result.has_encrypted_streams:
            indicators.append("Contains encrypted streams")
        
        return indicators
