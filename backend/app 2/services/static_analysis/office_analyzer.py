"""
NiksES Office Document Analyzer

Analyze Microsoft Office documents for:
- VBA macros
- OLE embedded objects
- DDE links
- Remote template injection
- Document metadata
"""

import io
import re
import zipfile
import logging
from typing import Optional, List
from datetime import datetime
from xml.etree import ElementTree as ET

from app.models.static_analysis import (
    OfficeAnalysisResult,
    VBAMacroInfo,
    OLEObjectInfo,
    FileMetadata,
)

logger = logging.getLogger(__name__)


class OfficeAnalyzer:
    """
    Analyze Microsoft Office documents for malicious indicators.
    
    Supports both legacy OLE formats (.doc, .xls, .ppt) and
    modern OOXML formats (.docx, .xlsx, .pptx).
    """
    
    # VBA auto-execute trigger names
    AUTO_EXEC_TRIGGERS = {
        'autoopen', 'auto_open', 'autoclose', 'auto_close',
        'autoexec', 'auto_exec', 'autonew', 'auto_new',
        'autoexit', 'auto_exit', 'document_open', 'document_close',
        'document_new', 'documentopen', 'documentclose',
        'workbook_open', 'workbook_close', 'workbook_activate',
        'worksheet_activate', 'worksheet_change',
        'app_startup', 'autostart', 'main'
    }
    
    # Suspicious VBA keywords
    SUSPICIOUS_VBA_KEYWORDS = {
        'shell', 'wscript', 'createobject', 'getobject',
        'powershell', 'cmd.exe', 'cmd /c', 'execute',
        'shellexecute', 'environ', 'downloadfile',
        'urldownloadtofile', 'xmlhttp', 'winhttp',
        'adodb.stream', 'scripting.filesystemobject',
        'wmi', 'win32_process', 'callbyname',
        'libc', 'kernel32', 'virtualalloc',
        'rtlmovememory', 'ntdll', 'base64',
        'frombase64string', 'chr(', 'chrw(',
        'asc(', 'xor', 'decrypt', 'encode',
    }
    
    # DDE patterns
    DDE_PATTERNS = [
        re.compile(rb'DDEAUTO\s', re.IGNORECASE),
        re.compile(rb'DDE\s', re.IGNORECASE),
        re.compile(rb'\\dde\s', re.IGNORECASE),
        re.compile(rb'<w:fldData>', re.IGNORECASE),
    ]
    
    # Suspicious OLE CLSIDs
    SUSPICIOUS_CLSIDS = {
        '00024500-0000-0000-C000-000000000046': 'Excel.Chart',
        '00024512-0000-0000-C000-000000000046': 'Excel.Sheet',
        'F4754C9B-64F5-4B40-8AF4-679732AC0607': 'Package (embedded file)',
        '0003000C-0000-0000-C000-000000000046': 'Package (embedded file)',
    }
    
    def analyze(self, content: bytes, filename: str) -> OfficeAnalysisResult:
        """
        Analyze Office document for malicious indicators.
        
        Args:
            content: File content as bytes
            filename: Original filename
            
        Returns:
            OfficeAnalysisResult with findings
        """
        result = OfficeAnalysisResult()
        
        # Determine format
        if content[:4] == b'\xd0\xcf\x11\xe0':
            # OLE format (legacy .doc, .xls, .ppt)
            self._analyze_ole(content, result)
        elif content[:2] == b'PK':
            # OOXML format (.docx, .xlsx, .pptx)
            self._analyze_ooxml(content, result)
        else:
            # Try RTF
            if content[:5] == b'{\\rtf':
                self._analyze_rtf(content, result)
        
        return result
    
    def _analyze_ole(self, content: bytes, result: OfficeAnalysisResult):
        """Analyze OLE compound document."""
        try:
            import olefile
            
            ole = olefile.OleFileIO(io.BytesIO(content))
            
            # Check for VBA macros
            if ole.exists('macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                result.has_macros = True
                self._extract_vba_ole(ole, result)
            
            # Check for embedded objects
            self._extract_ole_objects(ole, result)
            
            # Extract metadata
            result.metadata = self._extract_ole_metadata(ole)
            
            ole.close()
            
        except ImportError:
            logger.warning("olefile not installed, using basic OLE analysis")
            self._basic_ole_analysis(content, result)
        except Exception as e:
            logger.warning(f"OLE analysis failed: {e}")
            self._basic_ole_analysis(content, result)
    
    def _basic_ole_analysis(self, content: bytes, result: OfficeAnalysisResult):
        """Basic OLE analysis without olefile library."""
        content_lower = content.lower()
        
        # Check for VBA signatures
        if b'_vba_project' in content_lower or b'vbaproject' in content_lower:
            result.has_macros = True
            
            # Try to find macro code
            vba_start = content.find(b'Attribute VB_')
            if vba_start > 0:
                # Extract some code for preview
                code_end = min(vba_start + 2000, len(content))
                code_preview = content[vba_start:code_end].decode('utf-8', errors='ignore')
                
                macro_info = VBAMacroInfo(
                    stream_name='VBA_Module',
                    code_preview=code_preview[:500],
                    code_size=len(code_preview),
                    has_auto_exec=self._check_auto_exec(code_preview),
                    auto_exec_triggers=self._find_auto_exec_triggers(code_preview),
                    suspicious_keywords=self._find_suspicious_keywords(code_preview),
                    iocs_found=self._extract_iocs_from_code(code_preview)
                )
                result.macros.append(macro_info)
        
        # Check for OLE objects
        if b'\x00\x00\x00\x00\x00\x00\x00\x00' in content:  # Package signature
            result.has_ole_objects = True
    
    def _analyze_ooxml(self, content: bytes, result: OfficeAnalysisResult):
        """Analyze OOXML (ZIP-based) Office document."""
        try:
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                names = zf.namelist()
                
                # Check for VBA project
                if 'word/vbaProject.bin' in names or 'xl/vbaProject.bin' in names or 'ppt/vbaProject.bin' in names:
                    result.has_macros = True
                    
                    # Find and analyze vbaProject.bin
                    for name in names:
                        if 'vbaProject.bin' in name:
                            vba_content = zf.read(name)
                            self._analyze_vba_project_bin(vba_content, result)
                
                # Check for external relationships (template injection)
                for name in names:
                    if name.endswith('.rels'):
                        rels_content = zf.read(name).decode('utf-8', errors='ignore')
                        self._check_external_relationships(rels_content, result)
                
                # Check for DDE in document content
                for name in names:
                    if name.endswith('.xml'):
                        try:
                            xml_content = zf.read(name)
                            self._check_dde_ooxml(xml_content, result)
                        except Exception:
                            pass
                
                # Check for embedded objects
                for name in names:
                    if 'embeddings/' in name or 'oleObject' in name:
                        result.has_ole_objects = True
                        obj_content = zf.read(name)
                        self._analyze_embedded_object(name, obj_content, result)
                
                # Extract metadata from core.xml
                if 'docProps/core.xml' in names:
                    core_content = zf.read('docProps/core.xml')
                    result.metadata = self._extract_ooxml_metadata(core_content)
                    
        except Exception as e:
            logger.warning(f"OOXML analysis failed: {e}")
    
    def _analyze_rtf(self, content: bytes, result: OfficeAnalysisResult):
        """Analyze RTF document."""
        content_str = content.decode('utf-8', errors='ignore')
        
        # Check for embedded objects
        if '\\object' in content_str or '\\objdata' in content_str:
            result.has_ole_objects = True
            
            # Try to find object class
            obj_match = re.search(r'\\objclass\s+(\w+)', content_str)
            if obj_match:
                result.ole_objects.append(OLEObjectInfo(
                    object_type=obj_match.group(1),
                    is_suspicious='package' in obj_match.group(1).lower()
                ))
        
        # Check for DDE
        for pattern in self.DDE_PATTERNS:
            if pattern.search(content):
                result.has_dde = True
                break
    
    def _extract_vba_ole(self, ole, result: OfficeAnalysisResult):
        """Extract VBA macro information from OLE file."""
        try:
            import oletools.olevba as olevba
            
            vba_parser = olevba.VBA_Parser(ole=ole)
            
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                if vba_code:
                    macro_info = VBAMacroInfo(
                        stream_name=stream_path or vba_filename or 'Unknown',
                        code_preview=vba_code[:500] if vba_code else None,
                        code_size=len(vba_code) if vba_code else 0,
                        has_auto_exec=self._check_auto_exec(vba_code),
                        auto_exec_triggers=self._find_auto_exec_triggers(vba_code),
                        suspicious_keywords=self._find_suspicious_keywords(vba_code),
                        iocs_found=self._extract_iocs_from_code(vba_code)
                    )
                    result.macros.append(macro_info)
                    
            vba_parser.close()
            
        except ImportError:
            logger.warning("oletools not installed, using basic VBA extraction")
        except Exception as e:
            logger.warning(f"VBA extraction failed: {e}")
    
    def _analyze_vba_project_bin(self, content: bytes, result: OfficeAnalysisResult):
        """Analyze vbaProject.bin file."""
        # Try to extract any readable VBA code
        try:
            import oletools.olevba as olevba
            
            vba_parser = olevba.VBA_Parser(data=content)
            
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                if vba_code:
                    macro_info = VBAMacroInfo(
                        stream_name=stream_path or vba_filename or 'vbaProject.bin',
                        code_preview=vba_code[:500],
                        code_size=len(vba_code),
                        has_auto_exec=self._check_auto_exec(vba_code),
                        auto_exec_triggers=self._find_auto_exec_triggers(vba_code),
                        suspicious_keywords=self._find_suspicious_keywords(vba_code),
                        iocs_found=self._extract_iocs_from_code(vba_code)
                    )
                    result.macros.append(macro_info)
                    
            vba_parser.close()
            
        except ImportError:
            # Basic analysis
            content_str = content.decode('utf-8', errors='ignore')
            if 'Attribute VB_' in content_str or 'Sub ' in content_str:
                result.macros.append(VBAMacroInfo(
                    stream_name='vbaProject.bin',
                    code_preview=content_str[:500],
                    code_size=len(content),
                    has_auto_exec=self._check_auto_exec(content_str),
                    auto_exec_triggers=self._find_auto_exec_triggers(content_str),
                    suspicious_keywords=self._find_suspicious_keywords(content_str),
                    iocs_found=[]
                ))
        except Exception:
            pass
    
    def _check_external_relationships(self, rels_content: str, result: OfficeAnalysisResult):
        """Check for external relationships (template injection)."""
        try:
            root = ET.fromstring(rels_content)
            
            for rel in root.iter():
                target_mode = rel.get('TargetMode', '')
                target = rel.get('Target', '')
                rel_type = rel.get('Type', '')
                
                if target_mode == 'External':
                    result.has_external_links = True
                    result.external_links.append(target)
                    
                    # Check for template injection
                    if 'attachedTemplate' in rel_type or 'template' in rel_type.lower():
                        result.template_injection = True
                        result.template_url = target
                    
        except Exception:
            pass
    
    def _check_dde_ooxml(self, content: bytes, result: OfficeAnalysisResult):
        """Check for DDE in OOXML content."""
        for pattern in self.DDE_PATTERNS:
            if pattern.search(content):
                result.has_dde = True
                
                # Try to extract DDE command
                match = re.search(rb'DDEAUTO\s*"?([^"]+)"?\s*"?([^"]*)"?', content, re.IGNORECASE)
                if match:
                    result.dde_links.append(match.group(0).decode('utf-8', errors='ignore'))
                break
    
    def _extract_ole_objects(self, ole, result: OfficeAnalysisResult):
        """Extract information about embedded OLE objects."""
        try:
            for entry in ole.listdir():
                path = '/'.join(entry)
                
                if 'ObjectPool' in path or 'Embedding' in path:
                    result.has_ole_objects = True
                    
                    # Try to get object info
                    obj_info = OLEObjectInfo(
                        object_type=entry[-1] if entry else 'Unknown',
                        filename=path,
                        is_suspicious=False
                    )
                    
                    # Check for suspicious objects
                    if 'Package' in path:
                        obj_info.is_suspicious = True
                        obj_info.risk_reason = "Package object can contain any file type"
                    
                    result.ole_objects.append(obj_info)
                    
        except Exception:
            pass
    
    def _analyze_embedded_object(self, name: str, content: bytes, result: OfficeAnalysisResult):
        """Analyze an embedded object."""
        obj_info = OLEObjectInfo(
            object_type='Embedded',
            filename=name,
            size=len(content),
            is_suspicious=False
        )
        
        # Check content for executable
        if content[:2] == b'MZ':
            obj_info.is_suspicious = True
            obj_info.risk_reason = "Embedded executable detected"
        elif content[:4] == b'PK\x03\x04':
            obj_info.object_type = 'ZIP Archive'
        
        result.ole_objects.append(obj_info)
    
    def _extract_ole_metadata(self, ole) -> Optional[FileMetadata]:
        """Extract metadata from OLE document."""
        try:
            meta = ole.get_metadata()
            
            return FileMetadata(
                author=meta.author if hasattr(meta, 'author') else None,
                title=meta.title if hasattr(meta, 'title') else None,
                subject=meta.subject if hasattr(meta, 'subject') else None,
                keywords=meta.keywords if hasattr(meta, 'keywords') else None,
                created_date=meta.create_time if hasattr(meta, 'create_time') else None,
                modified_date=meta.last_saved_time if hasattr(meta, 'last_saved_time') else None,
                last_saved_by=meta.last_saved_by if hasattr(meta, 'last_saved_by') else None,
                company=meta.company if hasattr(meta, 'company') else None,
            )
        except Exception:
            return None
    
    def _extract_ooxml_metadata(self, content: bytes) -> Optional[FileMetadata]:
        """Extract metadata from OOXML core.xml."""
        try:
            root = ET.fromstring(content)
            
            # Namespace handling
            ns = {
                'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                'dc': 'http://purl.org/dc/elements/1.1/',
                'dcterms': 'http://purl.org/dc/terms/',
            }
            
            def get_text(xpath):
                elem = root.find(xpath, ns)
                return elem.text if elem is not None else None
            
            return FileMetadata(
                author=get_text('.//dc:creator'),
                title=get_text('.//dc:title'),
                subject=get_text('.//dc:subject'),
                keywords=get_text('.//cp:keywords'),
                last_saved_by=get_text('.//cp:lastModifiedBy'),
            )
        except Exception:
            return None
    
    def _check_auto_exec(self, code: str) -> bool:
        """Check if code contains auto-execute triggers."""
        code_lower = code.lower()
        return any(trigger in code_lower for trigger in self.AUTO_EXEC_TRIGGERS)
    
    def _find_auto_exec_triggers(self, code: str) -> List[str]:
        """Find specific auto-execute trigger names in code."""
        found = []
        code_lower = code.lower()
        
        for trigger in self.AUTO_EXEC_TRIGGERS:
            if trigger in code_lower:
                found.append(trigger)
        
        return found
    
    def _find_suspicious_keywords(self, code: str) -> List[str]:
        """Find suspicious keywords in VBA code."""
        found = []
        code_lower = code.lower()
        
        for keyword in self.SUSPICIOUS_VBA_KEYWORDS:
            if keyword in code_lower:
                found.append(keyword)
        
        return found
    
    def _extract_iocs_from_code(self, code: str) -> List[str]:
        """Extract IOCs (URLs, IPs) from macro code."""
        iocs = []
        
        # URLs
        url_pattern = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
        iocs.extend(url_pattern.findall(code))
        
        # IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        iocs.extend(ip_pattern.findall(code))
        
        return list(set(iocs))[:20]  # Dedupe and limit
