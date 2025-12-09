"""
NiksES Static Analysis Module

Comprehensive static analysis for email attachments without execution.

Features:
- File type detection via magic bytes
- Hash calculation (MD5, SHA1, SHA256, ssdeep)
- Entropy analysis for encryption/packing detection
- String extraction (URLs, IPs, emails, suspicious patterns)
- Office document analysis (VBA macros, DDE, OLE objects)
- PDF analysis (JavaScript, auto-actions, embedded files)
- PE analysis (imports, sections, packing)
- Archive analysis (contents, nested archives, executables)

Usage:
    from app.services.static_analysis import StaticAnalyzer
    
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(
        content=file_bytes,
        filename="suspicious.docx",
        claimed_content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    
    print(f"Threat Level: {result.threat_level}")
    print(f"Score: {result.threat_score}/100")
    print(f"Summary: {result.threat_summary}")
"""

from app.services.static_analysis.analyzer import StaticAnalyzer
from app.services.static_analysis.magic_detector import MagicDetector
from app.services.static_analysis.string_extractor import StringExtractor
from app.services.static_analysis.office_analyzer import OfficeAnalyzer
from app.services.static_analysis.pdf_analyzer import PDFAnalyzer
from app.services.static_analysis.pe_analyzer import PEAnalyzer
from app.services.static_analysis.archive_analyzer import ArchiveAnalyzer

__all__ = [
    'StaticAnalyzer',
    'MagicDetector',
    'StringExtractor',
    'OfficeAnalyzer',
    'PDFAnalyzer',
    'PEAnalyzer',
    'ArchiveAnalyzer',
]
