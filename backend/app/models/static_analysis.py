"""
NiksES Static Analysis Models

Data models for attachment static analysis results.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


class ThreatLevel(str, Enum):
    """Threat level classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class FileCategory(str, Enum):
    """File category classification."""
    EXECUTABLE = "executable"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    SCRIPT = "script"
    IMAGE = "image"
    MEDIA = "media"
    DATA = "data"
    UNKNOWN = "unknown"


class SuspiciousIndicator(BaseModel):
    """A suspicious indicator found during analysis."""
    indicator_type: str = Field(..., description="Type of indicator")
    description: str = Field(..., description="Human-readable description")
    severity: ThreatLevel = Field(ThreatLevel.MEDIUM, description="Severity level")
    evidence: Optional[str] = Field(None, description="Supporting evidence")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique")


class ExtractedString(BaseModel):
    """An interesting string extracted from the file."""
    value: str = Field(..., description="The extracted string")
    string_type: str = Field(..., description="Type: url, ip, email, path, registry, suspicious")
    offset: Optional[int] = Field(None, description="Offset in file")
    context: Optional[str] = Field(None, description="Surrounding context")


class FileMetadata(BaseModel):
    """Extracted file metadata."""
    author: Optional[str] = Field(None, description="Document author")
    creator: Optional[str] = Field(None, description="Creator application")
    producer: Optional[str] = Field(None, description="Producer application")
    title: Optional[str] = Field(None, description="Document title")
    subject: Optional[str] = Field(None, description="Document subject")
    keywords: Optional[str] = Field(None, description="Keywords")
    created_date: Optional[datetime] = Field(None, description="Creation date")
    modified_date: Optional[datetime] = Field(None, description="Last modified date")
    company: Optional[str] = Field(None, description="Company name")
    last_saved_by: Optional[str] = Field(None, description="Last saved by")
    revision: Optional[int] = Field(None, description="Revision number")
    custom_properties: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# OFFICE DOCUMENT ANALYSIS
# ============================================================================

class VBAMacroInfo(BaseModel):
    """VBA macro information."""
    stream_name: str = Field(..., description="OLE stream name")
    code_preview: Optional[str] = Field(None, description="First 500 chars of code")
    code_size: int = Field(0, description="Size of macro code")
    has_auto_exec: bool = Field(False, description="Has auto-execute trigger")
    auto_exec_triggers: List[str] = Field(default_factory=list, description="Auto-exec function names")
    suspicious_keywords: List[str] = Field(default_factory=list, description="Suspicious keywords found")
    iocs_found: List[str] = Field(default_factory=list, description="IOCs in macro code")


class OLEObjectInfo(BaseModel):
    """Embedded OLE object information."""
    object_type: str = Field(..., description="Type of embedded object")
    clsid: Optional[str] = Field(None, description="Class ID")
    filename: Optional[str] = Field(None, description="Original filename if available")
    size: int = Field(0, description="Object size in bytes")
    is_suspicious: bool = Field(False, description="Flagged as suspicious")
    risk_reason: Optional[str] = Field(None, description="Why it's suspicious")


class OfficeAnalysisResult(BaseModel):
    """Results from Office document analysis."""
    has_macros: bool = Field(False, description="Contains VBA macros")
    macros: List[VBAMacroInfo] = Field(default_factory=list)
    has_external_links: bool = Field(False, description="Has external links/relationships")
    external_links: List[str] = Field(default_factory=list)
    has_ole_objects: bool = Field(False, description="Contains OLE objects")
    ole_objects: List[OLEObjectInfo] = Field(default_factory=list)
    has_dde: bool = Field(False, description="Contains DDE links")
    dde_links: List[str] = Field(default_factory=list)
    template_injection: bool = Field(False, description="Remote template injection detected")
    template_url: Optional[str] = Field(None, description="Remote template URL")
    metadata: Optional[FileMetadata] = Field(None)


# ============================================================================
# PDF ANALYSIS
# ============================================================================

class PDFJavaScriptInfo(BaseModel):
    """JavaScript in PDF."""
    code_preview: Optional[str] = Field(None, description="First 500 chars")
    code_size: int = Field(0, description="Size of JS code")
    suspicious_functions: List[str] = Field(default_factory=list)
    urls_found: List[str] = Field(default_factory=list)


class PDFActionInfo(BaseModel):
    """PDF action (auto-open, etc.)."""
    action_type: str = Field(..., description="Action type: OpenAction, AA, etc.")
    target: Optional[str] = Field(None, description="Action target")
    is_suspicious: bool = Field(False)


class PDFAnalysisResult(BaseModel):
    """Results from PDF analysis."""
    has_javascript: bool = Field(False)
    javascript: List[PDFJavaScriptInfo] = Field(default_factory=list)
    has_embedded_files: bool = Field(False)
    embedded_files: List[str] = Field(default_factory=list)
    has_auto_actions: bool = Field(False)
    actions: List[PDFActionInfo] = Field(default_factory=list)
    has_launch_action: bool = Field(False, description="Can launch external programs")
    launch_targets: List[str] = Field(default_factory=list)
    has_encrypted_streams: bool = Field(False)
    has_object_streams: bool = Field(False)
    suspicious_names: List[str] = Field(default_factory=list, description="/Names with suspicious content")
    metadata: Optional[FileMetadata] = Field(None)
    page_count: int = Field(0)
    pdf_version: Optional[str] = Field(None)


# ============================================================================
# PE (EXECUTABLE) ANALYSIS
# ============================================================================

class PEImportInfo(BaseModel):
    """Imported DLL and functions."""
    dll_name: str = Field(..., description="DLL name")
    functions: List[str] = Field(default_factory=list, description="Imported functions")
    suspicious_functions: List[str] = Field(default_factory=list)


class PESectionInfo(BaseModel):
    """PE section information."""
    name: str = Field(..., description="Section name")
    virtual_size: int = Field(0)
    raw_size: int = Field(0)
    entropy: float = Field(0.0)
    is_executable: bool = Field(False)
    is_writable: bool = Field(False)
    characteristics: int = Field(0)


class PEAnalysisResult(BaseModel):
    """Results from PE/executable analysis."""
    # Basic info
    machine_type: Optional[str] = Field(None, description="x86, x64, etc.")
    subsystem: Optional[str] = Field(None, description="GUI, Console, etc.")
    compilation_timestamp: Optional[datetime] = Field(None)
    is_dll: bool = Field(False)
    is_driver: bool = Field(False)
    is_64bit: bool = Field(False)
    
    # Security features
    has_aslr: bool = Field(False)
    has_dep: bool = Field(False)
    has_seh: bool = Field(False)
    has_cfg: bool = Field(False)
    is_signed: bool = Field(False)
    signature_valid: bool = Field(False)
    signer: Optional[str] = Field(None)
    
    # Imports
    imports: List[PEImportInfo] = Field(default_factory=list)
    suspicious_imports: List[str] = Field(default_factory=list)
    total_imports: int = Field(0)
    
    # Sections
    sections: List[PESectionInfo] = Field(default_factory=list)
    suspicious_sections: List[str] = Field(default_factory=list)
    
    # Packing
    is_packed: bool = Field(False)
    packer_name: Optional[str] = Field(None)
    packing_indicators: List[str] = Field(default_factory=list)
    
    # Resources
    has_resources: bool = Field(False)
    resource_types: List[str] = Field(default_factory=list)
    suspicious_resources: List[str] = Field(default_factory=list)
    
    # Version info
    file_version: Optional[str] = Field(None)
    product_version: Optional[str] = Field(None)
    original_filename: Optional[str] = Field(None)
    internal_name: Optional[str] = Field(None)
    company_name: Optional[str] = Field(None)
    product_name: Optional[str] = Field(None)


# ============================================================================
# ARCHIVE ANALYSIS
# ============================================================================

class ArchiveEntry(BaseModel):
    """Entry in an archive."""
    filename: str = Field(..., description="Filename in archive")
    size_compressed: int = Field(0)
    size_uncompressed: int = Field(0)
    is_encrypted: bool = Field(False)
    is_directory: bool = Field(False)
    is_executable: bool = Field(False)
    is_suspicious: bool = Field(False)
    suspicion_reason: Optional[str] = Field(None)


class ArchiveAnalysisResult(BaseModel):
    """Results from archive analysis."""
    archive_type: str = Field(..., description="zip, rar, 7z, tar, etc.")
    is_password_protected: bool = Field(False)
    total_files: int = Field(0)
    total_directories: int = Field(0)
    total_size_uncompressed: int = Field(0)
    compression_ratio: float = Field(0.0)
    entries: List[ArchiveEntry] = Field(default_factory=list)
    has_nested_archives: bool = Field(False)
    nested_archive_count: int = Field(0)
    has_executables: bool = Field(False)
    executable_count: int = Field(0)
    has_scripts: bool = Field(False)
    has_office_docs: bool = Field(False)
    suspicious_entries: List[str] = Field(default_factory=list)
    max_depth: int = Field(1, description="Nesting depth")


# ============================================================================
# COMBINED STATIC ANALYSIS RESULT
# ============================================================================

class EntropyAnalysis(BaseModel):
    """File entropy analysis."""
    overall_entropy: float = Field(0.0, description="Overall file entropy (0-8)")
    is_high_entropy: bool = Field(False, description="Entropy > 7.0")
    is_likely_encrypted: bool = Field(False, description="Entropy > 7.5")
    is_likely_packed: bool = Field(False, description="High entropy executable")
    section_entropies: Dict[str, float] = Field(default_factory=dict)


class StaticAnalysisResult(BaseModel):
    """Complete static analysis result for an attachment."""
    # Basic file info
    filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., description="File size in bytes")
    file_category: FileCategory = Field(FileCategory.UNKNOWN)
    
    # Hashes
    md5: str = Field(..., description="MD5 hash")
    sha1: str = Field(..., description="SHA1 hash")
    sha256: str = Field(..., description="SHA256 hash")
    ssdeep: Optional[str] = Field(None, description="Fuzzy hash")
    imphash: Optional[str] = Field(None, description="Import hash for PE files")
    
    # File type detection
    extension: str = Field(..., description="File extension")
    claimed_type: str = Field(..., description="MIME type from Content-Type")
    detected_type: str = Field(..., description="Actual type from magic bytes")
    type_mismatch: bool = Field(False, description="Extension doesn't match content")
    
    # Double extension detection
    has_double_extension: bool = Field(False)
    double_extension_details: Optional[str] = Field(None)
    
    # Entropy
    entropy: EntropyAnalysis = Field(default_factory=EntropyAnalysis)
    
    # Extracted strings
    strings_summary: Dict[str, int] = Field(default_factory=dict, description="Count by type")
    interesting_strings: List[ExtractedString] = Field(default_factory=list, max_length=100)
    urls_found: List[str] = Field(default_factory=list)
    ips_found: List[str] = Field(default_factory=list)
    emails_found: List[str] = Field(default_factory=list)
    
    # Type-specific analysis
    office_analysis: Optional[OfficeAnalysisResult] = Field(None)
    pdf_analysis: Optional[PDFAnalysisResult] = Field(None)
    pe_analysis: Optional[PEAnalysisResult] = Field(None)
    archive_analysis: Optional[ArchiveAnalysisResult] = Field(None)
    
    # Suspicious indicators
    indicators: List[SuspiciousIndicator] = Field(default_factory=list)
    
    # Overall assessment
    threat_level: ThreatLevel = Field(ThreatLevel.UNKNOWN)
    threat_score: int = Field(0, ge=0, le=100, description="0-100 threat score")
    threat_summary: str = Field("", description="Human-readable summary")
    
    # Analysis metadata
    analysis_time_ms: int = Field(0, description="Time taken for analysis")
    analysis_errors: List[str] = Field(default_factory=list)
