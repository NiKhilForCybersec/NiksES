"""
NiksES IOC Export

Export IOCs for blocking/hunting.
"""

from typing import List

from app.models.analysis import AnalysisResult, ExtractedIOCs


def export_iocs(analysis: AnalysisResult, defang: bool = True) -> str:
    """
    Export all IOCs as plain text list.
    
    Args:
        analysis: AnalysisResult to export
        defang: Defang URLs/IPs for safe handling
        
    Returns:
        IOC list as string (one per line)
    """
    # TODO: Implement in Session 7
    raise NotImplementedError


def defang_iocs(iocs: ExtractedIOCs) -> ExtractedIOCs:
    """
    Defang all IOCs for safe handling.
    
    Args:
        iocs: ExtractedIOCs to defang
        
    Returns:
        Defanged ExtractedIOCs
    """
    # TODO: Implement in Session 7
    raise NotImplementedError


def defang_url(url: str) -> str:
    """Defang URL: https://evil.com -> hxxps[://]evil[.]com"""
    # TODO: Implement in Session 7
    raise NotImplementedError


def defang_ip(ip: str) -> str:
    """Defang IP: 1.2.3.4 -> 1[.]2[.]3[.]4"""
    # TODO: Implement in Session 7
    raise NotImplementedError


def defang_domain(domain: str) -> str:
    """Defang domain: evil.com -> evil[.]com"""
    # TODO: Implement in Session 7
    raise NotImplementedError
