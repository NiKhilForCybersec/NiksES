"""
NiksES STIX/IOC Export

Export IOCs in STIX 2.1 format for threat intelligence sharing.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.models.analysis import AnalysisResult, ExtractedIOCs

logger = logging.getLogger(__name__)


# STIX 2.1 object types
STIX_SPEC_VERSION = "2.1"


def generate_stix_id(type_name: str) -> str:
    """Generate STIX 2.1 compliant ID."""
    return f"{type_name}--{uuid.uuid4()}"


def create_stix_bundle(objects: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create STIX 2.1 bundle."""
    return {
        "type": "bundle",
        "id": generate_stix_id("bundle"),
        "objects": objects,
    }


def create_indicator(
    pattern: str,
    pattern_type: str,
    name: str,
    description: str,
    labels: List[str],
    valid_from: datetime,
    confidence: int = 80,
) -> Dict[str, Any]:
    """Create STIX 2.1 Indicator object."""
    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": generate_stix_id("indicator"),
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": valid_from.isoformat() + "Z",
        "labels": labels,
        "confidence": confidence,
    }


def create_observable(
    type_name: str,
    value: str,
    **properties
) -> Dict[str, Any]:
    """Create STIX 2.1 Observable object."""
    obj = {
        "type": type_name,
        "spec_version": STIX_SPEC_VERSION,
        "id": generate_stix_id(type_name),
    }
    
    # Add type-specific properties
    if type_name == "ipv4-addr":
        obj["value"] = value
    elif type_name == "ipv6-addr":
        obj["value"] = value
    elif type_name == "domain-name":
        obj["value"] = value
    elif type_name == "url":
        obj["value"] = value
    elif type_name == "email-addr":
        obj["value"] = value
    elif type_name == "file":
        obj["hashes"] = properties.get("hashes", {})
        if "name" in properties:
            obj["name"] = properties["name"]
    
    return obj


def create_relationship(
    source_id: str,
    target_id: str,
    relationship_type: str,
) -> Dict[str, Any]:
    """Create STIX 2.1 Relationship object."""
    return {
        "type": "relationship",
        "spec_version": STIX_SPEC_VERSION,
        "id": generate_stix_id("relationship"),
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }


def create_malware_analysis(
    analysis: AnalysisResult,
) -> Dict[str, Any]:
    """Create STIX 2.1 Malware Analysis object."""
    return {
        "type": "malware-analysis",
        "spec_version": STIX_SPEC_VERSION,
        "id": generate_stix_id("malware-analysis"),
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "product": "NiksES",
        "version": "1.0",
        "result": "malicious" if analysis.detection.risk_score >= 60 else "suspicious" if analysis.detection.risk_score >= 20 else "benign",
        "analysis_started": analysis.analyzed_at.isoformat() + "Z",
    }


def export_to_stix(
    analysis: AnalysisResult,
    include_observables: bool = True,
    include_indicators: bool = True,
) -> str:
    """
    Export analysis to STIX 2.1 bundle.
    
    Args:
        analysis: Complete analysis result
        include_observables: Include observable objects
        include_indicators: Include indicator objects
        
    Returns:
        STIX 2.1 bundle as JSON string
    """
    objects = []
    iocs = analysis.iocs
    valid_from = analysis.analyzed_at
    
    # Determine labels based on classification
    classification = analysis.detection.primary_classification.value
    labels = ["malicious-activity"]
    
    if "phishing" in classification:
        labels.append("phishing")
    if "malware" in classification:
        labels.append("malware")
    if "bec" in classification:
        labels.append("fraud")
    
    # Add malware analysis object
    objects.append(create_malware_analysis(analysis))
    
    # Process domains
    for domain in iocs.domains:
        if include_observables:
            obs = create_observable("domain-name", domain)
            objects.append(obs)
        
        if include_indicators:
            pattern = f"[domain-name:value = '{domain}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious Domain: {domain}",
                description=f"Domain associated with {classification}",
                labels=labels,
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    # Process URLs
    for url in iocs.urls:
        if include_observables:
            obs = create_observable("url", url)
            objects.append(obs)
        
        if include_indicators:
            # Escape single quotes in URL
            escaped_url = url.replace("'", "\\'")
            pattern = f"[url:value = '{escaped_url}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious URL",
                description=f"URL associated with {classification}",
                labels=labels,
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    # Process IPs
    for ip in iocs.ips:
        ip_type = "ipv6-addr" if ":" in ip else "ipv4-addr"
        
        if include_observables:
            obs = create_observable(ip_type, ip)
            objects.append(obs)
        
        if include_indicators:
            pattern = f"[{ip_type}:value = '{ip}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious IP: {ip}",
                description=f"IP address associated with {classification}",
                labels=labels,
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    # Process email addresses
    for email in iocs.email_addresses:
        if include_observables:
            obs = create_observable("email-addr", email)
            objects.append(obs)
        
        if include_indicators:
            pattern = f"[email-addr:value = '{email}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious Email: {email}",
                description=f"Email address associated with {classification}",
                labels=labels,
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    # Process file hashes
    for sha256 in iocs.file_hashes_sha256:
        if include_observables:
            obs = create_observable("file", sha256, hashes={"SHA-256": sha256})
            objects.append(obs)
        
        if include_indicators:
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious File Hash",
                description=f"File hash associated with {classification}",
                labels=labels + ["malware"],
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    for md5 in iocs.file_hashes_md5:
        if include_indicators:
            pattern = f"[file:hashes.MD5 = '{md5}']"
            indicator = create_indicator(
                pattern=pattern,
                pattern_type="stix",
                name=f"Malicious File Hash (MD5)",
                description=f"File hash associated with {classification}",
                labels=labels + ["malware"],
                valid_from=valid_from,
            )
            objects.append(indicator)
    
    bundle = create_stix_bundle(objects)
    return json.dumps(bundle, indent=2)


def export_iocs_simple(analysis: AnalysisResult) -> str:
    """
    Export IOCs in simple newline-separated format.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        IOCs as plain text, one per line
    """
    lines = []
    iocs = analysis.iocs
    
    lines.append("# NiksES IOC Export")
    lines.append(f"# Analysis ID: {analysis.analysis_id}")
    lines.append(f"# Date: {analysis.analyzed_at.isoformat()}")
    lines.append(f"# Risk Score: {analysis.detection.risk_score}/100")
    lines.append("")
    
    if iocs.domains:
        lines.append("# Domains")
        lines.extend(iocs.domains)
        lines.append("")
    
    if iocs.urls:
        lines.append("# URLs")
        lines.extend(iocs.urls)
        lines.append("")
    
    if iocs.ips:
        lines.append("# IP Addresses")
        lines.extend(iocs.ips)
        lines.append("")
    
    if iocs.email_addresses:
        lines.append("# Email Addresses")
        lines.extend(iocs.email_addresses)
        lines.append("")
    
    if iocs.file_hashes_sha256:
        lines.append("# SHA256 Hashes")
        lines.extend(iocs.file_hashes_sha256)
        lines.append("")
    
    if iocs.file_hashes_md5:
        lines.append("# MD5 Hashes")
        lines.extend(iocs.file_hashes_md5)
        lines.append("")
    
    return "\n".join(lines)
