"""
NiksES Header Analyzer

Comprehensive email header analysis:
- Received chain parsing with delay calculation
- SPF/DKIM/DMARC extraction
- Originating IP detection
- Header anomaly detection
- Security header analysis
"""

import re
import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from app.models.email import ReceivedHop, AuthenticationResult
from app.utils.exceptions import ParsingError

logger = logging.getLogger(__name__)


def analyze_headers(raw_headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive header analysis.
    
    Returns:
        Dictionary with:
        - received_chain: List of hops
        - auth_results: SPF/DKIM/DMARC results
        - originating_ip: First external IP
        - anomalies: List of detected anomalies
        - security_headers: Analysis of security headers
        - timing_analysis: Delivery timing info
    """
    result = {
        "received_chain": [],
        "auth_results": {},
        "originating_ip": None,
        "anomalies": [],
        "security_headers": {},
        "timing_analysis": {},
        "header_summary": {},
    }
    
    try:
        # Extract Received chain
        result["received_chain"] = extract_received_chain(raw_headers)
        
        # Extract originating IP
        if result["received_chain"]:
            result["originating_ip"] = extract_originating_ip(result["received_chain"])
        
        # Parse authentication results
        result["auth_results"] = extract_auth_results(raw_headers)
        
        # Detect anomalies
        result["anomalies"] = detect_header_anomalies(raw_headers, result["received_chain"])
        
        # Analyze security headers
        result["security_headers"] = analyze_security_headers(raw_headers)
        
        # Timing analysis
        result["timing_analysis"] = analyze_delivery_timing(result["received_chain"])
        
        # Header summary
        result["header_summary"] = build_header_summary(raw_headers, result)
        
    except Exception as e:
        logger.error(f"Header analysis error: {e}")
        result["anomalies"].append(f"Header analysis error: {str(e)}")
    
    return result


def extract_received_chain(headers: Dict[str, Any]) -> List[ReceivedHop]:
    """
    Extract and parse Received header chain.
    """
    received_headers = []
    
    # Get Received headers (can be single or multiple)
    received = headers.get("received", headers.get("Received", ""))
    
    if isinstance(received, str):
        received_headers = [received] if received else []
    elif isinstance(received, list):
        received_headers = received
    
    hops = []
    previous_timestamp = None
    
    for idx, header in enumerate(received_headers):
        try:
            hop = parse_received_header(header, idx + 1)
            
            # Calculate delay from previous hop
            if previous_timestamp and hop.timestamp:
                try:
                    delay = (previous_timestamp - hop.timestamp).total_seconds()
                    hop.delay_seconds = max(0, delay)
                except:
                    pass
            
            if hop.timestamp:
                previous_timestamp = hop.timestamp
            
            hops.append(hop)
        except Exception as e:
            logger.debug(f"Failed to parse Received header: {e}")
    
    return hops


def parse_received_header(header_value: str, hop_number: int = 0) -> ReceivedHop:
    """Parse a single Received header value."""
    
    hop = ReceivedHop(hop_number=hop_number, raw_header=header_value)
    
    # Extract "from" host and IP
    from_match = re.search(
        r'from\s+([^\s\(\)]+)(?:\s+\(([^)]+)\))?',
        header_value, re.IGNORECASE
    )
    if from_match:
        hop.from_host = from_match.group(1).strip()
        extra = from_match.group(2) or ""
        
        # Extract IP from the extra info
        ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', extra)
        if ip_match:
            hop.from_ip = ip_match.group(1)
        else:
            # Try to find IP in the hostname part
            ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', hop.from_host or "")
            if ip_match:
                hop.from_ip = ip_match.group(1)
    
    # Extract "by" host
    by_match = re.search(r'by\s+([^\s;]+)', header_value, re.IGNORECASE)
    if by_match:
        hop.by_host = by_match.group(1).strip()
    
    # Extract protocol
    with_match = re.search(r'with\s+(\w+)', header_value, re.IGNORECASE)
    if with_match:
        hop.protocol = with_match.group(1).upper()
    
    # Extract timestamp
    # Look for common date formats at end of header
    date_patterns = [
        r';\s*(.+?(?:\d{4}|\d{2}:\d{2}:\d{2}).+?)$',
        r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
    ]
    
    for pattern in date_patterns:
        date_match = re.search(pattern, header_value)
        if date_match:
            try:
                date_str = date_match.group(1).strip()
                # Remove timezone abbreviations that parsedate_to_datetime can't handle
                date_str = re.sub(r'\s*\([^)]+\)\s*$', '', date_str)
                hop.timestamp = parsedate_to_datetime(date_str)
                break
            except Exception:
                pass
    
    return hop


def extract_auth_results(headers: Dict[str, Any]) -> Dict[str, AuthenticationResult]:
    """
    Extract SPF, DKIM, DMARC results from headers.
    """
    results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }
    
    # Check Authentication-Results header
    auth_results = headers.get("authentication-results", headers.get("Authentication-Results", ""))
    if auth_results:
        parsed = _parse_authentication_results_header(auth_results)
        for auth in parsed:
            key = auth.mechanism.lower()
            if key in results:
                results[key] = auth
    
    # Check Received-SPF header
    received_spf = headers.get("received-spf", headers.get("Received-SPF", ""))
    if received_spf and not results["spf"]:
        spf_result = _parse_received_spf(received_spf)
        if spf_result:
            results["spf"] = spf_result
    
    # Check DKIM-Signature header
    dkim_sig = headers.get("dkim-signature", headers.get("DKIM-Signature", ""))
    if dkim_sig and not results["dkim"]:
        # If DKIM signature exists but no auth result, mark as "present"
        results["dkim"] = AuthenticationResult(
            mechanism="DKIM",
            result="present",
            details="DKIM signature present in headers"
        )
    
    return results


def _parse_authentication_results_header(header_value: str) -> List[AuthenticationResult]:
    """Parse Authentication-Results header value."""
    results = []
    
    if not header_value:
        return results
    
    # Handle multiple values
    if isinstance(header_value, list):
        header_value = " ".join(header_value)
    
    # Parse each mechanism
    mechanisms = ["spf", "dkim", "dmarc", "dara"]
    
    for mech in mechanisms:
        # Pattern: mechanism=result
        pattern = rf'{mech}=(\w+)'
        match = re.search(pattern, header_value, re.IGNORECASE)
        
        if match:
            result_value = match.group(1).lower()
            
            # Extract additional details
            details = ""
            
            # Look for header.i= for DKIM
            if mech == "dkim":
                header_i = re.search(r'header\.i=([^\s;]+)', header_value)
                if header_i:
                    details = f"header.i={header_i.group(1)}"
            
            # Look for domain info
            domain_match = re.search(rf'{mech}=[^\s]+\s+\([^)]+\)', header_value, re.IGNORECASE)
            if domain_match:
                details = domain_match.group(0)
            
            results.append(AuthenticationResult(
                mechanism=mech.upper(),
                result=result_value,
                details=details or f"From Authentication-Results header"
            ))
    
    return results


def _parse_received_spf(header_value: str) -> Optional[AuthenticationResult]:
    """Parse Received-SPF header."""
    if not header_value:
        return None
    
    # Format: pass (details...) or fail (details...)
    match = re.match(r'^(\w+)\s*(.*)$', header_value.strip())
    if match:
        result = match.group(1).lower()
        details = match.group(2).strip()
        
        return AuthenticationResult(
            mechanism="SPF",
            result=result,
            details=details or header_value
        )
    
    return None


def extract_originating_ip(received_chain: List[ReceivedHop]) -> Optional[str]:
    """
    Extract originating IP from Received chain.
    
    The originating IP is typically the first external/public IP
    in the chain (working backwards from the recipient).
    """
    # Internal/private IP patterns
    internal_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^::1$',
        r'^fe80:',
        r'^fc00:',
    ]
    
    def is_internal(ip: str) -> bool:
        return any(re.match(p, ip) for p in internal_patterns)
    
    # Work through the chain to find the first external IP
    for hop in received_chain:
        if hop.from_ip:
            if not is_internal(hop.from_ip):
                return hop.from_ip
    
    return None


def detect_header_anomalies(headers: Dict[str, Any], received_chain: List[ReceivedHop]) -> List[str]:
    """
    Detect suspicious header anomalies.
    """
    anomalies = []
    
    # Check for missing Date header
    if not headers.get("date") and not headers.get("Date"):
        anomalies.append("Missing Date header")
    
    # Check for missing Message-ID
    if not headers.get("message-id") and not headers.get("Message-ID"):
        anomalies.append("Missing Message-ID header")
    
    # Check for suspicious X-Mailer
    x_mailer = headers.get("x-mailer", headers.get("X-Mailer", ""))
    suspicious_mailers = ["PHPMailer", "leaf", "The Bat!", "Mass Mailer"]
    if any(m.lower() in x_mailer.lower() for m in suspicious_mailers):
        anomalies.append(f"Suspicious X-Mailer: {x_mailer}")
    
    # Check for missing From header
    if not headers.get("from") and not headers.get("From"):
        anomalies.append("Missing From header")
    
    # Check for empty subject
    subject = headers.get("subject", headers.get("Subject", ""))
    if not subject or subject.strip() == "":
        anomalies.append("Empty or missing Subject")
    
    # Check for Re: without In-Reply-To
    if subject and subject.lower().startswith("re:"):
        if not headers.get("in-reply-to") and not headers.get("In-Reply-To"):
            anomalies.append("Reply (Re:) without In-Reply-To header")
    
    # Check received chain for time anomalies
    if received_chain:
        # Check for future dates - use timezone-aware datetime
        now = datetime.now(timezone.utc)
        for hop in received_chain:
            if hop.timestamp:
                try:
                    # Make timestamp timezone-aware if it's naive
                    ts = hop.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts > now:
                        anomalies.append(f"Future timestamp in Received header: {hop.timestamp}")
                except Exception:
                    pass  # Skip comparison if there's any issue
        
        # Check for excessive delays (>1 hour)
        for hop in received_chain:
            if hop.delay_seconds and hop.delay_seconds > 3600:
                anomalies.append(f"Excessive delivery delay: {hop.delay_seconds/60:.0f} minutes")
    
    # Check for multiple From addresses
    from_header = headers.get("from", headers.get("From", ""))
    if isinstance(from_header, str) and from_header.count("@") > 1:
        anomalies.append("Multiple email addresses in From header")
    
    return anomalies


def analyze_security_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze security-related headers.
    """
    security = {
        "has_arc": False,
        "has_dkim_signature": False,
        "has_list_unsubscribe": False,
        "content_type": None,
        "x_originating_ip": None,
        "x_spam_status": None,
        "x_spam_score": None,
        "precedence": None,
    }
    
    # ARC headers
    if headers.get("arc-seal") or headers.get("ARC-Seal"):
        security["has_arc"] = True
    
    # DKIM signature
    if headers.get("dkim-signature") or headers.get("DKIM-Signature"):
        security["has_dkim_signature"] = True
    
    # List-Unsubscribe (indicates legitimate mailing list)
    if headers.get("list-unsubscribe") or headers.get("List-Unsubscribe"):
        security["has_list_unsubscribe"] = True
    
    # Content-Type
    security["content_type"] = headers.get("content-type", headers.get("Content-Type"))
    
    # X-Originating-IP
    x_orig_ip = headers.get("x-originating-ip", headers.get("X-Originating-IP"))
    if x_orig_ip:
        # Extract IP from brackets if present
        ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', str(x_orig_ip))
        if ip_match:
            security["x_originating_ip"] = ip_match.group(1)
    
    # Spam status/score
    security["x_spam_status"] = headers.get("x-spam-status", headers.get("X-Spam-Status"))
    security["x_spam_score"] = headers.get("x-spam-score", headers.get("X-Spam-Score"))
    
    # Precedence (bulk, junk, list)
    security["precedence"] = headers.get("precedence", headers.get("Precedence"))
    
    return security


def analyze_delivery_timing(received_chain: List[ReceivedHop]) -> Dict[str, Any]:
    """
    Analyze email delivery timing.
    """
    timing = {
        "total_hops": len(received_chain),
        "total_delay_seconds": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "average_delay": 0,
        "max_delay": 0,
        "suspicious_timing": False,
    }
    
    if not received_chain:
        return timing
    
    timestamps = [h.timestamp for h in received_chain if h.timestamp]
    delays = [h.delay_seconds for h in received_chain if h.delay_seconds is not None]
    
    if timestamps:
        timing["first_timestamp"] = min(timestamps).isoformat()
        timing["last_timestamp"] = max(timestamps).isoformat()
    
    if delays:
        timing["total_delay_seconds"] = sum(delays)
        timing["average_delay"] = sum(delays) / len(delays)
        timing["max_delay"] = max(delays)
        
        # Flag if max delay > 1 hour or total delay > 24 hours
        if timing["max_delay"] > 3600 or timing["total_delay_seconds"] > 86400:
            timing["suspicious_timing"] = True
    
    return timing


def build_header_summary(headers: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a summary of header analysis for display.
    """
    auth = analysis.get("auth_results", {})
    
    spf_result = "none"
    dkim_result = "none"
    dmarc_result = "none"
    
    if auth.get("spf"):
        spf_result = auth["spf"].result if hasattr(auth["spf"], 'result') else str(auth["spf"])
    if auth.get("dkim"):
        dkim_result = auth["dkim"].result if hasattr(auth["dkim"], 'result') else str(auth["dkim"])
    if auth.get("dmarc"):
        dmarc_result = auth["dmarc"].result if hasattr(auth["dmarc"], 'result') else str(auth["dmarc"])
    
    return {
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "originating_ip": analysis.get("originating_ip"),
        "hop_count": len(analysis.get("received_chain", [])),
        "anomaly_count": len(analysis.get("anomalies", [])),
        "has_security_headers": analysis.get("security_headers", {}).get("has_arc", False) or 
                               analysis.get("security_headers", {}).get("has_dkim_signature", False),
    }
