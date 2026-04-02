"""
NiksES Text & URL Normalizer

Pre-processing utilities that strip evasion techniques before analysis:
- Zero-width character removal
- Homoglyph normalization
- RTL override stripping
- Punycode/IDN decoding
- URL deobfuscation (IP encoding, @-sign, data URIs, open redirects)
- Soft hyphen / invisible character removal
"""

import re
import unicodedata
import logging
from typing import List, Tuple, Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


# =============================================================================
# ZERO-WIDTH & INVISIBLE CHARACTERS
# =============================================================================

ZERO_WIDTH_CHARS = {
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # Zero-width no-break space (BOM)
    '\u2060',  # Word joiner
    '\u00ad',  # Soft hyphen
    '\u034f',  # Combining grapheme joiner
    '\u180e',  # Mongolian vowel separator
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\u2066',  # Left-to-right isolate
    '\u2067',  # Right-to-left isolate
    '\u2068',  # First strong isolate
    '\u2069',  # Pop directional isolate
}

# RTL/LTR override characters used for filename spoofing
BIDI_OVERRIDE_CHARS = {
    '\u202a',  # Left-to-right embedding
    '\u202b',  # Right-to-left embedding
    '\u202c',  # Pop directional formatting
    '\u202d',  # Left-to-right override
    '\u202e',  # Right-to-left override (most dangerous)
    '\u200f',  # Right-to-left mark
    '\u200e',  # Left-to-right mark
}

# Unicode tag characters (invisible)
TAG_CHARS = set(chr(c) for c in range(0xE0001, 0xE0080))


# =============================================================================
# KNOWN OPEN REDIRECT PATTERNS
# =============================================================================

OPEN_REDIRECT_PATTERNS = [
    # Google
    (r'google\.com/url\?', 'q'),
    (r'google\.com/url\?', 'url'),
    # YouTube
    (r'youtube\.com/redirect\?', 'q'),
    # LinkedIn
    (r'linkedin\.com/redir/redirect', 'url'),
    # Facebook
    (r'facebook\.com/l\.php\?', 'u'),
    (r'l\.facebook\.com/', 'u'),
    # Microsoft
    (r'go\.microsoft\.com/', 'url'),
    # Yahoo
    (r'yahoo\.com/r/\?', 'url'),
    # Bing
    (r'bing\.com/ck/', 'u'),
]


# =============================================================================
# TEXT NORMALIZATION
# =============================================================================

def strip_zero_width(text: str) -> str:
    """Remove all zero-width and invisible characters from text."""
    if not text:
        return text
    return ''.join(c for c in text if c not in ZERO_WIDTH_CHARS and c not in TAG_CHARS)


def strip_bidi_overrides(text: str) -> str:
    """Remove bidirectional override characters (RTL override attack prevention)."""
    if not text:
        return text
    return ''.join(c for c in text if c not in BIDI_OVERRIDE_CHARS)


def normalize_unicode(text: str) -> str:
    """Normalize Unicode to NFKC form (collapses fullwidth, mathematical variants, etc.)."""
    if not text:
        return text
    return unicodedata.normalize('NFKC', text)


def detect_mixed_scripts(text: str) -> List[str]:
    """Detect mixed Unicode scripts in text (e.g., Latin + Cyrillic = likely homoglyph attack)."""
    scripts = set()
    findings = []

    for char in text:
        if char.isalpha():
            try:
                script = unicodedata.name(char, '').split()[0]
                if script in ('LATIN', 'CYRILLIC', 'GREEK'):
                    scripts.add(script)
            except (ValueError, IndexError):
                pass

    if len(scripts) > 1:
        findings.append(f"Mixed scripts detected: {', '.join(sorted(scripts))}")

    return findings


def full_text_normalize(text: str) -> str:
    """Apply all text normalizations in correct order."""
    if not text:
        return text
    text = strip_zero_width(text)
    text = strip_bidi_overrides(text)
    text = normalize_unicode(text)
    return text


def detect_evasion_techniques(text: str) -> List[Dict[str, str]]:
    """Detect evasion techniques in text, returning findings."""
    findings = []

    if not text:
        return findings

    # Check for zero-width characters
    zw_count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    if zw_count > 0:
        findings.append({
            "technique": "zero_width_chars",
            "description": f"Found {zw_count} zero-width/invisible characters (evasion technique)",
            "severity": "medium",
        })

    # Check for RTL override
    bidi_count = sum(1 for c in text if c in BIDI_OVERRIDE_CHARS)
    if bidi_count > 0:
        findings.append({
            "technique": "rtl_override",
            "description": f"Found {bidi_count} bidirectional override characters (filename/text spoofing)",
            "severity": "high",
        })

    # Check for mixed scripts
    mixed = detect_mixed_scripts(text)
    if mixed:
        findings.append({
            "technique": "mixed_scripts",
            "description": mixed[0],
            "severity": "high",
        })

    # Check for Unicode tag characters
    tag_count = sum(1 for c in text if c in TAG_CHARS)
    if tag_count > 0:
        findings.append({
            "technique": "unicode_tags",
            "description": f"Found {tag_count} Unicode tag characters (invisible text injection)",
            "severity": "medium",
        })

    return findings


# =============================================================================
# URL NORMALIZATION & DEOBFUSCATION
# =============================================================================

def decode_punycode_domain(domain: str) -> Tuple[str, bool]:
    """Decode punycode/IDN domain. Returns (decoded_domain, was_punycode)."""
    if not domain:
        return domain, False

    try:
        if 'xn--' in domain.lower():
            parts = domain.split('.')
            decoded_parts = []
            has_punycode = False
            for part in parts:
                if part.lower().startswith('xn--'):
                    try:
                        decoded_parts.append(part.encode('ascii').decode('idna'))
                        has_punycode = True
                    except (UnicodeError, UnicodeDecodeError):
                        decoded_parts.append(part)
                else:
                    decoded_parts.append(part)
            return '.'.join(decoded_parts), has_punycode
    except Exception:
        pass

    return domain, False


def normalize_ip_url(url: str) -> Optional[str]:
    """Detect and normalize IP-based URL obfuscation (decimal, hex, octal)."""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        host = parsed.hostname or ''

        # Decimal IP: http://3627729444/
        if host.isdigit():
            ip_int = int(host)
            if 0 < ip_int <= 0xFFFFFFFF:
                octets = [
                    (ip_int >> 24) & 0xFF,
                    (ip_int >> 16) & 0xFF,
                    (ip_int >> 8) & 0xFF,
                    ip_int & 0xFF,
                ]
                return f"{parsed.scheme}://{'.'.join(map(str, octets))}{parsed.path or '/'}"

        # Hex IP: 0xD83AC224
        if host.lower().startswith('0x'):
            try:
                ip_int = int(host, 16)
                if 0 < ip_int <= 0xFFFFFFFF:
                    octets = [
                        (ip_int >> 24) & 0xFF,
                        (ip_int >> 16) & 0xFF,
                        (ip_int >> 8) & 0xFF,
                        ip_int & 0xFF,
                    ]
                    return f"{parsed.scheme}://{'.'.join(map(str, octets))}{parsed.path or '/'}"
            except ValueError:
                pass

        # Octal notation in individual octets: 0330.072.0302.044
        parts = host.split('.')
        if len(parts) == 4:
            octets = []
            has_octal_or_hex = False
            for part in parts:
                try:
                    if part.lower().startswith('0x'):
                        octets.append(int(part, 16))
                        has_octal_or_hex = True
                    elif part.startswith('0') and len(part) > 1 and part.isdigit():
                        octets.append(int(part, 8))
                        has_octal_or_hex = True
                    else:
                        octets.append(int(part))
                except ValueError:
                    break

            if len(octets) == 4 and has_octal_or_hex and all(0 <= o <= 255 for o in octets):
                return f"{parsed.scheme}://{'.'.join(map(str, octets))}{parsed.path or '/'}"

    except Exception:
        pass

    return None


def detect_at_sign_url(url: str) -> Optional[str]:
    """Detect @-sign URL trick: http://legit.com@evil.com/path → real host is evil.com."""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        if parsed.username or '@' in (parsed.netloc or ''):
            # The real host is after the @
            actual_host = parsed.hostname
            full_netloc = parsed.netloc
            if '@' in full_netloc:
                fake_part = full_netloc.split('@')[0]
                return f"URL contains @-sign trick: displayed as '{fake_part}' but actual host is '{actual_host}'"
    except Exception:
        pass
    return None


def detect_data_uri(text: str) -> List[str]:
    """Detect data: URIs that could embed phishing pages."""
    findings = []
    data_uri_pattern = re.compile(r'data:\s*[a-zA-Z]+/[a-zA-Z0-9+.-]+\s*[;,]', re.IGNORECASE)
    matches = data_uri_pattern.findall(text or '')
    for match in matches:
        findings.append(f"Data URI detected: {match[:50]}... (could embed phishing content)")
    return findings


def detect_javascript_uri(text: str) -> List[str]:
    """Detect javascript: URIs in links."""
    findings = []
    js_pattern = re.compile(r'(?:href|src|action)\s*=\s*["\']?\s*javascript:', re.IGNORECASE)
    matches = js_pattern.findall(text or '')
    for match in matches:
        findings.append("javascript: URI detected in link (potential XSS/phishing)")
    return findings


def extract_open_redirect_target(url: str) -> Optional[str]:
    """Check if URL is an open redirect on a trusted domain, extract target."""
    url_lower = url.lower()

    for pattern, param_name in OPEN_REDIRECT_PATTERNS:
        if re.search(pattern, url_lower):
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                target = params.get(param_name, [None])[0]
                if target and ('http' in target.lower() or '.' in target):
                    return target
            except Exception:
                pass

    return None


def full_url_decode(url: str) -> str:
    """Recursively decode URL encoding until stable (handles double/triple encoding)."""
    if not url:
        return url

    prev = url
    for _ in range(5):  # Max 5 decode rounds
        decoded = unquote(prev)
        if decoded == prev:
            break
        prev = decoded

    return prev


def analyze_url_safety(url: str) -> List[Dict[str, str]]:
    """Run all URL safety checks, returning findings."""
    findings = []

    if not url:
        return findings

    # Fully decode first
    decoded_url = full_url_decode(url)

    # Check for @-sign trick
    at_sign = detect_at_sign_url(decoded_url)
    if at_sign:
        findings.append({
            "technique": "at_sign_url",
            "description": at_sign,
            "severity": "critical",
        })

    # Check for IP obfuscation
    normalized_ip = normalize_ip_url(decoded_url)
    if normalized_ip:
        findings.append({
            "technique": "ip_obfuscation",
            "description": f"IP-based URL obfuscation detected. Resolved to: {normalized_ip}",
            "severity": "high",
        })

    # Check for open redirect
    redirect_target = extract_open_redirect_target(decoded_url)
    if redirect_target:
        findings.append({
            "technique": "open_redirect",
            "description": f"Open redirect on trusted domain. Real target: {redirect_target[:100]}",
            "severity": "high",
        })

    # Check for punycode/IDN
    try:
        parsed = urlparse(decoded_url if '://' in decoded_url else f'http://{decoded_url}')
        hostname = parsed.hostname or ''
        decoded_domain, was_punycode = decode_punycode_domain(hostname)
        if was_punycode:
            findings.append({
                "technique": "punycode_idn",
                "description": f"Punycode domain: {hostname} decodes to '{decoded_domain}' (homograph attack)",
                "severity": "critical",
            })
    except Exception:
        pass

    # Check for data URI
    if decoded_url.lower().startswith('data:'):
        findings.append({
            "technique": "data_uri",
            "description": "data: URI detected — could embed entire phishing page inline",
            "severity": "critical",
        })

    # Check for javascript URI
    if decoded_url.lower().startswith('javascript:'):
        findings.append({
            "technique": "javascript_uri",
            "description": "javascript: URI detected — code execution in browser",
            "severity": "critical",
        })

    return findings


# =============================================================================
# EMAIL-SPECIFIC CHECKS
# =============================================================================

def detect_display_name_email_trick(display_name: str, actual_email: str) -> Optional[Dict[str, str]]:
    """Detect when display name contains an email address to trick recipients.
    e.g., From: "ceo@company.com" <attacker@evil.com>
    """
    if not display_name:
        return None

    # Check if display name looks like an email address
    email_in_display = re.search(r'[\w.+-]+@[\w.-]+\.\w+', display_name)
    if email_in_display:
        fake_email = email_in_display.group()
        if fake_email.lower() != actual_email.lower():
            return {
                "technique": "display_name_email_trick",
                "description": f"Display name contains fake email '{fake_email}' but actual sender is '{actual_email}'",
                "severity": "critical",
            }

    return None


def detect_reply_to_mismatch(from_email: str, reply_to: str) -> Optional[Dict[str, str]]:
    """Detect From/Reply-To domain mismatch."""
    if not from_email or not reply_to:
        return None

    try:
        from_domain = from_email.split('@')[-1].lower()
        reply_domain = reply_to.split('@')[-1].lower()

        # Free email providers used as reply-to for corporate-looking From
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'protonmail.com', 'mail.com', 'yandex.com', 'tutanota.com',
            'zoho.com', 'icloud.com', 'gmx.com', 'inbox.com',
        }

        if from_domain != reply_domain:
            severity = "high"
            description = f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'"

            # Extra suspicious if reply-to is a free provider but from is corporate
            if reply_domain in free_providers and from_domain not in free_providers:
                severity = "critical"
                description += f" — corporate sender with free email reply-to (likely phishing)"

            return {
                "technique": "reply_to_mismatch",
                "description": description,
                "severity": severity,
            }
    except Exception:
        pass

    return None


def detect_hidden_html_content(html: str) -> List[Dict[str, str]]:
    """Detect hidden text in HTML (Bayesian poisoning, invisible content)."""
    findings = []

    if not html:
        return findings

    # Font-size: 0 or 1px
    tiny_font = re.findall(r'font-size\s*:\s*[01](?:px|pt|em)', html, re.IGNORECASE)
    if tiny_font:
        findings.append({
            "technique": "hidden_text_tiny_font",
            "description": f"Found {len(tiny_font)} elements with font-size: 0/1px (hidden text to fool classifiers)",
            "severity": "medium",
        })

    # display: none with content
    hidden_divs = re.findall(r'display\s*:\s*none[^>]*>[^<]+<', html, re.IGNORECASE)
    if hidden_divs:
        findings.append({
            "technique": "hidden_text_display_none",
            "description": f"Found {len(hidden_divs)} hidden elements with content (Bayesian poisoning)",
            "severity": "medium",
        })

    # visibility: hidden
    invisible = re.findall(r'visibility\s*:\s*hidden[^>]*>[^<]+<', html, re.IGNORECASE)
    if invisible:
        findings.append({
            "technique": "hidden_text_visibility",
            "description": f"Found {len(invisible)} invisible elements with content",
            "severity": "medium",
        })

    # White/near-white text (color: #fff, color: white, color: #ffffff)
    white_text = re.findall(
        r'color\s*:\s*(?:#fff(?:fff)?|white|#fefefe|#fdfdfd|rgba?\s*\(\s*255\s*,\s*255\s*,\s*255)',
        html, re.IGNORECASE
    )
    if white_text:
        findings.append({
            "technique": "hidden_text_white",
            "description": f"Found {len(white_text)} white/near-white text elements (hidden content)",
            "severity": "medium",
        })

    return findings


# =============================================================================
# SMS-SPECIFIC CHECKS
# =============================================================================

def normalize_sms_text(text: str) -> str:
    """Normalize SMS text: strip zero-width chars, reassemble split URLs."""
    if not text:
        return text

    # Strip zero-width chars that could split URLs
    normalized = strip_zero_width(text)
    normalized = strip_bidi_overrides(normalized)
    normalized = normalize_unicode(normalized)

    return normalized
