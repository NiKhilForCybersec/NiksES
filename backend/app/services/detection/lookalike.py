"""
NiksES Lookalike Domain Detector

Detects domain impersonation using:
- Levenshtein edit distance
- Homoglyph/Unicode confusable detection
- Brand keyword matching
- Common typosquatting patterns
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)


# =============================================================================
# HOMOGLYPH / CONFUSABLE CHARACTER MAPPINGS
# =============================================================================
# Characters that look similar to ASCII letters

HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', 'ａ', '@'],  # Cyrillic а, Greek alpha, etc. (NOT ASCII 'a')
    'b': ['Ь', 'ь', 'Ƅ', 'ƅ', 'ｂ'],
    'c': ['с', 'ϲ', 'ᴄ', 'ⅽ', 'ｃ'],  # Cyrillic с
    'd': ['ԁ', 'ⅾ', 'ｄ'],
    'e': ['е', 'ё', 'ε', 'ℯ', 'ｅ'],  # Cyrillic е
    'g': ['ɡ', 'ց', 'ｇ'],
    'h': ['һ', 'ｈ'],  # Cyrillic һ
    'i': ['і', 'ι', 'ɪ', '1', '!', 'ｉ'],  # Cyrillic і, Greek iota, number 1 (NOT ASCII 'l')
    'j': ['ј', 'ｊ'],  # Cyrillic ј
    'k': ['κ', 'ｋ'],
    'l': ['1', '|', 'ⅼ', 'ｌ', 'ı'],  # Number 1, pipe (NOT ASCII 'i')
    'm': ['м', 'ｍ'],  # Cyrillic м (removed 'rn' - that's a different technique)
    'n': ['п', 'ո', 'ｎ'],
    'o': ['о', 'ο', '0', 'ｏ'],  # Cyrillic о, Greek omicron, zero
    'p': ['р', 'ρ', 'ｐ'],  # Cyrillic р, Greek rho
    'q': ['ԛ', 'ｑ'],
    'r': ['г', 'ｒ'],
    's': ['ѕ', 'ｓ'],  # Cyrillic ѕ
    't': ['т', 'ｔ'],
    'u': ['υ', 'ц', 'ｕ'],
    'v': ['ν', 'ѵ', 'ｖ'],  # Greek nu
    'w': ['ω', 'ｗ'],
    'x': ['х', 'χ', 'ｘ'],  # Cyrillic х, Greek chi
    'y': ['у', 'γ', 'ｙ'],  # Cyrillic у
    'z': ['ᴢ', 'ｚ'],
}

# Reverse mapping for normalization
HOMOGLYPH_TO_ASCII = {}
for ascii_char, confusables in HOMOGLYPHS.items():
    for confusable in confusables:
        HOMOGLYPH_TO_ASCII[confusable] = ascii_char


# =============================================================================
# BRAND TARGETS FOR LOOKALIKE DETECTION
# =============================================================================

BRAND_DOMAINS = {
    "microsoft": {
        "legitimate": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com", "azure.com"],
        "keywords": ["microsoft", "msft", "office", "outlook", "azure", "onedrive", "sharepoint", "teams"],
    },
    "google": {
        "legitimate": ["google.com", "gmail.com", "googleapis.com", "googlemail.com", "youtube.com"],
        "keywords": ["google", "gmail", "goog", "youtube", "gdrive"],
    },
    "amazon": {
        "legitimate": ["amazon.com", "amazon.co.uk", "amazonaws.com", "aws.amazon.com", "prime.amazon.com"],
        "keywords": ["amazon", "amzn", "aws", "prime"],
    },
    "paypal": {
        "legitimate": ["paypal.com", "paypal.me"],
        "keywords": ["paypal", "pypal"],
    },
    "apple": {
        "legitimate": ["apple.com", "icloud.com", "me.com", "itunes.com"],
        "keywords": ["apple", "icloud", "itunes", "appstore"],
    },
    "facebook": {
        "legitimate": ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"],
        "keywords": ["facebook", "fb", "meta", "instagram", "whatsapp"],
    },
    "netflix": {
        "legitimate": ["netflix.com"],
        "keywords": ["netflix", "netfix"],
    },
    "bank_of_america": {
        "legitimate": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bankofamerica", "bofa", "boa"],
    },
    "chase": {
        "legitimate": ["chase.com", "jpmorganchase.com"],
        "keywords": ["chase", "jpmorgan"],
    },
    "wells_fargo": {
        "legitimate": ["wellsfargo.com", "wf.com"],
        "keywords": ["wellsfargo", "wells-fargo"],
    },
    "dhl": {
        "legitimate": ["dhl.com", "dhl.de"],
        "keywords": ["dhl"],
    },
    "ups": {
        "legitimate": ["ups.com"],
        "keywords": ["ups"],
    },
    "fedex": {
        "legitimate": ["fedex.com"],
        "keywords": ["fedex", "fed-ex"],
    },
    "usps": {
        "legitimate": ["usps.com"],
        "keywords": ["usps"],
    },
    "linkedin": {
        "legitimate": ["linkedin.com"],
        "keywords": ["linkedin", "linked-in"],
    },
    "dropbox": {
        "legitimate": ["dropbox.com"],
        "keywords": ["dropbox"],
    },
    "docusign": {
        "legitimate": ["docusign.com", "docusign.net"],
        "keywords": ["docusign", "docu-sign"],
    },
}


@dataclass
class LookalikeMatch:
    """A detected lookalike domain."""
    suspicious_domain: str
    target_brand: str
    legitimate_domain: str
    confidence: float
    detection_methods: List[str] = field(default_factory=list)
    edit_distance: Optional[int] = None
    homoglyphs_found: List[str] = field(default_factory=list)
    description: str = ""
    
    def __post_init__(self):
        """Generate description after initialization."""
        if not self.description:
            self.description = self._generate_description()
    
    def _generate_description(self) -> str:
        """Generate human-readable description of why this domain is suspicious."""
        parts = []
        brand = self.target_brand.capitalize()
        
        # Main intro
        if self.confidence >= 0.9:
            parts.append(f"This domain is highly likely impersonating {brand}.")
        elif self.confidence >= 0.7:
            parts.append(f"This domain appears to be impersonating {brand}.")
        else:
            parts.append(f"This domain may be attempting to impersonate {brand}.")
        
        # Explain detection methods
        explanations = []
        
        if "exact_homoglyph_match" in self.detection_methods:
            explanations.append(f"uses deceptive Unicode characters that look identical to '{self.legitimate_domain}' but are actually different")
        elif "homoglyph_detected" in self.detection_methods:
            explanations.append("contains Unicode characters designed to visually mimic legitimate letters")
        
        if "brand_keyword_in_domain" in self.detection_methods:
            explanations.append(f"includes the '{brand}' brand name to appear legitimate")
        
        if "suspicious_tld" in self.detection_methods:
            tld = self.suspicious_domain.split('.')[-1] if '.' in self.suspicious_domain else ''
            explanations.append(f"uses a suspicious top-level domain (.{tld}) commonly associated with phishing")
        
        if "typosquatting_pattern" in self.detection_methods:
            explanations.append("uses common typosquatting techniques like character swapping or insertion")
        
        for method in self.detection_methods:
            if method.startswith("edit_distance_"):
                dist = method.split("_")[-1]
                explanations.append(f"is only {dist} character(s) different from the legitimate domain")
        
        if explanations:
            parts.append("It " + ", and ".join(explanations[:2]) + ".")
        
        # Risk assessment
        if self.confidence >= 0.8:
            parts.append("Users may be tricked into entering credentials or sensitive data on a fake website.")
        elif self.confidence >= 0.5:
            parts.append("Exercise caution before clicking any links from this sender.")
        
        return " ".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "suspicious_domain": self.suspicious_domain,
            "target_brand": self.target_brand,
            "legitimate_domain": self.legitimate_domain,
            "confidence": self.confidence,
            "detection_methods": self.detection_methods,
            "edit_distance": self.edit_distance,
            "homoglyphs_found": self.homoglyphs_found,
            "description": self.description,
        }


@dataclass
class LookalikeAnalysisResult:
    """Result of lookalike domain analysis."""
    has_lookalikes: bool = False
    matches: List[LookalikeMatch] = field(default_factory=list)
    highest_confidence: float = 0.0
    primary_target: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_lookalikes": self.has_lookalikes,
            "matches": [m.to_dict() for m in self.matches],
            "highest_confidence": self.highest_confidence,
            "primary_target": self.primary_target,
        }


class LookalikeDetector:
    """
    Detects lookalike/typosquatting domains.
    
    Detection methods:
    1. Levenshtein edit distance to known brands
    2. Homoglyph/Unicode confusable detection
    3. Brand keyword in non-brand domain
    4. Common typosquatting patterns
    """
    
    def __init__(self, custom_brands: Optional[Dict[str, Dict]] = None):
        """
        Initialize detector.
        
        Args:
            custom_brands: Additional brand definitions to check
        """
        self.brands = BRAND_DOMAINS.copy()
        if custom_brands:
            self.brands.update(custom_brands)
    
    def analyze_domain(self, domain: str) -> LookalikeAnalysisResult:
        """
        Analyze a single domain for lookalike patterns.
        
        Args:
            domain: Domain to analyze
            
        Returns:
            LookalikeAnalysisResult
        """
        result = LookalikeAnalysisResult()
        domain_lower = domain.lower().strip()
        
        # Early exit: Check if this is a legitimate domain for ANY brand
        # This prevents false positives for subdomains like mail.microsoft.com
        for brand_id, brand_info in self.brands.items():
            legitimate_domains = brand_info["legitimate"]
            # Exact match
            if domain_lower in legitimate_domains:
                return result  # Empty result - not a lookalike
            # Subdomain of legitimate domain (e.g., mail.microsoft.com)
            if any(domain_lower.endswith(f".{legit}") for legit in legitimate_domains):
                return result  # Empty result - not a lookalike
        
        # Extract base domain (remove TLD)
        domain_parts = domain_lower.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[:-1])
            tld = domain_parts[-1]
        else:
            base_domain = domain_lower
            tld = ""
        
        # Check against each brand
        for brand_id, brand_info in self.brands.items():
            legitimate_domains = brand_info["legitimate"]
            keywords = brand_info["keywords"]
            
            match = self._check_brand_lookalike(
                domain_lower, base_domain, tld,
                brand_id, legitimate_domains, keywords
            )
            
            if match and match.confidence > 0.4:
                result.matches.append(match)
        
        # Sort by confidence
        result.matches.sort(key=lambda m: m.confidence, reverse=True)
        
        if result.matches:
            result.has_lookalikes = True
            result.highest_confidence = result.matches[0].confidence
            result.primary_target = result.matches[0].target_brand
        
        return result
    
    def analyze_domains(self, domains: List[str]) -> List[LookalikeAnalysisResult]:
        """Analyze multiple domains."""
        return [self.analyze_domain(d) for d in domains]
    
    def _check_brand_lookalike(
        self,
        domain: str,
        base_domain: str,
        tld: str,
        brand_id: str,
        legitimate_domains: List[str],
        keywords: List[str],
    ) -> Optional[LookalikeMatch]:
        """Check if domain is a lookalike for a specific brand."""
        
        methods = []
        confidence = 0.0
        edit_distance = None
        homoglyphs = []
        
        # Normalize domain (replace homoglyphs)
        normalized = self._normalize_homoglyphs(domain)
        normalized_base = self._normalize_homoglyphs(base_domain)
        
        # Check if homoglyphs were replaced
        if normalized != domain:
            homoglyphs = self._find_homoglyphs(domain)
            methods.append("homoglyph_detected")
            confidence += 0.4
        
        # Check Levenshtein distance to legitimate domains
        for legit in legitimate_domains:
            legit_base = legit.split('.')[0]
            
            # Compare normalized versions
            dist = self._levenshtein_distance(normalized_base, legit_base)
            
            if dist == 0 and normalized != domain:
                # Exact match after normalization = homoglyph attack
                confidence = max(confidence, 0.95)
                edit_distance = 0
                methods.append("exact_homoglyph_match")
            elif dist <= 2 and len(legit_base) > 3:
                # Small edit distance
                if dist == 1:
                    confidence = max(confidence, 0.85)
                elif dist == 2:
                    confidence = max(confidence, 0.70)
                edit_distance = dist
                methods.append(f"edit_distance_{dist}")
        
        # Check if brand keyword appears in suspicious domain
        # Use normalized_base to catch homoglyph attacks (e.g., micr0soft -> microsoft)
        for keyword in keywords:
            # Check normalized version - this catches homoglyph attacks
            if keyword in normalized_base:
                # Keyword present but domain isn't legitimate
                if not any(domain == legit or domain.endswith(f".{legit}") for legit in legitimate_domains):
                    # Higher confidence if homoglyphs were used to hide the keyword
                    if homoglyphs:
                        confidence = max(confidence, 0.90)
                    else:
                        confidence = max(confidence, 0.80)
                    methods.append("brand_keyword_in_domain")
                    break
        
        # Check for common typosquatting patterns
        typo_confidence = self._check_typosquatting_patterns(domain, legitimate_domains)
        if typo_confidence > 0:
            confidence = max(confidence, typo_confidence)
            methods.append("typosquatting_pattern")
        
        # Check suspicious TLDs
        suspicious_tlds = {'xyz', 'top', 'club', 'work', 'click', 'link', 'info', 'site', 'online', 'icu', 'buzz'}
        if tld in suspicious_tlds:
            # Boost confidence if suspicious TLD combined with brand keyword
            # Check both original and normalized to catch homoglyph attacks
            for keyword in keywords:
                if keyword in base_domain or keyword in normalized_base:
                    confidence = min(1.0, confidence + 0.1)
                    methods.append("suspicious_tld")
                    break
        
        if confidence > 0.4 and methods:
            return LookalikeMatch(
                suspicious_domain=domain,
                target_brand=brand_id,
                legitimate_domain=legitimate_domains[0],
                confidence=min(1.0, confidence),
                detection_methods=list(set(methods)),
                edit_distance=edit_distance,
                homoglyphs_found=homoglyphs,
            )
        
        return None
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyphs with their ASCII equivalents."""
        result = []
        for char in text:
            if char in HOMOGLYPH_TO_ASCII:
                result.append(HOMOGLYPH_TO_ASCII[char])
            else:
                result.append(char)
        return ''.join(result)
    
    def _find_homoglyphs(self, text: str) -> List[str]:
        """Find homoglyph characters in text."""
        found = []
        for char in text:
            if char in HOMOGLYPH_TO_ASCII:
                found.append(f"{char} → {HOMOGLYPH_TO_ASCII[char]}")
        return found
    
    @lru_cache(maxsize=1000)
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_typosquatting_patterns(
        self,
        domain: str,
        legitimate_domains: List[str],
    ) -> float:
        """Check for common typosquatting patterns."""
        
        # Extract the main domain part (excluding subdomains and TLD)
        # e.g., "mail.microsoft.com" -> "microsoft"
        # e.g., "microsoft-login.xyz" -> "microsoft-login"
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            # Get the second-level domain (main part before TLD)
            main_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
        else:
            main_domain = domain
        
        for legit in legitimate_domains:
            legit_base = legit.split('.')[0]
            
            # Check if legitimate domain appears as fake subdomain
            # e.g., microsoft.com.evil.xyz (legit domain used as subdomain prefix)
            if f"{legit}." in domain and domain != legit:
                # Make sure it's not a real subdomain of the legitimate domain
                if not domain.endswith(f".{legit}"):
                    return 0.85
            
            # Check for hyphenated versions in the main domain
            # e.g., microsoft-support.xyz
            if f"{legit_base}-" in main_domain or f"-{legit_base}" in main_domain:
                return 0.75
            
            # Check for doubled letters (common typo) in main domain only
            # e.g., microsooft.com
            for i, char in enumerate(legit_base[:-1]):
                doubled = legit_base[:i+1] + char + legit_base[i+1:]
                # Match if doubled version IS the main domain (not just substring)
                if doubled == main_domain:
                    return 0.70
            
            # Check for missing letters in main domain only
            # e.g., "microsft.com" (missing 'o')
            # Only match if the missing-letter version IS the main domain
            for i in range(len(legit_base)):
                missing = legit_base[:i] + legit_base[i+1:]
                # Require exact match or very close match to avoid false positives
                if len(missing) > 4 and missing == main_domain:
                    return 0.65
        
        return 0.0


# Singleton
_lookalike_detector: Optional[LookalikeDetector] = None


def get_lookalike_detector(custom_brands: Optional[Dict] = None) -> LookalikeDetector:
    """Get or create lookalike detector singleton."""
    global _lookalike_detector
    if _lookalike_detector is None:
        _lookalike_detector = LookalikeDetector(custom_brands)
    return _lookalike_detector
