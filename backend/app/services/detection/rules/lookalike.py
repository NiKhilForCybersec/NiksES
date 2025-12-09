"""
NiksES Lookalike Domain Detection Rules

Rules for detecting domain spoofing including typosquatting,
homoglyph attacks, and subdomain abuse.
"""

import re
from typing import Optional, List, Tuple

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel
from app.utils.constants import BRAND_TARGETS

from .base import DetectionRule, RuleMatch, register_rule


# Homoglyph mappings (characters that look similar)
# Maps legitimate characters to their visual lookalikes used in attacks
HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', '@', '4'],  # Cyrillic a, Latin alpha, Greek alpha
    'c': ['с', 'ϲ', '('],  # Cyrillic c
    'e': ['е', 'ё', 'ε', '3'],  # Cyrillic e
    'i': ['і', 'ι', '1', '|', '!'],  # Cyrillic i, Greek iota, number 1
    'l': ['1', 'I', '|', 'і'],  # Number 1 looks like lowercase L
    'o': ['о', 'ο', '0'],  # Cyrillic o, Greek omicron, zero
    'p': ['р', 'ρ'],  # Cyrillic r, Greek rho
    's': ['ѕ', 'ş', '5', '$'],  # Cyrillic dze
    'x': ['х', 'χ'],  # Cyrillic kha, Greek chi
    'y': ['у', 'γ'],  # Cyrillic u
    'n': ['п', 'ո'],  # Cyrillic n
    'm': ['т', 'rn'],  # rn looks like m
    'w': ['vv', 'ѡ'],  # vv looks like w
    'd': ['ԁ', 'ɗ'],  # Cyrillic d
    'g': ['ɡ', 'ց', '9'],  # Different g variants
    'b': ['ь', 'Ь'],  # Cyrillic soft sign
    'h': ['һ', 'н'],  # Cyrillic variants
    'k': ['κ', 'к'],  # Greek kappa, Cyrillic
    't': ['τ', 'т'],  # Greek tau, Cyrillic
    'u': ['υ', 'ц'],  # Greek upsilon
    'v': ['ν', 'ѵ'],  # Greek nu
}

# Common typosquatting patterns
TYPO_PATTERNS = [
    # Missing letters: gogle.com
    (r'(.)\1', r'\1'),  # Double letter removed
    # Adjacent key swaps
    ('qw', 'wq'), ('we', 'ew'), ('er', 're'), ('rt', 'tr'),
    ('ty', 'yt'), ('yu', 'uy'), ('ui', 'iu'), ('io', 'oi'),
    ('as', 'sa'), ('sd', 'ds'), ('df', 'fd'), ('fg', 'gf'),
    ('gh', 'hg'), ('hj', 'jh'), ('jk', 'kj'), ('kl', 'lk'),
    ('zx', 'xz'), ('xc', 'cx'), ('cv', 'vc'), ('vb', 'bv'),
    ('bn', 'nb'), ('nm', 'mn'),
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
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


def check_homoglyphs(domain: str, target: str) -> Tuple[bool, str]:
    """
    Check if domain uses homoglyph substitution to impersonate target.
    
    Requirements:
    1. Domains must be very similar in length (within 2 chars)
    2. Domains must have high character overlap
    3. Only 1-2 homoglyph substitutions allowed
    """
    domain_lower = domain.lower()
    target_lower = target.lower()
    
    # Must be exact match if same string
    if domain_lower == target_lower:
        return False, ""
    
    # Length check - must be very similar (within 2 characters)
    len_diff = abs(len(domain_lower) - len(target_lower))
    if len_diff > 2:
        return False, ""
    
    # Must be same length for homoglyph detection to work properly
    if len(domain_lower) != len(target_lower):
        return False, ""
    
    # Count matches, mismatches, and homoglyphs
    matches = 0
    mismatches = 0
    homoglyph_subs = []
    
    for i, (d_char, t_char) in enumerate(zip(domain_lower, target_lower)):
        if d_char == t_char:
            matches += 1
        else:
            # Check if d_char is a homoglyph of t_char
            if t_char in HOMOGLYPHS and d_char in HOMOGLYPHS[t_char]:
                homoglyph_subs.append((d_char, t_char, i))
            else:
                mismatches += 1
    
    # Requirements for homoglyph attack:
    # 1. At least one homoglyph substitution found
    # 2. No more than 2 homoglyph substitutions
    # 3. No other mismatches (all differences must be homoglyphs)
    # 4. At least 80% of characters must match or be homoglyphs
    
    if len(homoglyph_subs) == 0:
        return False, ""
    
    if len(homoglyph_subs) > 2:
        return False, ""  # Too many substitutions - likely not intentional
    
    if mismatches > 0:
        return False, ""  # Has other differences beyond homoglyphs
    
    min_similarity = 0.8
    similarity = (matches + len(homoglyph_subs)) / len(target_lower)
    if similarity < min_similarity:
        return False, ""
    
    # Valid homoglyph attack detected
    sub = homoglyph_subs[0]
    return True, f"'{sub[0]}' substituted for '{sub[1]}'"


@register_rule
class HomoglyphDomainRule(DetectionRule):
    """Detect domains using homoglyph character substitution."""
    
    rule_id = "LOOK-001"
    name = "Homoglyph Domain"
    description = "Domain uses lookalike characters to impersonate a brand"
    category = "lookalike"
    severity = RiskLevel.CRITICAL
    mitre_technique = "T1583.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain:
            return None
        
        # Extract base domain (remove TLD)
        parts = sender_domain.rsplit('.', 1)
        base_domain = parts[0] if parts else sender_domain
        
        # Check against brand targets
        for brand_id, brand_info in BRAND_TARGETS.items():
            for legit_domain in brand_info.get('legitimate_domains', []):
                legit_parts = legit_domain.rsplit('.', 1)
                legit_base = legit_parts[0] if legit_parts else legit_domain
                
                # Skip if exact match (legitimate)
                if sender_domain == legit_domain:
                    continue
                
                is_homoglyph, detail = check_homoglyphs(base_domain, legit_base)
                
                if is_homoglyph:
                    return self.create_match(
                        evidence=[
                            f"Sender domain: {sender_domain}",
                            f"Impersonates: {legit_domain} ({brand_info['name']})",
                            f"Homoglyph detected: {detail}",
                        ],
                        indicators=[{
                            'type': 'homoglyph_domain',
                            'sender_domain': sender_domain,
                            'target_domain': legit_domain,
                            'brand': brand_info['name'],
                            'technique': 'homoglyph',
                        }],
                    )
        
        return None


@register_rule
class TyposquatDomainRule(DetectionRule):
    """Detect domains using typosquatting (similar spelling)."""
    
    rule_id = "LOOK-002"
    name = "Typosquat Domain"
    description = "Domain is suspiciously similar to a known brand domain"
    category = "lookalike"
    severity = RiskLevel.HIGH
    mitre_technique = "T1583.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain:
            return None
        
        # Extract base domain
        parts = sender_domain.rsplit('.', 1)
        base_domain = parts[0] if parts else sender_domain
        
        # Check against brand targets
        for brand_id, brand_info in BRAND_TARGETS.items():
            for legit_domain in brand_info.get('legitimate_domains', []):
                # Skip if exact match
                if sender_domain == legit_domain:
                    continue
                
                legit_parts = legit_domain.rsplit('.', 1)
                legit_base = legit_parts[0] if legit_parts else legit_domain
                
                # Skip if base domains are identical (different TLD)
                if base_domain == legit_base:
                    continue
                
                # Length must be very similar (typosquats are usually same length ±1)
                len_diff = abs(len(base_domain) - len(legit_base))
                if len_diff > 1:
                    continue
                
                # Calculate edit distance
                distance = levenshtein_distance(base_domain, legit_base)
                
                # Require distance of exactly 1-2 for short domains, scale for longer
                max_distance = 1 if len(legit_base) < 6 else 2
                
                # If very close (1-2 edits) and similar length
                if 1 <= distance <= max_distance and len(legit_base) >= 4:
                    # Calculate similarity ratio
                    similarity = 1 - (distance / max(len(base_domain), len(legit_base)))
                    
                    # Lower threshold for shorter domains since 1-2 char difference is more significant
                    # Short domains (4-5 chars): 0.6 threshold (e.g., 2 edits in 5 chars = 0.6)
                    # Medium domains (6-8 chars): 0.65 threshold (e.g., 2 edits in 6 chars = 0.67)
                    # Long domains (9+ chars): 0.7 threshold
                    if len(legit_base) <= 5:
                        min_similarity = 0.6
                    elif len(legit_base) <= 8:
                        min_similarity = 0.65
                    else:
                        min_similarity = 0.7
                    
                    if similarity < min_similarity:
                        continue
                    
                    return self.create_match(
                        evidence=[
                            f"Sender domain: {sender_domain}",
                            f"Similar to: {legit_domain} ({brand_info['name']})",
                            f"Edit distance: {distance}",
                            f"Similarity: {similarity:.0%}",
                        ],
                        indicators=[{
                            'type': 'typosquat_domain',
                            'sender_domain': sender_domain,
                            'target_domain': legit_domain,
                            'brand': brand_info['name'],
                            'edit_distance': distance,
                            'similarity': similarity,
                        }],
                    )
        
        return None


@register_rule
class SubdomainSpoofRule(DetectionRule):
    """Detect subdomain-based spoofing (paypal.evil.com)."""
    
    rule_id = "LOOK-003"
    name = "Subdomain Spoofing"
    description = "Domain uses brand name as subdomain of unrelated domain"
    category = "lookalike"
    severity = RiskLevel.HIGH
    mitre_technique = "T1583.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain:
            return None
        
        # Split into parts
        parts = sender_domain.split('.')
        
        if len(parts) < 3:
            return None
        
        # Get subdomain (everything before the registered domain)
        subdomain = '.'.join(parts[:-2])
        
        # Check if subdomain contains brand names
        for brand_id, brand_info in BRAND_TARGETS.items():
            brand_name = brand_info['name'].lower()
            
            # Check if brand is in subdomain but not in main domain
            if brand_name in subdomain.lower():
                # Check if main domain is NOT a legitimate domain
                main_domain = '.'.join(parts[-2:])
                if main_domain not in brand_info.get('legitimate_domains', []):
                    return self.create_match(
                        evidence=[
                            f"Sender domain: {sender_domain}",
                            f"Brand '{brand_info['name']}' used as subdomain",
                            f"Actual domain: {main_domain}",
                            "Brand subdomains on unrelated domains are suspicious",
                        ],
                        indicators=[{
                            'type': 'subdomain_spoof',
                            'sender_domain': sender_domain,
                            'brand': brand_info['name'],
                            'actual_domain': main_domain,
                        }],
                    )
        
        return None


@register_rule
class BrandKeywordDomainRule(DetectionRule):
    """Detect domains containing brand keywords but not from the brand."""
    
    rule_id = "LOOK-004"
    name = "Brand Keyword in Domain"
    description = "Domain contains brand keyword but is not a legitimate brand domain"
    category = "lookalike"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1583.001"
    
    # Service-related words that, when combined with brand names, indicate phishing
    SERVICE_KEYWORDS = [
        'support', 'help', 'service', 'account', 'login', 'signin', 'verify',
        'secure', 'security', 'update', 'billing', 'payment', 'recover',
        'password', 'alert', 'notification', 'team', 'admin', 'center',
    ]
    
    # Patterns that indicate legitimate non-brand domains (tech blogs, reviews, etc.)
    LEGITIMATE_PATTERNS = [
        'learn', 'training', 'course', 'academy', 'blog', 'news', 
        'review', 'reviews', 'compare', 'alternative', 'forum', 
        'community', 'stack', 'overflow', 'defend', 'versus', 'vs',
    ]
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain:
            return None
        
        domain_lower = sender_domain.lower()
        
        # Check for legitimate patterns (tech blogs, comparison sites, etc.)
        # Only skip if no brand name is detected
        for pattern in self.LEGITIMATE_PATTERNS:
            if pattern in domain_lower:
                # Check if ANY brand name is also in the domain
                has_brand = False
                for brand_id, brand_info in BRAND_TARGETS.items():
                    if brand_info['name'].lower() in domain_lower:
                        has_brand = True
                        break
                
                # Only skip if no brand is present
                if not has_brand:
                    return None
        
        # Check each brand
        for brand_id, brand_info in BRAND_TARGETS.items():
            legitimate_domains = brand_info.get('legitimate_domains', [])
            
            # Skip if this is a legitimate domain
            if sender_domain in legitimate_domains:
                continue
            
            # Skip if domain is a subdomain of legitimate domain
            is_legit_subdomain = False
            for legit in legitimate_domains:
                if sender_domain.endswith('.' + legit):
                    is_legit_subdomain = True
                    break
            if is_legit_subdomain:
                continue
            
            # Check for brand name in domain
            brand_name = brand_info['name'].lower()
            
            if brand_name in domain_lower:
                # Make sure it's at a word boundary
                idx = domain_lower.find(brand_name)
                valid_before = (idx == 0 or domain_lower[idx-1] in '.-_')
                end_idx = idx + len(brand_name)
                valid_after = (end_idx >= len(domain_lower) or domain_lower[end_idx] in '.-_')
                
                if valid_before and valid_after:
                    # Check if it also contains service keywords (higher suspicion)
                    has_service_word = any(sw in domain_lower for sw in self.SERVICE_KEYWORDS)
                    
                    return self.create_match(
                        evidence=[
                            f"Sender domain: {sender_domain}",
                            f"Contains brand name: '{brand_name}'",
                            f"Not a legitimate {brand_info['name']} domain",
                        ] + ([f"Combined with service keyword (highly suspicious)"] if has_service_word else []),
                        indicators=[{
                            'type': 'brand_keyword_domain',
                            'sender_domain': sender_domain,
                            'keyword': brand_name,
                            'brand': brand_info['name'],
                            'has_service_word': has_service_word,
                        }],
                    )
        
        return None


@register_rule
class URLDomainMismatchRule(DetectionRule):
    """Detect when link text shows one domain but links to another."""
    
    rule_id = "LOOK-005"
    name = "Link Text Domain Mismatch"
    description = "Link displays one domain but actually links to a different domain"
    category = "lookalike"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.body_html:
            return None
        
        # Find links where text looks like a URL but differs from href
        pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*(?:https?://|www\.)[^<]*)</a>'
        matches = re.findall(pattern, email.body_html, re.IGNORECASE)
        
        mismatches = []
        for href, link_text in matches:
            # Extract domains
            try:
                from urllib.parse import urlparse
                href_domain = urlparse(href).netloc.lower()
                
                # Find domain in link text
                text_url_match = re.search(r'(?:https?://)?([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)', link_text, re.IGNORECASE)
                if text_url_match:
                    text_domain = text_url_match.group(1).lower()
                    
                    if href_domain and text_domain and href_domain != text_domain:
                        mismatches.append({
                            'displayed_domain': text_domain,
                            'actual_domain': href_domain,
                            'link_text': link_text[:50],
                        })
            except Exception:
                continue
        
        if mismatches:
            evidence = ["Link text shows different domain than actual link:"]
            for mm in mismatches[:3]:
                evidence.append(f"  - Shows '{mm['displayed_domain']}' but links to '{mm['actual_domain']}'")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'link_text_mismatch',
                    **mm
                } for mm in mismatches],
            )
        
        return None


@register_rule
class LookalikeURLRule(DetectionRule):
    """Detect lookalike domains in URLs."""
    
    rule_id = "LOOK-006"
    name = "Lookalike URL Domain"
    description = "URL contains domain similar to known brands"
    category = "lookalike"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.urls:
            return None
        
        lookalikes = []
        
        for url in email.urls:
            url_domain = url.domain
            if not url_domain:
                continue
            
            # Check against brands
            for brand_id, brand_info in BRAND_TARGETS.items():
                legitimate = brand_info.get('legitimate_domains', [])
                
                # Skip if legitimate
                if url_domain in legitimate:
                    continue
                
                # Skip if subdomain of legitimate
                is_legit_sub = any(url_domain.endswith('.' + leg) for leg in legitimate)
                if is_legit_sub:
                    continue
                
                for legit_domain in legitimate:
                    legit_parts = legit_domain.rsplit('.', 1)
                    legit_base = legit_parts[0]
                    
                    url_parts = url_domain.rsplit('.', 1)
                    url_base = url_parts[0] if url_parts else url_domain
                    
                    # Skip if identical base
                    if url_base == legit_base:
                        continue
                    
                    # Length must be very similar
                    len_diff = abs(len(url_base) - len(legit_base))
                    if len_diff > 1:
                        continue
                    
                    distance = levenshtein_distance(url_base, legit_base)
                    
                    # Must be very similar
                    max_distance = 1 if len(legit_base) < 6 else 2
                    
                    if 1 <= distance <= max_distance and len(legit_base) >= 4:
                        similarity = 1 - (distance / max(len(url_base), len(legit_base)))
                        if similarity < 0.75:
                            continue
                        
                        lookalikes.append({
                            'url': url.url,
                            'domain': url_domain,
                            'similar_to': legit_domain,
                            'brand': brand_info['name'],
                            'similarity': similarity,
                        })
                        break
        
        if lookalikes:
            evidence = ["Lookalike domains found in URLs:"]
            for la in lookalikes[:3]:
                evidence.append(f"  - {la['domain']} (similar to {la['similar_to']}, {la['similarity']:.0%})")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'lookalike_url',
                    **la
                } for la in lookalikes],
            )
        
        return None


@register_rule
class SenderDomainLookalikeRule(DetectionRule):
    """
    Detect sender domains that impersonate known brands using the 
    comprehensive LookalikeDetector service.
    
    This rule uses advanced detection including:
    - Homoglyph substitution (e.g., micr0soft)
    - Typosquatting patterns (e.g., microsft)
    - Brand keyword + suspicious TLD (e.g., microsoft.xyz)
    - Subdomain tricks (e.g., microsoft.com.evil.xyz)
    """
    
    rule_id = "LOOK-007"
    name = "Sender Domain Impersonation"
    description = "Sender domain impersonates a known brand using lookalike techniques"
    category = "lookalike"
    severity = RiskLevel.CRITICAL
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain:
            return None
        
        # Use the LookalikeDetector service for comprehensive analysis
        try:
            from app.services.detection.lookalike import get_lookalike_detector
            detector = get_lookalike_detector()
            result = detector.analyze_domain(sender_domain)
            
            if result.has_lookalikes and result.matches:
                top_match = result.matches[0]
                
                # Determine severity based on confidence
                if top_match.confidence >= 0.9:
                    severity = RiskLevel.CRITICAL
                elif top_match.confidence >= 0.7:
                    severity = RiskLevel.HIGH
                else:
                    severity = RiskLevel.MEDIUM
                
                evidence = [
                    f"Sender domain: {sender_domain}",
                    f"Impersonating: {top_match.target_brand.capitalize()}",
                    f"Legitimate domain: {top_match.legitimate_domain}",
                    f"Confidence: {top_match.confidence:.0%}",
                    f"Detection methods: {', '.join(top_match.detection_methods)}",
                ]
                
                if top_match.homoglyphs_found:
                    evidence.append(f"Homoglyphs: {', '.join(top_match.homoglyphs_found)}")
                
                return self.create_match(
                    evidence=evidence,
                    indicators=[{
                        'type': 'sender_lookalike',
                        'sender_domain': sender_domain,
                        'target_brand': top_match.target_brand,
                        'legitimate_domain': top_match.legitimate_domain,
                        'confidence': top_match.confidence,
                        'methods': top_match.detection_methods,
                        'description': top_match.description,
                    }],
                    severity_override=severity,
                    description_override=top_match.description,
                )
        except Exception as e:
            self.logger.warning(f"LookalikeDetector error: {e}")
        
        return None
