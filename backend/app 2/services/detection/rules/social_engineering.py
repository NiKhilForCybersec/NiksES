"""
NiksES Social Engineering Detection Rules

Rules for detecting psychological manipulation tactics used in phishing.
"""

import re
from typing import Optional, List

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel
from app.utils.constants import URGENCY_KEYWORDS, AUTHORITY_KEYWORDS, FEAR_KEYWORDS

from .base import DetectionRule, RuleMatch, register_rule


# Reward/greed keywords
REWARD_KEYWORDS = [
    'you have won', 'you\'ve won', 'congratulations', 'winner',
    'prize', 'lottery', 'reward', 'bonus', 'free money', 'cash prize',
    'million dollars', 'inheritance', 'beneficiary', 'unclaimed funds',
    'claim your', 'gift for you', 'special offer', 'exclusive deal',
    'limited offer', 'selected winner', 'lucky winner',
]

# Scarcity/time pressure
SCARCITY_KEYWORDS = [
    'limited time', 'offer expires', 'act now', 'don\'t miss',
    'last chance', 'final notice', 'expires today', 'only today',
    'hours left', 'ending soon', 'while supplies last',
    'exclusive access', 'limited availability', 'running out',
]

# Social proof
SOCIAL_PROOF_KEYWORDS = [
    'millions of users', 'thousands of customers', 'everyone is',
    'join millions', 'trusted by', 'as seen on', 'featured in',
    'recommended by', 'verified by', 'certified by',
]

# Curiosity
CURIOSITY_KEYWORDS = [
    'you won\'t believe', 'shocking', 'secret', 'hidden',
    'exposed', 'revealed', 'discover', 'find out why',
    'what they don\'t want you to know', 'the truth about',
]


@register_rule
class UrgencyRule(DetectionRule):
    """Detect urgency language designed to pressure quick action."""
    
    rule_id = "SE-001"
    name = "Urgency Tactics"
    description = "Email uses urgency language to pressure immediate action"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in URGENCY_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        if len(found) >= 2:
            severity = RiskLevel.HIGH if len(found) >= 4 else RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=[
                    "Urgency tactics detected:",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'urgency_tactic',
                    'keywords': found,
                    'count': len(found),
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class FearRule(DetectionRule):
    """Detect fear-inducing language."""
    
    rule_id = "SE-002"
    name = "Fear Tactics"
    description = "Email uses threatening or fear-inducing language"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in FEAR_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        if len(found) >= 2:
            severity = RiskLevel.HIGH if len(found) >= 3 else RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=[
                    "Fear-inducing language detected:",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'fear_tactic',
                    'keywords': found,
                    'count': len(found),
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class AuthorityRule(DetectionRule):
    """Detect impersonation of authority figures or organizations."""
    
    rule_id = "SE-003"
    name = "Authority Impersonation"
    description = "Email claims to be from authority figure or official organization"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # CRITICAL: Don't flag authority claims from LEGITIMATE senders
        # If Apple sends email about "account security", that's legitimate!
        sender_domain = self.get_sender_domain(email)
        if sender_domain:
            from app.utils.constants import BRAND_TARGETS
            sender_domain_lower = sender_domain.lower()
            for brand_id, brand_info in BRAND_TARGETS.items():
                legitimate_domains = [d.lower() for d in brand_info.get("legitimate_domains", [])]
                for legit in legitimate_domains:
                    if sender_domain_lower == legit or sender_domain_lower.endswith(f".{legit}"):
                        # Sender is from legitimate brand - don't flag authority claims
                        return None
        
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in AUTHORITY_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        # Also check subject
        if email.subject:
            subject_lower = email.subject.lower()
            for keyword in AUTHORITY_KEYWORDS:
                if keyword.lower() in subject_lower and keyword not in found:
                    found.append(keyword)
        
        if found:
            return self.create_match(
                evidence=[
                    "Authority claims detected:",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'authority_claim',
                    'keywords': found,
                }],
            )
        
        return None


@register_rule
class RewardRule(DetectionRule):
    """Detect reward/prize language (lottery scams, etc.)."""
    
    rule_id = "SE-004"
    name = "Reward/Prize Language"
    description = "Email mentions prizes, winnings, or unexpected rewards"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in REWARD_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        if len(found) >= 2:
            severity = RiskLevel.HIGH if len(found) >= 3 else RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=[
                    "Reward/prize language detected (common in scams):",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'reward_tactic',
                    'keywords': found,
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class ScarcityRule(DetectionRule):
    """Detect scarcity/limited availability tactics."""
    
    rule_id = "SE-005"
    name = "Scarcity Tactics"
    description = "Email creates artificial scarcity or time pressure"
    category = "social_engineering"
    severity = RiskLevel.LOW
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in SCARCITY_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        if len(found) >= 2:
            return self.create_match(
                evidence=[
                    "Scarcity/limited time tactics detected:",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'scarcity_tactic',
                    'keywords': found,
                }],
            )
        
        return None


@register_rule
class CuriosityRule(DetectionRule):
    """Detect curiosity-triggering clickbait language."""
    
    rule_id = "SE-006"
    name = "Clickbait Language"
    description = "Email uses sensational or curiosity-triggering language"
    category = "social_engineering"
    severity = RiskLevel.LOW
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found = []
        for keyword in CURIOSITY_KEYWORDS:
            if keyword.lower() in body_text:
                found.append(keyword)
        
        if len(found) >= 2:
            return self.create_match(
                evidence=[
                    "Clickbait/curiosity language detected:",
                ] + [f"  - '{kw}'" for kw in found[:5]],
                indicators=[{
                    'type': 'curiosity_tactic',
                    'keywords': found,
                }],
            )
        
        return None


@register_rule
class CallbackPhishingRule(DetectionRule):
    """Detect callback phishing (requests to call a phone number)."""
    
    rule_id = "SE-007"
    name = "Callback Phishing"
    description = "Email requests calling a phone number for urgent matter"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Look for callback patterns
        callback_patterns = [
            r'call\s+(?:us|me|this number|now)',
            r'contact\s+(?:us|me)\s+(?:immediately|urgently|now)',
            r'phone\s+(?:us|me)\s+(?:immediately|urgently|now)',
            r'reach\s+(?:us|me)\s+at',
            r'(?:urgent|important)[^.]*call',
        ]
        
        found_patterns = []
        for pattern in callback_patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                found_patterns.append(pattern)
        
        # Check if there's a phone number and urgency
        has_phone = len(email.phone_numbers) > 0 if email.phone_numbers else bool(re.search(r'\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', body_text))
        has_urgency = any(kw in body_text for kw in ['urgent', 'immediately', 'asap', 'right away'])
        
        if found_patterns and has_phone and has_urgency:
            return self.create_match(
                evidence=[
                    "Callback phishing indicators detected:",
                    "  - Requests phone call",
                    "  - Contains phone number",
                    "  - Uses urgent language",
                ],
                indicators=[{
                    'type': 'callback_phishing',
                    'has_phone': True,
                    'patterns_matched': len(found_patterns),
                }],
                severity_override=RiskLevel.HIGH,
            )
        
        return None


@register_rule
class MultipleSETacticsRule(DetectionRule):
    """Detect emails using multiple social engineering tactics."""
    
    rule_id = "SE-008"
    name = "Multiple SE Tactics"
    description = "Email combines multiple social engineering techniques"
    category = "social_engineering"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        tactics_found = []
        
        # Check each tactic category
        if any(kw.lower() in body_text for kw in URGENCY_KEYWORDS[:5]):
            tactics_found.append('urgency')
        
        if any(kw.lower() in body_text for kw in FEAR_KEYWORDS[:5]):
            tactics_found.append('fear')
        
        if any(kw.lower() in body_text for kw in AUTHORITY_KEYWORDS[:5]):
            tactics_found.append('authority')
        
        if any(kw.lower() in body_text for kw in REWARD_KEYWORDS[:5]):
            tactics_found.append('reward')
        
        if any(kw.lower() in body_text for kw in SCARCITY_KEYWORDS[:5]):
            tactics_found.append('scarcity')
        
        if len(tactics_found) >= 3:
            return self.create_match(
                evidence=[
                    f"Multiple social engineering tactics detected ({len(tactics_found)}):",
                ] + [f"  - {tactic.title()} tactics" for tactic in tactics_found],
                indicators=[{
                    'type': 'multiple_se_tactics',
                    'tactics': tactics_found,
                    'count': len(tactics_found),
                }],
                severity_override=RiskLevel.CRITICAL if len(tactics_found) >= 4 else RiskLevel.HIGH,
            )
        
        return None


# Romance/Dating spam keywords
ROMANCE_SPAM_KEYWORDS = [
    'sexy', 'chat with me', 'contact me here', 'dating', 'hook up',
    'hookup', 'meet me', 'meet singles', 'lonely', 'bored', 'hot singles',
    'adult', 'webcam', 'cam girl', 'private chat', 'naughty', 'flirt',
    'looking for fun', 'single and ready', 'no strings attached',
    'casual encounter', 'get together', 'chat about something',
    'meet local', 'find love', 'intimate', 'discreet',
    'i am bored', "i'm bored", 'we can chat', 'want to chat',
]

# Spam domain patterns (regex)
SPAM_DOMAIN_PATTERNS = [
    r'dating', r'meet', r'chat', r'singles', r'hook', r'love',
    r'adult', r'sexy', r'cam', r'flirt', r'romance', r'hot',
]


@register_rule
class RomanceSpamRule(DetectionRule):
    """Detect romance/dating spam and potential sextortion."""
    
    rule_id = "SE-009"
    name = "Romance/Dating Spam"
    description = "Email contains romance scam or dating spam language designed to lure victims"
    category = "social_engineering"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in ROMANCE_SPAM_KEYWORDS:
            if keyword.lower() in body_text:
                found_keywords.append(keyword)
        
        # Also check URLs for dating/romance patterns
        spam_url_domains = []
        if email.urls:
            for url in email.urls:
                domain = url.domain.lower() if url.domain else ''
                for pattern in SPAM_DOMAIN_PATTERNS:
                    if re.search(pattern, domain):
                        spam_url_domains.append(url.domain)
                        break
        
        # Trigger if romance keywords found OR spam domain patterns in URLs
        if found_keywords or spam_url_domains:
            evidence = []
            
            if found_keywords:
                evidence.append(f"Romance/dating spam language detected ({len(found_keywords)} indicators):")
                evidence.extend([f"  - '{kw}'" for kw in found_keywords[:5]])
            
            if spam_url_domains:
                evidence.append("Suspicious dating/spam domains in URLs:")
                evidence.extend([f"  - {domain}" for domain in set(spam_url_domains)[:3]])
            
            # Higher severity if both content and URL match
            severity = RiskLevel.HIGH
            if found_keywords and spam_url_domains:
                severity = RiskLevel.CRITICAL
            elif len(found_keywords) >= 2:
                severity = RiskLevel.HIGH
            else:
                severity = RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'romance_spam',
                    'keywords': found_keywords,
                    'spam_domains': list(set(spam_url_domains)),
                    'keyword_count': len(found_keywords),
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class DisplayNameMismatchRule(DetectionRule):
    """Detect mismatch between display name and email address."""
    
    rule_id = "SE-010"
    name = "Display Name Mismatch"
    description = "Sender display name does not match email address pattern (common in spam/phishing)"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.sender or not email.sender.display_name:
            return None
        
        display_name = email.sender.display_name.lower().strip()
        email_addr = email.sender.email.lower() if email.sender.email else ''
        local_part = email.sender.local_part.lower() if email.sender.local_part else ''
        
        if not display_name or not email_addr:
            return None
        
        # Extract potential name parts from display name
        display_parts = re.findall(r'[a-z]+', display_name)
        
        if not display_parts:
            return None
        
        # Check if ANY part of display name appears in email
        name_in_email = any(part in local_part for part in display_parts if len(part) > 2)
        
        # Check for random-looking email patterns
        random_patterns = [
            r'^[a-z]{2,4}\d{4,}',  # ab1234567
            r'^\d{2,}[a-z]+\d*',   # 123abc456
            r'^[a-z]+\d+[a-z]+$',  # abc123def
            r'[a-z]{10,}',         # very long random string
        ]
        
        looks_random = any(re.match(p, local_part) for p in random_patterns)
        
        # Mismatch if display name has real name but email looks random
        if display_parts and not name_in_email and looks_random:
            # Extra check: display name looks like real name (first last pattern)
            if len(display_parts) >= 2 and all(len(p) > 2 for p in display_parts[:2]):
                return self.create_match(
                    evidence=[
                        "Display name does not match email address:",
                        f"  - Display name: '{email.sender.display_name}'",
                        f"  - Email address: {email_addr}",
                        "  - This is common in spam and phishing emails",
                    ],
                    indicators=[{
                        'type': 'display_name_mismatch',
                        'display_name': email.sender.display_name,
                        'email': email_addr,
                        'looks_random': looks_random,
                    }],
                    severity_override=RiskLevel.MEDIUM,
                )
        
        return None


@register_rule
class SpamURLPatternRule(DetectionRule):
    """Detect URLs with spam/scam domain patterns."""
    
    rule_id = "SE-011"
    name = "Spam URL Pattern"
    description = "URL contains domain patterns commonly used in spam campaigns"
    category = "social_engineering"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.urls:
            return None
        
        # Import whitelist
        from app.utils.constants import LEGITIMATE_FINANCIAL_DOMAINS
        
        # More specific spam patterns with word boundaries to avoid false positives
        # These patterns target actual spam domains, not legitimate sites
        spam_patterns = [
            (r'\bdating\b', 'dating/romance spam'),
            (r'\bmeet(me|singles|local)\b', 'meeting/dating spam'),
            (r'\bchatroom\b', 'chat spam'),
            (r'\bsingles\b', 'dating spam'),
            (r'\bhookup\b', 'hookup spam'),
            (r'\badultfriend\b', 'adult content spam'),
            (r'\bsexy(singles|chat|meet)\b', 'adult content spam'),
            (r'\bcamgirl\b', 'webcam spam'),
            (r'\blivecam\b', 'webcam spam'),
            (r'\bwebcam\b', 'webcam spam'),
            (r'\bflirt(4free|chat)\b', 'dating spam'),
            (r'\blovetonight\b', 'romance spam'),
            (r'\bhotties\b', 'adult spam'),
            (r'\baffair\b', 'affair spam'),
            (r'exclusive.*\d{2,}', 'tracking/affiliate spam'),
            (r'\?.*s=\w+_\d+', 'affiliate tracking spam'),
        ]
        
        matches = []
        for url in email.urls:
            domain = url.domain.lower() if url.domain else ''
            full_url = url.url.lower() if url.url else ''
            
            # Skip legitimate financial domains
            if any(legit_domain in domain for legit_domain in LEGITIMATE_FINANCIAL_DOMAINS):
                continue
            
            for pattern, spam_type in spam_patterns:
                # Check domain and URL path separately
                if re.search(pattern, domain, re.IGNORECASE):
                    matches.append({
                        'domain': url.domain,
                        'url': url.url[:80],
                        'pattern': pattern,
                        'spam_type': spam_type,
                    })
                    break
                # Only check full URL for tracking patterns
                elif 'exclusive' in pattern or '?' in pattern:
                    if re.search(pattern, full_url, re.IGNORECASE):
                        matches.append({
                            'domain': url.domain,
                            'url': url.url[:80],
                            'pattern': pattern,
                            'spam_type': spam_type,
                        })
                        break
        
        if matches:
            severity = RiskLevel.HIGH if len(matches) >= 2 else RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=[
                    f"Spam URL patterns detected ({len(matches)} URLs):",
                ] + [f"  - {m['domain']}: {m['spam_type']}" for m in matches[:5]],
                indicators=[{
                    'type': 'spam_url_pattern',
                    'matches': matches,
                    'count': len(matches),
                }],
                severity_override=severity,
            )
        
        return None
