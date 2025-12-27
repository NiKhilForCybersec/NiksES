"""
NiksES Dynamic SMS/URL Scoring Engine

Applies the same dynamic scoring principles to SMS/URL analysis:
- Evidence-based scoring (no hardcoded values)
- TI is the anchor for external validation
- Attack chain detection for smishing patterns
- Confidence-adjusted thresholds
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse

# Import centralized scoring configuration
try:
    from app.config.scoring import get_scoring_config
    USE_CENTRALIZED_CONFIG = True
except ImportError:
    USE_CENTRALIZED_CONFIG = False

# Use try/except for flexible importing
try:
    from .evidence import (
        Evidence,
        EvidenceCategory,
        EvidenceType,
        EvidenceSource,
        AttackChain,
        SourceReliabilityCalculator,
        SpecificityCalculator,
    )
    from .dynamic_scorer import (
        TIScore,
        ThreatIntelScorer,
        DynamicEvidenceWeighter,
        FinalScore,
        ScoreBreakdown,
        DimensionScore,
    )
except ImportError:
    from evidence import (
        Evidence,
        EvidenceCategory,
        EvidenceType,
        EvidenceSource,
        AttackChain,
        SourceReliabilityCalculator,
        SpecificityCalculator,
    )
    from dynamic_scorer import (
        TIScore,
        ThreatIntelScorer,
        DynamicEvidenceWeighter,
        FinalScore,
        ScoreBreakdown,
        DimensionScore,
    )

logger = logging.getLogger(__name__)


# =============================================================================
# SMS/URL SPECIFIC EVIDENCE TYPES
# =============================================================================

class SMSEvidenceType:
    """Extended evidence types for SMS/URL analysis."""
    # URL-based
    SHORTENED_URL = "shortened_url"
    IP_IN_URL = "ip_in_url"
    SUSPICIOUS_TLD = "suspicious_tld"
    HOMOGLYPH_URL = "homoglyph_url"
    EXCESSIVE_SUBDOMAINS = "excessive_subdomains"
    CREDENTIAL_PARAMS = "credential_params"
    REDIRECT_CHAIN = "redirect_chain"
    NEWLY_REGISTERED = "newly_registered"
    NO_SSL = "no_ssl"
    
    # Content-based
    FINANCIAL_KEYWORDS = "financial_keywords"
    DELIVERY_SCAM = "delivery_scam"
    PRIZE_SCAM = "prize_scam"
    GOVERNMENT_SCAM = "government_scam"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    CRYPTO_SCAM = "crypto_scam"
    SUBSCRIPTION_SCAM = "subscription_scam"
    ACCOUNT_LOCKED = "account_locked"
    REFUND_SCAM = "refund_scam"
    JOB_SCAM = "job_scam"
    
    # Behavioral
    UNKNOWN_SENDER = "unknown_sender"
    SHORT_CODE_SENDER = "short_code_sender"
    URGENCY_IN_SMS = "urgency_in_sms"
    GRAMMAR_ERRORS = "grammar_errors"
    EXCESSIVE_CAPS = "excessive_caps"
    EXCESSIVE_PUNCTUATION = "excessive_punctuation"
    MULTIPLE_URLS = "multiple_urls"
    
    # TI
    URL_FLAGGED = "url_flagged"
    DOMAIN_FLAGGED = "domain_flagged"
    KNOWN_PHISHING = "known_phishing"


# =============================================================================
# SMISHING PATTERN DEFINITIONS
# =============================================================================

# Patterns are defined with evidence requirements, not fixed scores
SMISHING_PATTERNS = {
    "banking_smishing": {
        "description": "Bank account compromise/verification scam",
        "keywords": [
            r"(?:bank|account).*(?:suspend|lock|limit|unusual|verify|compromis)",
            r"(?:verify|confirm|update).*(?:account|identity|transaction|detail)",
            r"unauthorized.*(?:transaction|access|login|activity)",
            r"your.*(?:card|account|bank).*(?:block|suspend|lock|compromis)",
            r"(?:suspicious|unusual|fraudulent).*(?:activity|transaction|login)",
            r"(?:security|fraud).*(?:alert|notice|warning)",
        ],
        "brands": ["chase", "wells fargo", "bank of america", "citi", "capital one", "td bank", "usbank", "boa", "bofa", "pnc", "hsbc", "barclays"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "delivery_smishing": {
        "description": "Package delivery notification scam",
        "keywords": [
            r"package.*(?:held|pending|deliver|customs|unable|failed)",
            r"(?:usps|ups|fedex|dhl|royal\s*mail).*(?:deliver|package|parcel)",
            r"your.*(?:package|parcel|shipment|order).*(?:track|confirm|reschedule|deliver)",
            r"delivery.*(?:failed|attempt|pending|unable|missed)",
            r"customs.*(?:fee|charge|payment|clear)",
            r"(?:reschedule|schedule).*(?:delivery|pickup)",
            r"(?:tracking|shipment).*(?:update|status|number)",
        ],
        "brands": ["usps", "ups", "fedex", "dhl", "amazon", "royal mail", "post office", "hermes", "dpd"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "prize_smishing": {
        "description": "Prize/lottery/gift card scam",
        "keywords": [
            r"(?:won|winner|selected|chosen|congrat).*(?:\$|dollar|prize|gift|reward|cash)",
            r"(?:claim|collect|redeem).*(?:prize|reward|winnings|gift)",
            r"congratulations.*(?:won|winner|selected|prize)",
            r"(?:free|gift).*(?:iphone|samsung|card|cash|prize|reward)",
            r"(?:lottery|sweepstakes|giveaway).*(?:winner|won|claim)",
            r"(?:exclusive|special).*(?:offer|reward|prize|gift)",
        ],
        "brands": ["walmart", "amazon", "apple", "costco", "target", "best buy", "home depot"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "government_smishing": {
        "description": "Government/IRS/SSA impersonation scam",
        "keywords": [
            r"(?:irs|tax).*(?:refund|payment|audit|overdue|owe)",
            r"(?:social\s*security|ssa|ssn).*(?:suspend|expire|verify|blocked)",
            r"(?:medicare|medicaid).*(?:card|benefit|verify|new)",
            r"(?:stimulus|relief|economic).*(?:payment|check|deposit)",
            r"(?:dmv|license|registration).*(?:suspend|expire|renew|update)",
            r"(?:government|federal).*(?:notice|alert|action)",
        ],
        "brands": ["irs", "ssa", "medicare", "dmv", "social security"],
        "requires_url": False,
        "mitre": "T1566.002",
    },
    "tech_support_smishing": {
        "description": "Tech support scam",
        "keywords": [
            r"(?:virus|malware|infected|hacked).*(?:detect|found|computer|device)",
            r"(?:microsoft|apple|google).*(?:support|security|alert|warning)",
            r"(?:call|contact).*(?:support|immediately|urgent|now)",
            r"your.*(?:device|computer|phone|system).*(?:compromised|hacked|infected)",
            r"(?:security|tech).*(?:support|helpdesk|team)",
        ],
        "brands": ["microsoft", "apple", "google", "norton", "mcafee", "windows", "geek squad"],
        "requires_url": False,
        "mitre": "T1566.003",
    },
    "crypto_smishing": {
        "description": "Cryptocurrency scam",
        "keywords": [
            r"(?:bitcoin|btc|ethereum|eth|crypto).*(?:wallet|transfer|earn|investment)",
            r"(?:seed|recovery|private)\s*(?:phrase|key)",
            r"(?:crypto|wallet|coinbase|binance).*(?:suspend|verify|secure|locked)",
            r"(?:investment|trading).*(?:opportunity|profit|return|guaranteed)",
            r"(?:airdrop|giveaway).*(?:crypto|bitcoin|token|coin)",
            r"(?:nft|defi|blockchain).*(?:investment|opportunity|profit)",
        ],
        "brands": ["coinbase", "binance", "crypto.com", "metamask", "trust wallet", "kraken"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "subscription_smishing": {
        "description": "Fake subscription/renewal scam",
        "keywords": [
            r"(?:netflix|spotify|amazon\s*prime|disney|hulu).*(?:expire|renew|cancel|suspend)",
            r"(?:subscription|membership|account).*(?:expire|cancel|renew|charged|payment)",
            r"(?:auto|automatic).*(?:renew|charge|payment|debit)",
            r"(?:billing|payment).*(?:fail|declined|update|problem|issue)",
            r"(?:renew|update).*(?:payment|card|billing).*(?:method|info|detail)",
            r"(?:service|access).*(?:interrupt|suspend|cancel|expire)",
        ],
        "brands": ["netflix", "spotify", "amazon", "apple", "disney", "hulu", "hbo", "prime", "youtube"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "account_locked_smishing": {
        "description": "Account locked/suspended scam",
        "keywords": [
            r"(?:account|profile|access).*(?:lock|suspend|restrict|limit|disabled)",
            r"(?:unusual|suspicious|unauthorized).*(?:activity|login|sign|access)",
            r"(?:verify|confirm|validate).*(?:identity|account|ownership|you)",
            r"(?:security|verification)\s*(?:code|link|required|needed)",
            r"(?:restore|unlock|reactivate).*(?:account|access|service)",
            r"(?:action|step).*(?:required|needed|necessary).*(?:secure|protect)",
        ],
        "brands": ["facebook", "instagram", "paypal", "amazon", "apple", "google", "twitter", "linkedin", "tiktok", "snapchat"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "refund_smishing": {
        "description": "Fake refund scam",
        "keywords": [
            r"(?:refund|reimbursement|cashback).*(?:pending|process|claim|approve)",
            r"(?:overpay|overcharge|double\s*charge).*(?:refund|return|credit)",
            r"(?:eligible|qualify|entitled).*(?:refund|reimbursement|credit|payment)",
            r"(?:claim|collect|receive).*(?:refund|money|payment|credit)",
            r"(?:refund|payment).*(?:ready|waiting|available|process)",
        ],
        "brands": ["amazon", "apple", "paypal", "bank", "irs", "gov"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "job_smishing": {
        "description": "Fake job offer scam",
        "keywords": [
            r"(?:job|position|opportunity|role).*(?:offer|available|hiring|open)",
            r"(?:work|earn).*(?:home|remote|online).*(?:\$|dollar|hour|day|week)",
            r"(?:interview|application).*(?:schedule|complete|click|immediate)",
            r"(?:hiring|recruitment|recruiter).*(?:immediately|urgently|now)",
            r"(?:easy|simple).*(?:money|cash|income|earn)",
            r"(?:part\s*time|full\s*time).*(?:\$|dollar|hour|salary|pay)",
        ],
        "brands": [],
        "requires_url": True,
        "mitre": "T1566.002",
    },
    "toll_smishing": {
        "description": "Unpaid toll/parking scam",
        "keywords": [
            r"(?:unpaid|outstanding|overdue).*(?:toll|parking|fine|fee)",
            r"(?:toll|parking).*(?:violation|notice|payment|due)",
            r"(?:pay|settle).*(?:toll|parking|fine).*(?:immediately|now|avoid)",
            r"(?:license|registration).*(?:suspend|revoke).*(?:unpaid|toll)",
            r"(?:ezpass|sunpass|fastrak).*(?:payment|account|balance)",
        ],
        "brands": ["ezpass", "sunpass", "fastrak", "ipass"],
        "requires_url": True,
        "mitre": "T1566.002",
    },
}


# =============================================================================
# URL RISK INDICATORS
# =============================================================================

# Suspicious TLDs (not a blacklist, just elevates scrutiny)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs often abused
    "xyz", "top", "work", "click",  # Cheap TLDs
    "buzz", "surf", "monster",
    "ru", "cn",  # Higher risk regions (context dependent)
}

# URL shorteners (require expansion/extra scrutiny)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
    "rebrand.ly", "short.io", "cutt.ly", "rb.gy", "tiny.cc",
}

# =============================================================================
# SAFE DOMAINS WHITELIST - Legitimate domains that should NOT trigger alerts
# =============================================================================
SAFE_DOMAINS = {
    # AI/Tech Companies
    "openai.com", "chat.openai.com", "chatgpt.com", "platform.openai.com",
    "anthropic.com", "claude.ai",
    "google.com", "www.google.com", "mail.google.com", "drive.google.com", 
    "docs.google.com", "accounts.google.com", "play.google.com", "cloud.google.com",
    "gemini.google.com", "bard.google.com",
    "microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
    "office.com", "office365.com", "outlook.com", "outlook.live.com",
    "live.com", "login.live.com", "azure.com", "portal.azure.com",
    "bing.com", "copilot.microsoft.com",
    "apple.com", "www.apple.com", "icloud.com", "appleid.apple.com",
    "support.apple.com", "store.apple.com",
    "amazon.com", "www.amazon.com", "aws.amazon.com", "console.aws.amazon.com",
    "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in",
    
    # Social Media
    "facebook.com", "www.facebook.com", "m.facebook.com", "fb.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "x.com", "mobile.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "tiktok.com", "www.tiktok.com",
    "reddit.com", "www.reddit.com", "old.reddit.com",
    "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
    "pinterest.com", "snapchat.com", "discord.com", "discord.gg",
    "whatsapp.com", "web.whatsapp.com", "wa.me",
    "telegram.org", "t.me", "web.telegram.org",
    "slack.com", "app.slack.com",
    
    # Financial (Legitimate)
    "paypal.com", "www.paypal.com", "paypal.me",
    "chase.com", "www.chase.com", "secure.chase.com",
    "bankofamerica.com", "www.bankofamerica.com",
    "wellsfargo.com", "www.wellsfargo.com",
    "citi.com", "citibank.com", "online.citi.com",
    "capitalone.com", "www.capitalone.com",
    "americanexpress.com", "www.americanexpress.com",
    "discover.com", "www.discover.com",
    "usbank.com", "www.usbank.com",
    "stripe.com", "dashboard.stripe.com",
    "square.com", "squareup.com", "cash.app",
    "venmo.com", "account.venmo.com",
    "wise.com", "transferwise.com",
    
    # Crypto (Legitimate)
    "coinbase.com", "www.coinbase.com", "pro.coinbase.com",
    "binance.com", "www.binance.com",
    "kraken.com", "www.kraken.com",
    "crypto.com",
    
    # Streaming/Entertainment
    "netflix.com", "www.netflix.com",
    "spotify.com", "open.spotify.com", "accounts.spotify.com",
    "hulu.com", "www.hulu.com",
    "disneyplus.com", "www.disneyplus.com",
    "hbomax.com", "max.com",
    "primevideo.com", "www.primevideo.com",
    "twitch.tv", "www.twitch.tv",
    
    # E-commerce
    "ebay.com", "www.ebay.com",
    "walmart.com", "www.walmart.com",
    "target.com", "www.target.com",
    "bestbuy.com", "www.bestbuy.com",
    "etsy.com", "www.etsy.com",
    "shopify.com", "myshopify.com",
    "aliexpress.com",
    
    # Shipping/Logistics (Legitimate)
    "usps.com", "www.usps.com", "tools.usps.com",
    "ups.com", "www.ups.com", "wwwapps.ups.com",
    "fedex.com", "www.fedex.com",
    "dhl.com", "www.dhl.com",
    
    # Email Providers
    "gmail.com", "mail.google.com",
    "yahoo.com", "mail.yahoo.com",
    "protonmail.com", "mail.protonmail.com", "proton.me",
    "zoho.com", "mail.zoho.com",
    
    # Development/Tech
    "github.com", "www.github.com", "gist.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com", "www.npmjs.com",
    "pypi.org",
    "docker.com", "hub.docker.com",
    "heroku.com", "herokuapp.com",
    "railway.app",
    "vercel.com", "vercel.app",
    "netlify.com", "netlify.app",
    "cloudflare.com", "dash.cloudflare.com",
    "digitalocean.com",
    "linode.com",
    
    # News/Media
    "nytimes.com", "www.nytimes.com",
    "washingtonpost.com",
    "cnn.com", "www.cnn.com",
    "bbc.com", "www.bbc.com", "bbc.co.uk",
    "reuters.com", "www.reuters.com",
    "theguardian.com",
    "forbes.com", "www.forbes.com",
    "bloomberg.com",
    
    # Productivity
    "notion.so", "www.notion.so",
    "trello.com",
    "asana.com",
    "monday.com",
    "figma.com", "www.figma.com",
    "canva.com", "www.canva.com",
    "dropbox.com", "www.dropbox.com",
    "box.com", "www.box.com",
    "zoom.us", "us02web.zoom.us", "us04web.zoom.us",
    "webex.com",
    "teams.microsoft.com",
    
    # Government
    "irs.gov", "www.irs.gov",
    "ssa.gov", "www.ssa.gov",
    "usa.gov", "www.usa.gov",
    "medicare.gov", "www.medicare.gov",
    "gov.uk", "www.gov.uk",
    
    # Education
    "wikipedia.org", "en.wikipedia.org",
    "khanacademy.org",
    "coursera.org", "www.coursera.org",
    "udemy.com", "www.udemy.com",
    "edx.org", "www.edx.org",
}

# Brand domains for impersonation detection
# These are legitimate domains - if URL contains brand name but domain isn't here, it's suspicious
BRAND_DOMAINS = {
    # Tech Giants
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "azure.com", "bing.com", "xbox.com", "linkedin.com", "skype.com", "msn.com", "windows.com", "microsoftonline.com", "office365.com", "onedrive.com", "sharepoint.com", "teams.microsoft.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.co.uk", "google.ca", "drive.google.com", "docs.google.com", "cloud.google.com", "play.google.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com", "appleid.apple.com", "itunes.com", "me.com", "mzstatic.com", "apple.co", "icloud-content.com", "cdn-apple.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in", "amazonaws.com", "aws.amazon.com", "primevideo.com", "alexa.com", "a]mazon.in", "amazon.es", "amazon.fr", "amazon.it", "amazonpay.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com", "meta.com", "messenger.com", "whatsapp.com", "fb.me", "facebookcorewwwi.onion"],
    "openai": ["openai.com", "chatgpt.com", "chat.openai.com", "platform.openai.com", "api.openai.com"],
    "anthropic": ["anthropic.com", "claude.ai", "console.anthropic.com"],
    
    # Financial
    "paypal": ["paypal.com", "paypal.me", "paypal-communication.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "wells fargo": ["wellsfargo.com", "wf.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com", "boa.com"],
    "bank of america": ["bankofamerica.com", "bofa.com", "boa.com"],
    "citi": ["citi.com", "citibank.com", "citicards.com"],
    "citibank": ["citi.com", "citibank.com", "citicards.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net", "hdfc.com"],
    "icici": ["icicibank.com", "icicibank.co.in"],
    "sbi": ["sbi.co.in", "onlinesbi.com", "sbicard.com"],
    "axis": ["axisbank.com", "axisbank.co.in"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk"],
    "barclays": ["barclays.com", "barclays.co.uk"],
    
    # Streaming/Entertainment
    "netflix": ["netflix.com", "nflxso.net"],
    "spotify": ["spotify.com", "scdn.co"],
    "disney": ["disney.com", "disneyplus.com", "go.com"],
    "hulu": ["hulu.com", "huluim.com"],
    "hbo": ["hbo.com", "hbomax.com"],
    
    # Shipping/Delivery
    "usps": ["usps.com", "usps.gov"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.de"],
    
    # Government
    "irs": ["irs.gov"],
    "ssa": ["ssa.gov", "socialsecurity.gov"],
    "dmv": ["dmv.gov", "dmv.ca.gov", "dmv.ny.gov"],
    
    # Crypto
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com", "binance.us"],
    "metamask": ["metamask.io"],
    
    # E-commerce
    "walmart": ["walmart.com"],
    "target": ["target.com"],
    "ebay": ["ebay.com"],
    "bestbuy": ["bestbuy.com"],
}

# Homoglyph characters
HOMOGLYPHS = {
    'a': ['а', 'ạ', 'ą', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā', '@'],
    'e': ['е', 'ẹ', 'ę', 'è', 'é', 'ê', 'ë', 'ē', '3'],
    'i': ['і', 'ị', 'ì', 'í', 'î', 'ï', 'ī', '1', 'l', '|'],
    'o': ['о', 'ọ', 'ø', 'ò', 'ó', 'ô', 'õ', 'ö', 'ō', '0'],
    'u': ['υ', 'ụ', 'ù', 'ú', 'û', 'ü', 'ū'],
    'l': ['1', 'I', '|', 'ł'],
    's': ['5', '$'],
    'g': ['9', 'ğ'],
    't': ['7', '+'],
    'b': ['8', 'ḅ'],
}


# =============================================================================
# SMS/URL EVIDENCE COLLECTOR
# =============================================================================

class SMSEvidenceCollector:
    """
    Collect evidence from SMS/URL content with dynamic quality metrics.
    """
    
    def __init__(self):
        self.reliability_calc = SourceReliabilityCalculator()
        self.specificity_calc = SpecificityCalculator()
        self.evidence_list: List[Evidence] = []
        self.api_status: Dict[str, str] = {}
        self.is_safe_domain = False  # Track if URL is from a safe domain
    
    def set_api_status(self, status: Dict[str, str]):
        """Set API status for reliability calculations."""
        self.api_status = status
    
    def clear(self):
        """Clear collected evidence."""
        self.evidence_list = []
        self.is_safe_domain = False
    
    def _is_domain_safe(self, domain: str) -> bool:
        """Check if domain is in the safe whitelist."""
        domain_lower = domain.lower().strip()
        
        # Direct match
        if domain_lower in SAFE_DOMAINS:
            return True
        
        # Check if it's a subdomain of a safe domain
        for safe_domain in SAFE_DOMAINS:
            if domain_lower.endswith(f".{safe_domain}"):
                return True
            # Also check base domain match
            if domain_lower == safe_domain or domain_lower == f"www.{safe_domain}":
                return True
        
        return False
    
    def _get_base_domain(self, domain: str) -> str:
        """Extract base domain from full domain."""
        parts = domain.split('.')
        if len(parts) >= 2:
            # Handle common SLDs like co.uk
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain
    
    def collect_from_text(
        self,
        text: str,
        urls: List[str],
        sender: Optional[str] = None,
    ):
        """
        Collect all evidence from SMS/URL text.
        """
        text_lower = text.lower()
        
        # FIRST: Check if ALL URLs are from safe domains
        all_urls_safe = True
        safe_domain_found = None
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                if self._is_domain_safe(domain):
                    safe_domain_found = domain
                else:
                    all_urls_safe = False
                    break
            except:
                all_urls_safe = False
                break
        
        # If all URLs are safe and no suspicious text patterns, mark as safe
        if urls and all_urls_safe:
            self.is_safe_domain = True
            logger.info(f"URL from safe domain: {safe_domain_found}")
            return  # Skip evidence collection for safe domains
        
        # 1. Analyze URLs for risk indicators (only for non-safe domains)
        if urls:
            self._collect_url_evidence(urls)
        
        # 1. Analyze URLs
        self._collect_url_evidence(urls)
        
        # 2. Match smishing patterns
        self._collect_pattern_evidence(text_lower)
        
        # 3. Analyze sender
        if sender:
            self._collect_sender_evidence(sender)
        
        # 4. Text quality indicators
        self._collect_text_quality_evidence(text)
        
        # 5. Content structure
        self._collect_structure_evidence(text, urls)
    
    def _collect_url_evidence(self, urls: List[str]):
        """Analyze URLs for risk indicators."""
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # SKIP safe domains entirely
                if self._is_domain_safe(domain):
                    logger.debug(f"Skipping safe domain: {domain}")
                    continue
                
                # Check for IP address in URL
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    self._add_evidence(
                        evidence_type=EvidenceType.EXTERNAL_LINK,
                        category=EvidenceCategory.INFRASTRUCTURE,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"URL contains IP address: {domain}",
                        raw_value=url,
                        specificity_boost=0.15,  # Very specific indicator
                    )
                
                # Check for URL shortener
                base_domain = self._get_base_domain(domain)
                if base_domain in URL_SHORTENERS:
                    self._add_evidence(
                        evidence_type=EvidenceType.SHORTENED_URL,
                        category=EvidenceCategory.CONTENT,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"Shortened URL hides destination: {base_domain}",
                        raw_value=url,
                    )
                
                # Check TLD
                tld = domain.split('.')[-1] if '.' in domain else ''
                if tld in SUSPICIOUS_TLDS:
                    self._add_evidence(
                        evidence_type=EvidenceType.EXTERNAL_LINK,
                        category=EvidenceCategory.INFRASTRUCTURE,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"Suspicious TLD: .{tld}",
                        raw_value=domain,
                        specificity_boost=0.1,  # Suspicious TLD is more specific
                    )
                
                # Check for excessive subdomains
                subdomain_count = domain.count('.') - 1
                if subdomain_count >= 3:
                    self._add_evidence(
                        evidence_type=EvidenceType.EXTERNAL_LINK,
                        category=EvidenceCategory.CONTENT,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"Excessive subdomains ({subdomain_count}): {domain}",
                        raw_value=domain,
                    )
                
                # Check for homoglyphs in domain
                homoglyphs_found = self._detect_homoglyphs(domain)
                if homoglyphs_found:
                    self._add_evidence(
                        evidence_type=EvidenceType.HOMOGLYPH_DETECTED,
                        category=EvidenceCategory.BRAND_IMPERSONATION,
                        source=EvidenceSource.LOOKALIKE_DETECTOR,
                        description=f"Homoglyph characters in domain: {homoglyphs_found}",
                        raw_value=domain,
                        specificity_boost=0.25,  # Homoglyphs are very suspicious
                    )
                
                # Check for brand in URL (only for non-safe domains)
                brand_match = self._check_brand_in_url(domain, url)
                if brand_match:
                    self._add_evidence(
                        evidence_type=EvidenceType.BRAND_IN_URL,
                        category=EvidenceCategory.BRAND_IMPERSONATION,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"Brand '{brand_match}' in suspicious URL",
                        raw_value=url,
                        specificity_boost=0.15,
                    )
                
                # Check for credential parameters
                query = parsed.query.lower()
                cred_params = ['email=', 'user=', 'login=', 'password=', 'account=', 'ssn=']
                for param in cred_params:
                    if param in query:
                        self._add_evidence(
                            evidence_type=EvidenceType.CREDENTIAL_REQUEST,
                            category=EvidenceCategory.CONTENT,
                            source=EvidenceSource.PATTERN_ENGINE,
                            description=f"Credential parameter in URL: {param}",
                            raw_value=url,
                            specificity_boost=0.1,
                        )
                        break
                
                # Check for no HTTPS (only a minor indicator)
                if parsed.scheme == 'http':
                    self._add_evidence(
                        evidence_type=EvidenceType.EXTERNAL_LINK,
                        category=EvidenceCategory.TECHNICAL,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description="URL uses insecure HTTP",
                        raw_value=url,
                        specificity_boost=-0.15,  # Very minor indicator
                    )
                
            except Exception as e:
                logger.warning(f"Error analyzing URL {url}: {e}")
    
    def _collect_pattern_evidence(self, text_lower: str):
        """Match smishing patterns against text."""
        for pattern_name, pattern_config in SMISHING_PATTERNS.items():
            matches = []
            
            for regex in pattern_config["keywords"]:
                try:
                    found = re.findall(regex, text_lower)
                    if found:
                        matches.extend(found)
                except re.error:
                    continue
            
            if matches:
                # Calculate specificity based on match count and quality
                match_count = len(matches)
                specificity_boost = min(match_count * 0.05, 0.2)
                
                # Map pattern to evidence type
                evidence_type = self._pattern_to_evidence_type(pattern_name)
                
                self._add_evidence(
                    evidence_type=evidence_type,
                    category=EvidenceCategory.CONTENT,
                    source=EvidenceSource.PATTERN_ENGINE,
                    description=f"{pattern_config['description']} ({match_count} indicators)",
                    raw_value=matches[:3],
                    matched_text=str(matches[0]) if matches else None,
                    mitre_technique=pattern_config.get("mitre"),
                    specificity_boost=specificity_boost,
                    metadata={"pattern_name": pattern_name, "match_count": match_count},
                )
            
            # Check for brand mentions - but only if there are also suspicious URLs
            # Brand mentions alone shouldn't flag as impersonation
            for brand in pattern_config.get("brands", []):
                if brand.lower() in text_lower:
                    # Only add as evidence if we have a suspicious URL context
                    # This will be set by _collect_url_evidence if brand is found in non-legitimate URL
                    # Store for later correlation but with very low weight
                    self._add_evidence(
                        evidence_type=EvidenceType.BRAND_KEYWORD_MISMATCH,
                        category=EvidenceCategory.BRAND_IMPERSONATION,
                        source=EvidenceSource.PATTERN_ENGINE,
                        description=f"Brand mentioned: {brand} (verify URL legitimacy)",
                        raw_value=brand,
                        specificity_boost=-0.3,  # Low weight unless corroborated by URL evidence
                    )
    
    def _collect_sender_evidence(self, sender: str):
        """Analyze sender for risk indicators."""
        # Unknown/no sender info
        if not sender or sender.lower() in ['unknown', 'none', '']:
            self._add_evidence(
                evidence_type=EvidenceType.FIRST_TIME_SENDER,
                category=EvidenceCategory.BEHAVIORAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description="Unknown or missing sender",
                raw_value=sender,
            )
        
        # Short code sender (common in smishing)
        if sender and len(sender) <= 6 and sender.isdigit():
            self._add_evidence(
                evidence_type=EvidenceType.FIRST_TIME_SENDER,
                category=EvidenceCategory.BEHAVIORAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description=f"Short code sender: {sender}",
                raw_value=sender,
            )
    
    def _collect_text_quality_evidence(self, text: str):
        """Analyze text quality indicators."""
        # Excessive caps
        if len(text) > 20:
            caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
            if caps_ratio > 0.5:
                self._add_evidence(
                    evidence_type=EvidenceType.URGENCY_LANGUAGE,
                    category=EvidenceCategory.SOCIAL_ENGINEERING,
                    source=EvidenceSource.SE_ANALYZER,
                    description=f"Excessive capitals ({int(caps_ratio*100)}%)",
                    raw_value=caps_ratio,
                    specificity_boost=-0.1,  # Common but not specific
                )
        
        # Excessive punctuation
        punct_count = len(re.findall(r'[!?]{2,}', text))
        if punct_count >= 2:
            self._add_evidence(
                evidence_type=EvidenceType.URGENCY_LANGUAGE,
                category=EvidenceCategory.SOCIAL_ENGINEERING,
                source=EvidenceSource.SE_ANALYZER,
                description=f"Excessive punctuation ({punct_count} instances)",
                raw_value=punct_count,
                specificity_boost=-0.1,
            )
        
        # Grammar/spelling indicators (simplified)
        common_errors = [
            r'kindly\s+(?:click|verify|confirm)',  # Nigerian prince style
            r'(?:dear|hello)\s+(?:customer|user|member)',  # Generic greeting
            r'(?:do\s+the\s+needful)',
            r'(?:revert\s+back)',
        ]
        for pattern in common_errors:
            if re.search(pattern, text.lower()):
                self._add_evidence(
                    evidence_type=EvidenceType.PATTERN_MATCH,
                    category=EvidenceCategory.CONTENT,
                    source=EvidenceSource.PATTERN_ENGINE,
                    description="Suspicious phrasing detected",
                    raw_value=pattern,
                )
                break
    
    def _collect_structure_evidence(self, text: str, urls: List[str]):
        """Analyze message structure."""
        # Multiple URLs
        if len(urls) >= 2:
            self._add_evidence(
                evidence_type=EvidenceType.EXTERNAL_LINK,
                category=EvidenceCategory.CONTENT,
                source=EvidenceSource.PATTERN_ENGINE,
                description=f"Multiple URLs in message ({len(urls)})",
                raw_value=len(urls),
            )
        
        # Very short message with URL (common in smishing)
        if len(text) < 100 and len(urls) >= 1:
            self._add_evidence(
                evidence_type=EvidenceType.PATTERN_MATCH,
                category=EvidenceCategory.CONTENT,
                source=EvidenceSource.PATTERN_ENGINE,
                description="Short message with URL (smishing indicator)",
                raw_value=len(text),
                specificity_boost=-0.05,  # Common pattern
            )
        
        # Urgency words
        urgency_words = ['urgent', 'immediately', 'now', 'today', 'expire', 'limited', 'act fast', 'don\'t delay']
        found_urgency = [w for w in urgency_words if w in text.lower()]
        if len(found_urgency) >= 2:
            self._add_evidence(
                evidence_type=EvidenceType.URGENCY_LANGUAGE,
                category=EvidenceCategory.SOCIAL_ENGINEERING,
                source=EvidenceSource.SE_ANALYZER,
                description=f"Urgency language: {', '.join(found_urgency[:3])}",
                raw_value=found_urgency,
                matched_text=found_urgency[0],
            )
    
    def add_from_enrichment(self, url_enrichment: List[Dict], url_sandbox: List[Dict] = None):
        """Add evidence from URL enrichment results."""
        for enrichment in url_enrichment:
            url = enrichment.get("url", "")
            
            if enrichment.get("is_malicious"):
                self._add_evidence(
                    evidence_type=EvidenceType.URL_FLAGGED_MALICIOUS,
                    category=EvidenceCategory.THREAT_INTEL,
                    source=EvidenceSource.VIRUSTOTAL,
                    description=f"URL flagged as malicious",
                    raw_value=url,
                    external_validation=0.9,
                    specificity_boost=0.2,
                )
            
            threat_score = enrichment.get("threat_score", 0)
            if threat_score > 0:
                # Normalize score to external validation
                ext_validation = min(threat_score / 100, 1.0)
                
                sources = enrichment.get("sources", [])
                source_str = ", ".join(sources[:3]) if sources else "TI"
                
                self._add_evidence(
                    evidence_type=EvidenceType.URL_FLAGGED_MALICIOUS,
                    category=EvidenceCategory.THREAT_INTEL,
                    source=EvidenceSource.VIRUSTOTAL,
                    description=f"URL threat score: {threat_score}/100 ({source_str})",
                    raw_value={"url": url, "score": threat_score},
                    external_validation=ext_validation,
                )
        
        # Sandbox results
        if url_sandbox:
            for sandbox in url_sandbox:
                if sandbox.get("is_malicious"):
                    self._add_evidence(
                        evidence_type=EvidenceType.URL_FLAGGED_MALICIOUS,
                        category=EvidenceCategory.THREAT_INTEL,
                        source=EvidenceSource.VIRUSTOTAL,  # Generic TI
                        description=f"URL confirmed malicious by sandbox",
                        raw_value=sandbox.get("url"),
                        external_validation=0.95,
                        specificity_boost=0.25,
                    )
                
                sandbox_score = sandbox.get("threat_score", 0)
                if sandbox_score > 50:
                    self._add_evidence(
                        evidence_type=EvidenceType.URL_FLAGGED_MALICIOUS,
                        category=EvidenceCategory.THREAT_INTEL,
                        source=EvidenceSource.VIRUSTOTAL,
                        description=f"Sandbox threat score: {sandbox_score}/100",
                        raw_value=sandbox.get("url"),
                        external_validation=sandbox_score / 100,
                    )
    
    def add_from_ai_analysis(self, ai_analysis: Dict[str, Any]):
        """Add evidence from AI analysis."""
        if not ai_analysis or not ai_analysis.get("enabled"):
            return
        
        # AI key findings
        for finding in ai_analysis.get("key_findings", []):
            self._add_evidence(
                evidence_type=EvidenceType.AI_DETECTION,
                category=EvidenceCategory.CONTENT,
                source=EvidenceSource.AI_ANALYSIS,
                description=finding,
                raw_value=finding,
            )
        
        # AI detected tactics
        for tactic in ai_analysis.get("social_engineering_tactics", []):
            self._add_evidence(
                evidence_type=EvidenceType.EMOTIONAL_MANIPULATION,
                category=EvidenceCategory.SOCIAL_ENGINEERING,
                source=EvidenceSource.AI_ANALYSIS,
                description=f"AI detected tactic: {tactic}",
                raw_value=tactic,
            )
    
    def _add_evidence(
        self,
        evidence_type: EvidenceType,
        category: EvidenceCategory,
        source: EvidenceSource,
        description: str,
        raw_value: Any = None,
        matched_text: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        external_validation: float = 0.0,
        specificity_boost: float = 0.0,
        metadata: Optional[Dict] = None,
    ):
        """Add evidence with calculated quality metrics."""
        # Calculate reliability
        reliability = self.reliability_calc.calculate(
            source=source,
            api_status=self.api_status,
        )
        
        # Calculate specificity with boost
        base_specificity = self.specificity_calc.calculate(
            evidence_type=evidence_type,
            matched_text=matched_text,
            context=metadata,
        )
        specificity = min(1.0, max(0.0, base_specificity + specificity_boost))
        
        evidence = Evidence(
            evidence_type=evidence_type,
            category=category,
            source=source,
            description=description,
            raw_value=raw_value,
            matched_text=matched_text,
            source_reliability=reliability,
            specificity=specificity,
            external_validation=external_validation,
            mitre_technique=mitre_technique,
            metadata=metadata or {},
        )
        
        self.evidence_list.append(evidence)
    
    def _get_base_domain(self, domain: str) -> str:
        """Extract base domain from full domain."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def _detect_homoglyphs(self, domain: str) -> List[str]:
        """Detect homoglyph characters in domain."""
        found = []
        for char in domain:
            for ascii_char, homoglyph_list in HOMOGLYPHS.items():
                if char in homoglyph_list:
                    found.append(f"{char}→{ascii_char}")
        return found
    
    def _check_brand_in_url(self, domain: str, url: str) -> Optional[str]:
        """Check if brand appears in URL path but domain is not legitimate."""
        url_lower = url.lower()
        
        for brand, legit_domains in BRAND_DOMAINS.items():
            # Check if brand keyword in URL
            if brand in url_lower:
                # But domain is not legitimate
                is_legit = any(
                    domain == d or domain.endswith(f".{d}")
                    for d in legit_domains
                )
                if not is_legit:
                    return brand
        
        return None
    
    def _pattern_to_evidence_type(self, pattern_name: str) -> EvidenceType:
        """Map pattern name to evidence type."""
        mapping = {
            "banking_smishing": EvidenceType.CREDENTIAL_REQUEST,
            "delivery_smishing": EvidenceType.PATTERN_MATCH,
            "prize_smishing": EvidenceType.REWARD_PROMISE,
            "government_smishing": EvidenceType.AUTHORITY_CLAIM,
            "tech_support_smishing": EvidenceType.FEAR_LANGUAGE,
            "crypto_smishing": EvidenceType.CREDENTIAL_REQUEST,
            "subscription_smishing": EvidenceType.PAYMENT_REQUEST,
            "account_locked_smishing": EvidenceType.FEAR_LANGUAGE,
            "refund_smishing": EvidenceType.REWARD_PROMISE,
            "job_smishing": EvidenceType.REWARD_PROMISE,
        }
        return mapping.get(pattern_name, EvidenceType.PATTERN_MATCH)
    
    def get_all_evidence(self) -> List[Evidence]:
        """Get all collected evidence."""
        return self.evidence_list


# =============================================================================
# SMS/URL ATTACK CHAIN DETECTOR
# =============================================================================

class SMSAttackChainDetector:
    """
    Detect smishing attack patterns from evidence.
    """
    
    CHAIN_PATTERNS = {
        "financial_smishing": {
            "description": "Financial account compromise smishing",
            "required": {EvidenceType.CREDENTIAL_REQUEST, EvidenceType.EXTERNAL_LINK},
            "supporting": {
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.BRAND_KEYWORD_MISMATCH,
                EvidenceType.SHORTENED_URL,
                EvidenceType.FEAR_LANGUAGE,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_MALICIOUS, EvidenceType.URL_FLAGGED_PHISHING},
        },
        "delivery_smishing": {
            "description": "Package delivery scam",
            "required": {EvidenceType.EXTERNAL_LINK},
            "required_patterns": {"delivery_smishing"},
            "supporting": {
                EvidenceType.SHORTENED_URL,
                EvidenceType.URGENCY_LANGUAGE,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING},
        },
        "prize_scam": {
            "description": "Prize/lottery scam",
            "required": {EvidenceType.REWARD_PROMISE},
            "supporting": {
                EvidenceType.EXTERNAL_LINK,
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.CREDENTIAL_REQUEST,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING},
        },
        "brand_impersonation_smishing": {
            "description": "Brand impersonation via SMS",
            "required": {EvidenceType.BRAND_KEYWORD_MISMATCH, EvidenceType.EXTERNAL_LINK},
            "supporting": {
                EvidenceType.HOMOGLYPH_DETECTED,
                EvidenceType.BRAND_IN_URL,
                EvidenceType.URGENCY_LANGUAGE,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING, EvidenceType.DOMAIN_FLAGGED},
        },
    }
    
    def detect(
        self,
        evidence_list: List[Evidence],
        ti_confidence: float = 0.0,
    ) -> List[AttackChain]:
        """Detect attack chains from evidence."""
        detected = []
        evidence_types = {e.evidence_type for e in evidence_list}
        
        for chain_name, pattern in self.CHAIN_PATTERNS.items():
            required = pattern.get("required", set())
            supporting = pattern.get("supporting", set())
            ti_boost = pattern.get("ti_boost", set())
            
            required_present = len(required & evidence_types)
            required_total = len(required)
            
            if required_total > 0 and required_present < required_total:
                continue
            
            supporting_present = len(supporting & evidence_types)
            supporting_total = len(supporting)
            
            ti_present = len(ti_boost & evidence_types)
            
            # Calculate confidence
            confidence = self._calc_confidence(
                required_present, required_total,
                supporting_present, supporting_total,
                ti_present, ti_confidence,
            )
            
            if confidence >= 0.4:
                chain = AttackChain(
                    name=chain_name,
                    confidence=confidence,
                    required_evidence=[e for e in evidence_list if e.evidence_type in required],
                    supporting_evidence=[e for e in evidence_list if e.evidence_type in supporting],
                    ti_confirmation=ti_present > 0,
                    description=pattern["description"],
                )
                detected.append(chain)
        
        detected.sort(key=lambda c: c.confidence, reverse=True)
        return detected
    
    def _calc_confidence(
        self,
        req_present: int, req_total: int,
        sup_present: int, sup_total: int,
        ti_present: int, ti_confidence: float,
    ) -> float:
        """Calculate chain confidence."""
        if req_total == 0:
            req_ratio = 1.0
        else:
            req_ratio = req_present / req_total
        
        sup_ratio = sup_present / sup_total if sup_total > 0 else 0
        ti_boost = 0.15 if ti_present > 0 else 0
        
        base = req_ratio * 0.5 + sup_ratio * 0.35 + ti_boost
        
        if ti_confidence > 0.6:
            base *= 1.15
        
        return min(base, 1.0)


# =============================================================================
# MAIN SMS/URL DYNAMIC SCORER
# =============================================================================

class SMSDynamicScorer:
    """
    Calculate dynamic risk score for SMS/URL content.
    
    Uses the same principles as email scoring:
    - Evidence-based (no hardcoded scores)
    - TI is anchor
    - Attack chains boost confidence
    """
    
    def __init__(self):
        self.evidence_weighter = DynamicEvidenceWeighter()
        self.ti_scorer = ThreatIntelScorer()
        self.chain_detector = SMSAttackChainDetector()
    
    def calculate(
        self,
        text: str,
        urls: List[str],
        sender: Optional[str] = None,
        url_enrichment: List[Dict] = None,
        url_sandbox: List[Dict] = None,
        ai_analysis: Optional[Dict] = None,
    ) -> FinalScore:
        """
        Calculate dynamic score for SMS/URL content.
        """
        # Collect evidence
        collector = SMSEvidenceCollector()
        
        # From text and URLs
        collector.collect_from_text(text, urls, sender)
        
        # CHECK: If all URLs are from safe domains, return very low score
        if collector.is_safe_domain:
            logger.info("All URLs from safe domains - returning clean score")
            return FinalScore(
                value=0,
                level="informational",
                confidence=0.95,
                verdict="⚪ SAFE - Legitimate domain (95% confidence)",
                classification="Legitimate",
                attack_chains=[],
                top_evidence=[],
                explanation=["✅ URL belongs to a known legitimate domain"],
                recommended_action="No action needed - legitimate URL",
                mitre_techniques=[],
            )
        
        # From enrichment
        if url_enrichment:
            collector.add_from_enrichment(url_enrichment, url_sandbox)
        
        # From AI
        if ai_analysis:
            collector.add_from_ai_analysis(ai_analysis)
        
        evidence_list = collector.get_all_evidence()
        
        # If no evidence and no TI flags, return low score
        if not evidence_list and not url_enrichment:
            return FinalScore(
                value=5,
                level="informational",
                confidence=0.6,
                verdict="⚪ LOW RISK - No suspicious indicators found",
                classification="Unknown",
                attack_chains=[],
                top_evidence=[],
                explanation=["No suspicious patterns detected"],
                recommended_action="Appears safe, exercise normal caution",
                mitre_techniques=[],
            )
        
        # Build TI results from enrichment
        ti_results = self._build_ti_results(url_enrichment, url_sandbox)
        ti_score = self.ti_scorer.calculate(ti_results)
        
        # Detect attack chains
        chains = self.chain_detector.detect(evidence_list, ti_score.confidence)
        
        # Calculate scores
        evidence_score = self._calc_evidence_score(evidence_list, ti_score)
        chain_score = self._calc_chain_score(chains)
        ai_score = ai_analysis.get("confidence", 0) * 20 if ai_analysis else 0
        correlation_bonus = self._calc_correlation(evidence_list, ti_score, chains)
        
        # HIGH-RISK URL PATTERN BOOST
        # Directly boost score for obvious phishing patterns
        url_risk_boost = self._calc_url_risk_boost(urls, evidence_list)
        
        # Dynamic weights
        weights = self._calc_weights(evidence_list, ti_score, chains, ai_analysis)
        
        # Final value
        final_value = (
            evidence_score * weights["evidence"] +
            ti_score.value * weights["ti"] +
            chain_score * weights["chain"] +
            ai_score * weights["ai"] +
            correlation_bonus +
            url_risk_boost  # Add URL risk boost
        )
        
        # Confidence
        confidence = self._calc_confidence(evidence_list, ti_score, chains, ai_analysis)
        
        # Level
        level = self._calc_level(final_value, confidence)
        
        # Classification
        classification = self._determine_classification(chains, evidence_list)
        
        # Build result
        result = FinalScore(
            value=min(100, max(0, int(final_value))),
            level=level,
            confidence=confidence,
            verdict=self._gen_verdict(final_value, level, confidence),
            classification=classification,
            attack_chains=chains,
            top_evidence=sorted(evidence_list, key=lambda e: e.quality_score, reverse=True)[:10],
            explanation=self._gen_explanation(evidence_list, ti_score, chains),
            recommended_action=self._gen_action(level, chains),
            mitre_techniques=self._extract_mitre(chains, evidence_list),
        )
        
        # Breakdown
        result.breakdown = ScoreBreakdown(
            evidence_score=evidence_score,
            evidence_weight=weights["evidence"],
            ti_score=ti_score.value,
            ti_weight=weights["ti"],
            chain_score=chain_score,
            chain_weight=weights["chain"],
            ai_score=ai_score,
            ai_weight=weights["ai"],
            correlation_bonus=correlation_bonus,
        )
        
        return result
    
    def _build_ti_results(
        self,
        url_enrichment: List[Dict] = None,
        url_sandbox: List[Dict] = None,
    ) -> Dict[str, Any]:
        """Build TI results structure from enrichment data."""
        sources = {}
        sources_checked = 0
        sources_flagged = 0
        
        if url_enrichment:
            for enrichment in url_enrichment:
                threat_score = enrichment.get("threat_score", 0)
                is_malicious = enrichment.get("is_malicious", False)
                
                for source in enrichment.get("sources", []):
                    sources_checked += 1
                    if is_malicious or threat_score > 30:
                        sources_flagged += 1
                        sources[source] = {
                            "verdict": "malicious" if is_malicious else "suspicious",
                            "score": threat_score,
                        }
        
        if url_sandbox:
            for sandbox in url_sandbox:
                sources_checked += 1
                if sandbox.get("is_malicious"):
                    sources_flagged += 1
                    sources["sandbox"] = {
                        "verdict": "malicious",
                        "score": sandbox.get("threat_score", 80),
                    }
        
        return {
            "sources": sources,
            "sources_checked": sources_checked,
            "sources_flagged": sources_flagged,
        }
    
    def _calc_evidence_score(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
    ) -> float:
        """Calculate evidence score with aggressive threat detection."""
        if not evidence_list:
            return 0.0
        
        total = 0.0
        high_risk_indicators = 0
        
        for evidence in evidence_list:
            weight = self.evidence_weighter.calculate_weight(
                evidence, evidence_list, ti_score
            )
            
            # Base contribution
            contrib = evidence.quality_score * weight * 18
            
            # BOOST for high-risk evidence types
            if evidence.evidence_type in [
                EvidenceType.HOMOGLYPH_DETECTED,
                EvidenceType.BRAND_IN_URL,
                EvidenceType.BRAND_KEYWORD_MISMATCH,
                EvidenceType.CREDENTIAL_REQUEST,
            ]:
                contrib *= 1.5
                high_risk_indicators += 1
            
            # BOOST for suspicious TLDs
            if evidence.category == EvidenceCategory.INFRASTRUCTURE:
                if "suspicious tld" in (evidence.description or "").lower():
                    contrib *= 1.4
                    high_risk_indicators += 1
            
            # BOOST for URL shorteners (hiding destination)
            if evidence.evidence_type == EvidenceType.SHORTENED_URL:
                contrib *= 1.3
            
            total += contrib
        
        # Softer diminishing returns
        count = len(evidence_list)
        if count > 1:
            scale = 1 + (math.log(count + 1) / math.log(8))
            total = (total / scale) * 1.6
        
        # High-risk indicator bonus
        if high_risk_indicators >= 2:
            total += 20
        elif high_risk_indicators >= 1:
            total += 10
        
        return min(100, total)
    
    def _calc_chain_score(self, chains: List[AttackChain]) -> float:
        """Calculate chain contribution with higher impact."""
        if not chains:
            return 0.0
        
        score = 0.0
        for chain in chains:
            # Increased chain contribution
            contrib = chain.confidence * 45
            if chain.ti_confirmation:
                contrib *= 1.4
            score += contrib
        
        return min(score, 60)
    
    def _calc_correlation(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
    ) -> float:
        """Calculate correlation bonus - increased for better detection."""
        bonus = 0.0
        
        categories = {e.category for e in evidence_list}
        if len(categories) >= 3:
            bonus += 8
        elif len(categories) >= 2:
            bonus += 4
        
        if ti_score.sources_flagged >= 1 and len(evidence_list) >= 2:
            bonus += 10
        
        for chain in chains:
            if chain.ti_confirmation and chain.confidence > 0.4:
                bonus += 8
            elif chain.confidence > 0.5:
                bonus += 5
        
        # Bonus for multiple evidence pieces
        if len(evidence_list) >= 5:
            bonus += 5
        
        return min(bonus, 25)
    
    def _calc_url_risk_boost(
        self,
        urls: List[str],
        evidence_list: List[Evidence],
    ) -> float:
        """
        Calculate direct URL risk boost for obvious phishing patterns.
        
        This catches cases where URL structure alone indicates phishing:
        - Suspicious TLD + brand impersonation
        - Homoglyphs in domain
        - Known phishing patterns
        """
        if not urls:
            return 0.0
        
        boost = 0.0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()
                
                # Skip safe domains
                if domain in SAFE_DOMAINS or any(domain.endswith(f".{sd}") for sd in SAFE_DOMAINS):
                    continue
                
                tld = domain.split('.')[-1] if '.' in domain else ''
                
                # HIGH RISK: Suspicious TLD + brand in domain/path
                if tld in SUSPICIOUS_TLDS:
                    boost += 15  # Base boost for suspicious TLD
                    
                    # Check for brand impersonation
                    for brand in BRAND_DOMAINS.keys():
                        if brand in domain or brand in path:
                            boost += 25  # Brand + suspicious TLD = phishing
                            logger.info(f"High-risk pattern: {brand} in {domain} with .{tld}")
                            break
                
                # HIGH RISK: Homoglyphs (character substitution)
                has_homoglyph = any(
                    e.evidence_type == EvidenceType.HOMOGLYPH_DETECTED 
                    for e in evidence_list
                )
                if has_homoglyph:
                    boost += 25
                
                # MEDIUM RISK: Brand in non-brand domain
                for brand, legit_domains in BRAND_DOMAINS.items():
                    if brand in domain:
                        is_legit = any(
                            domain == d or domain.endswith(f".{d}") 
                            for d in legit_domains
                        )
                        if not is_legit:
                            boost += 20
                            break
                
                # MEDIUM RISK: Login/verify/secure in path with suspicious domain
                risky_paths = ['login', 'verify', 'secure', 'account', 'update', 'confirm']
                for risky in risky_paths:
                    if risky in path:
                        boost += 10
                        break
                
                # MEDIUM RISK: URL shortener
                base_domain = domain.split('.')[-2] + '.' + tld if domain.count('.') >= 1 else domain
                if base_domain in URL_SHORTENERS or domain in URL_SHORTENERS:
                    boost += 12
                
            except Exception as e:
                logger.warning(f"Error calculating URL risk boost: {e}")
        
        return min(boost, 50)  # Cap at 50 to prevent runaway scores
    
    def _calc_weights(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
        ai_analysis: Optional[Dict],
    ) -> Dict[str, float]:
        """Calculate dynamic weights."""
        evidence_weight = 0.35 if evidence_list else 0
        ti_weight = 0.40 * ti_score.confidence if ti_score.confidence > 0 else 0
        chain_weight = 0.18 if chains else 0
        ai_weight = 0.12 if ai_analysis else 0
        
        total = evidence_weight + ti_weight + chain_weight + ai_weight
        if total == 0:
            return {"evidence": 0, "ti": 0, "chain": 0, "ai": 0}
        
        return {
            "evidence": evidence_weight / total,
            "ti": ti_weight / total,
            "chain": chain_weight / total,
            "ai": ai_weight / total,
        }
    
    def _calc_confidence(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
        ai_analysis: Optional[Dict],
    ) -> float:
        """Calculate overall confidence."""
        conf = 0.0
        
        if evidence_list:
            avg_q = sum(e.quality_score for e in evidence_list) / len(evidence_list)
            conf += min(len(evidence_list) / 6, 0.25) * (0.8 + avg_q * 0.4)
        
        conf += ti_score.confidence * 0.35
        
        if chains:
            best = max(chains, key=lambda c: c.confidence)
            conf += best.confidence * 0.20
        
        if ai_analysis:
            conf += 0.08
        
        return min(conf, 1.0)
    
    def _calc_level(self, score: float, confidence: float) -> str:
        """
        Calculate risk level using dynamic thresholds from centralized config.
        
        Philosophy: Better to flag and review than to miss threats (10% FP acceptable)
        
        Thresholds tuned for maximum threat detection with acceptable FP rate.
        """
        if USE_CENTRALIZED_CONFIG:
            config = get_scoring_config()
            thresholds = config.thresholds
            
            # Use confidence-adjusted thresholds from config
            critical = thresholds.get_threshold("critical", confidence)
            high = thresholds.get_threshold("high", confidence)
            medium = thresholds.get_threshold("medium", confidence)
            low = thresholds.get_threshold("low", confidence)
            
            if score >= critical:
                return "critical"
            elif score >= high:
                return "high"
            elif score >= medium:
                return "medium"
            elif score >= low:
                return "low"
            return "informational"
        
        # Fallback to hardcoded values
        if confidence >= 0.55:
            # High confidence - aggressive thresholds
            if score >= 50:
                return "critical"
            elif score >= 30:
                return "high"
            elif score >= 18:
                return "medium"
            elif score >= 8:
                return "low"
        elif confidence >= 0.30:
            # Medium confidence - still aggressive
            if score >= 60:
                return "critical"
            elif score >= 40:
                return "high"
            elif score >= 22:
                return "medium"
            elif score >= 10:
                return "low"
        else:
            # Low confidence - flag anything suspicious
            if score >= 75:
                return "critical"
            elif score >= 50:
                return "high"
            elif score >= 28:
                return "medium"
            elif score >= 12:
                return "low"
        
        return "informational"
    
    def _determine_classification(
        self,
        chains: List[AttackChain],
        evidence_list: List[Evidence],
    ) -> str:
        """Determine threat classification."""
        if chains:
            best = max(chains, key=lambda c: c.confidence)
            return best.name.replace("_", " ").title()
        
        evidence_types = {e.evidence_type for e in evidence_list}
        
        if EvidenceType.CREDENTIAL_REQUEST in evidence_types:
            return "Credential Phishing"
        if EvidenceType.PAYMENT_REQUEST in evidence_types:
            return "Financial Scam"
        if EvidenceType.REWARD_PROMISE in evidence_types:
            return "Prize Scam"
        if EvidenceType.FEAR_LANGUAGE in evidence_types:
            return "Fear-based Scam"
        if EvidenceType.BRAND_KEYWORD_MISMATCH in evidence_types:
            return "Brand Impersonation"
        
        return "Suspicious"
    
    def _gen_verdict(self, score: float, level: str, confidence: float) -> str:
        """Generate verdict string."""
        conf_pct = int(confidence * 100)
        
        verdicts = {
            "critical": f"🔴 CRITICAL THREAT ({conf_pct}% confidence) - Do not interact",
            "high": f"🟠 HIGH RISK ({conf_pct}% confidence) - Likely scam/phishing",
            "medium": f"🟡 SUSPICIOUS ({conf_pct}% confidence) - Exercise caution",
            "low": f"🟢 LOW RISK ({conf_pct}% confidence) - Minor indicators",
            "informational": f"⚪ APPEARS SAFE ({conf_pct}% confidence)",
        }
        return verdicts.get(level, f"Score: {score}")
    
    def _gen_explanation(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
    ) -> List[str]:
        """Generate explanation."""
        exp = []
        
        sorted_ev = sorted(evidence_list, key=lambda e: e.quality_score, reverse=True)
        for e in sorted_ev[:5]:
            icon = "🔴" if e.quality_score >= 0.7 else "🟡" if e.quality_score >= 0.4 else "⚪"
            exp.append(f"{icon} {e.description}")
        
        if ti_score.sources_flagged > 0:
            exp.append(f"🔍 TI: {ti_score.sources_flagged} source(s) flagged URL/domain")
        
        for chain in chains:
            exp.append(f"⛓️ Pattern: {chain.description} ({int(chain.confidence*100)}% match)")
        
        return exp
    
    def _gen_action(self, level: str, chains: List[AttackChain]) -> str:
        """Generate recommended action."""
        actions = {
            "critical": "DO NOT CLICK - Delete message immediately, report as spam/phishing",
            "high": "AVOID clicking links - Verify through official channels if concerned",
            "medium": "EXERCISE CAUTION - Verify sender before taking any action",
            "low": "Likely safe but verify if requesting sensitive information",
            "informational": "No action needed",
        }
        return actions.get(level, "Review manually")
    
    def _extract_mitre(
        self,
        chains: List[AttackChain],
        evidence_list: List[Evidence],
    ) -> List[Dict[str, str]]:
        """Extract MITRE techniques."""
        mitre = []
        seen = set()
        
        for chain in chains:
            for tech in chain.mitre_tactics:
                if tech not in seen:
                    mitre.append({"technique_id": tech, "source": chain.name})
                    seen.add(tech)
        
        for e in evidence_list:
            if e.mitre_technique and e.mitre_technique not in seen:
                mitre.append({"technique_id": e.mitre_technique, "source": e.source.value})
                seen.add(e.mitre_technique)
        
        return mitre


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def calculate_sms_dynamic_score(
    text: str,
    urls: List[str],
    sender: Optional[str] = None,
    url_enrichment: List[Dict] = None,
    url_sandbox: List[Dict] = None,
    ai_analysis: Optional[Dict] = None,
) -> FinalScore:
    """
    Convenience function to calculate dynamic SMS/URL score.
    
    This is the main entry point for SMS/URL scoring.
    """
    scorer = SMSDynamicScorer()
    return scorer.calculate(
        text=text,
        urls=urls,
        sender=sender,
        url_enrichment=url_enrichment,
        url_sandbox=url_sandbox,
        ai_analysis=ai_analysis,
    )
