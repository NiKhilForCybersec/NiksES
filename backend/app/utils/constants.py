"""
NiksES Constants - Central location for ALL constant values.
"""

from typing import Dict, List, Tuple

# APPLICATION INFO
APP_NAME: str = "NiksES"
APP_FULL_NAME: str = "Niks Email Security"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = "AI-Powered Email Investigation Copilot"

# FILE LIMITS
MAX_EMAIL_SIZE_MB: int = 25
MAX_EMAIL_SIZE_BYTES: int = MAX_EMAIL_SIZE_MB * 1024 * 1024
MAX_ATTACHMENT_SIZE_MB: int = 10
MAX_ATTACHMENT_SIZE_BYTES: int = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
MAX_URLS_PER_EMAIL: int = 100
MAX_ATTACHMENTS_PER_EMAIL: int = 50
MAX_BODY_PREVIEW_LENGTH: int = 500

# RISK SCORING
RISK_THRESHOLDS: Dict[str, Tuple[int, int]] = {
    "informational": (0, 19),
    "low": (20, 39),
    "medium": (40, 59),
    "high": (60, 79),
    "critical": (80, 100)
}

DEFAULT_RISK_THRESHOLD_HIGH: int = 70
DEFAULT_RISK_THRESHOLD_CRITICAL: int = 85

# API RATE LIMITS
VIRUSTOTAL_RATE_LIMIT_PER_MINUTE: int = 4
VIRUSTOTAL_RATE_LIMIT_PER_DAY: int = 500
ABUSEIPDB_RATE_LIMIT_PER_DAY: int = 1000
GEOIP_RATE_LIMIT_PER_MINUTE: int = 45

# TIMEOUTS (seconds)
API_TIMEOUT_DEFAULT: int = 30
API_TIMEOUT_ENRICHMENT: int = 45  # Increased for VirusTotal which can be slow
API_TIMEOUT_AI: int = 60
WHOIS_TIMEOUT: int = 15
DNS_TIMEOUT: int = 10

# EXTERNAL API URLS
VIRUSTOTAL_API_URL: str = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL: str = "https://api.abuseipdb.com/api/v2"
URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1"
PHISHTANK_API_URL: str = "https://checkurl.phishtank.com/checkurl/"
GEOIP_API_URL: str = "http://ip-api.com/json"
OPENAI_API_URL: str = "https://api.openai.com/v1"

# DOMAIN LISTS
FREEMAIL_DOMAINS: List[str] = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com",
    "zoho.com", "yandex.com", "gmx.com", "live.com",
    "msn.com", "me.com", "inbox.com", "ymail.com"
]

SHORTENER_DOMAINS: List[str] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
    "rebrand.ly", "short.io", "cutt.ly", "rb.gy", "tiny.cc",
    "shorturl.at", "v.gd", "clck.ru", "qps.ru"
]

# Legitimate Financial Institution Domains
# These domains are excluded from certain BEC/spam detection rules
LEGITIMATE_FINANCIAL_DOMAINS: List[str] = [
    # Indian Banks
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "yesbank.in", "indusind.com", "rbl.bank",
    "federalbank.co.in", "idfcfirstbank.com", "bandhanbank.com",
    # US Banks
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "usbank.com", "pnc.com", "capitalone.com", "tdbank.com",
    # UK Banks
    "barclays.co.uk", "hsbc.co.uk", "lloydsbank.com", "natwest.com",
    "santander.co.uk", "halifax.co.uk", "tsb.co.uk",
    # International Banks
    "hsbc.com", "standardchartered.com", "db.com", "ubs.com",
    "credit-suisse.com", "ing.com", "bnpparibas.com",
    # Payment Processors
    "paypal.com", "stripe.com", "square.com", "razorpay.com",
    "paytm.com", "phonepe.com",
    # Financial Services
    "fidelity.com", "schwab.com", "vanguard.com", "ameriprise.com",
]

SUSPICIOUS_TLDS: List[str] = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".work", ".click", ".link", ".info", ".biz", ".online",
    ".site", ".website", ".space", ".pw", ".cc", ".ws",
    ".icu", ".buzz", ".rest", ".fit", ".surf",
    # Romance/Dating spam TLDs
    ".lol", ".fun", ".life", ".live", ".dating", ".date",
    ".love", ".chat", ".cam", ".xxx", ".adult", ".sex", ".sexy",
    # Additional abuse-prone TLDs
    ".win", ".loan", ".stream", ".download", ".racing", ".accountant",
    ".science", ".gdn", ".men", ".party", ".review", ".trade",
    ".bid", ".cricket", ".faith", ".kim", ".country", ".support"
]

# Romance/Dating Spam Keywords
ROMANCE_SPAM_KEYWORDS: List[str] = [
    "sexy", "chat with me", "contact me here", "dating", "hook up",
    "hookup", "meet me", "meet singles", "lonely", "bored", "hot singles",
    "adult", "webcam", "cam girl", "private chat", "naughty", "flirt",
    "looking for fun", "single and ready", "no strings attached",
    "casual encounter", "get together", "hang out", "chat about something",
    "meet local", "find love", "romance", "intimate", "discreet",
]

# Spam domain patterns
SPAM_DOMAIN_PATTERNS: List[str] = [
    r"dating", r"meet", r"chat", r"singles", r"hook", r"love",
    r"adult", r"sexy", r"cam", r"flirt", r"romance",
]

# FILE EXTENSIONS
DANGEROUS_EXTENSIONS: Dict[str, List[str]] = {
    "executable": [".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".msi", ".dll", ".cpl"],
    "script": [".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1"],
    "macro_enabled": [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".potm", ".ppam"],
    "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".cab", ".arj"],
    "other_risky": [".hta", ".jar", ".lnk", ".reg", ".scf", ".url", ".inf", ".application"]
}

ALLOWED_UPLOAD_EXTENSIONS: List[str] = [".eml", ".msg"]

# AI CONFIGURATION
DEFAULT_LLM_MODEL: str = "gpt-4o-mini"
DEFAULT_LLM_MAX_TOKENS: int = 2000
DEFAULT_LLM_TEMPERATURE: float = 0.3

# DATABASE
DEFAULT_PAGE_SIZE: int = 50
MAX_PAGE_SIZE: int = 100

# CACHE
CACHE_TTL_ENRICHMENT: int = 3600  # 1 hour
CACHE_TTL_WHOIS: int = 86400  # 24 hours

# NEWLY REGISTERED DOMAIN THRESHOLD
NEWLY_REGISTERED_DAYS_THRESHOLD: int = 30

# BRAND IMPERSONATION TARGETS
BRAND_TARGETS: Dict[str, Dict] = {
    "microsoft": {
        "name": "Microsoft",
        "keywords": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "teams", "azure"],
        "legitimate_domains": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"]
    },
    "google": {
        "name": "Google",
        "keywords": ["google", "gmail", "drive", "workspace", "docs", "sheets"],
        "legitimate_domains": ["google.com", "gmail.com", "googlemail.com", "googleapis.com"]
    },
    "amazon": {
        "name": "Amazon",
        "keywords": ["amazon", "prime", "aws", "alexa", "kindle"],
        "legitimate_domains": ["amazon.com", "amazon.co.uk", "amazonaws.com"]
    },
    "paypal": {
        "name": "PayPal",
        "keywords": ["paypal", "pay pal"],
        "legitimate_domains": ["paypal.com", "paypal.me"]
    },
    "apple": {
        "name": "Apple",
        "keywords": ["apple", "icloud", "itunes", "app store", "apple id", "appleid"],
        "legitimate_domains": ["apple.com", "icloud.com", "me.com", "itunes.com", "mzstatic.com"]
    },
    # Indian Banks
    "axis_bank": {
        "name": "Axis Bank",
        "keywords": ["axis bank", "axis"],
        "legitimate_domains": ["axisbank.com", "trans.axisbank.com", "email.axisbank.com"]
    },
    "hdfc_bank": {
        "name": "HDFC Bank",
        "keywords": ["hdfc bank", "hdfc"],
        "legitimate_domains": ["hdfcbank.com", "hdfcbank.net"]
    },
    "icici_bank": {
        "name": "ICICI Bank",
        "keywords": ["icici bank", "icici"],
        "legitimate_domains": ["icicibank.com", "icicibank.co.in"]
    },
    "sbi": {
        "name": "State Bank of India",
        "keywords": ["sbi", "state bank of india", "state bank"],
        "legitimate_domains": ["sbi.co.in", "onlinesbi.com"]
    },
    # US Banks
    "chase": {
        "name": "Chase",
        "keywords": ["chase", "jpmorgan"],
        "legitimate_domains": ["chase.com", "jpmorganchase.com"]
    },
    "bank_of_america": {
        "name": "Bank of America",
        "keywords": ["bank of america", "bofa"],
        "legitimate_domains": ["bankofamerica.com", "bofa.com", "boa.com"]
    },
    "wells_fargo": {
        "name": "Wells Fargo",
        "keywords": ["wells fargo"],
        "legitimate_domains": ["wellsfargo.com", "wf.com"]
    },
    "citi": {
        "name": "Citibank",
        "keywords": ["citibank", "citi"],
        "legitimate_domains": ["citi.com", "citibank.com", "citicards.com"]
    },
}

# SOCIAL ENGINEERING KEYWORDS
URGENCY_KEYWORDS: List[str] = [
    "immediately", "urgent", "within 24 hours", "action required",
    "expire", "suspended", "terminated", "verify now", "act now",
    "limited time", "final notice", "last chance", "deadline",
    "within 48 hours", "24 hours", "48 hours", "time sensitive",
    "respond immediately", "requires immediate", "do not ignore",
]

AUTHORITY_KEYWORDS: List[str] = [
    "ceo", "cfo", "cto", "president", "director", "executive",
    "it department", "it support", "help desk", "tech support",
    "human resources", "hr department", "payroll", "administrator",
    "security team", "account security", "fraud department",
]

FEAR_KEYWORDS: List[str] = [
    "account will be closed", "legal action", "police",
    "unauthorized access", "security breach", "compromised",
    "locked out", "terminated", "suspended", "deleted",
    "permanently restricted", "permanently deleted", "permanently suspended",
    "access may be", "will be restricted", "will be suspended",
    "limited state", "unusual sign-in", "unusual activity",
]

BEC_KEYWORDS: List[str] = [
    "wire transfer", "bank transfer", "payment", "invoice",
    "routing number", "account number", "swift", "iban",
    "ach", "funds", "remittance", "confidential"
]

# RISK LEVEL CONSTANTS
RISK_LEVEL_INFORMATIONAL: str = "informational"
RISK_LEVEL_LOW: str = "low"
RISK_LEVEL_MEDIUM: str = "medium"
RISK_LEVEL_HIGH: str = "high"
RISK_LEVEL_CRITICAL: str = "critical"

# VERDICT CONSTANTS
VERDICT_CLEAN: str = "clean"
VERDICT_SUSPICIOUS: str = "suspicious"
VERDICT_MALICIOUS: str = "malicious"
VERDICT_UNKNOWN: str = "unknown"
