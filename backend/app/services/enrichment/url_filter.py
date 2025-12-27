"""
URL Filter for Threat Intelligence

Filters URLs before sending to TI APIs to:
1. Skip image/asset URLs
2. Skip known safe domains
3. Skip tracking pixels
4. Prioritize suspicious URLs

This saves API quota and speeds up analysis.
"""

import re
import logging
from typing import List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Known safe domains that don't need TI checking
SAFE_DOMAINS = {
    # === Major Tech Companies ===
    "google.com", "www.google.com", "googleapis.com", "google.co.uk", "google.ca",
    "microsoft.com", "www.microsoft.com", "office.com", "office365.com",
    "outlook.com", "live.com", "hotmail.com", "msn.com", "bing.com",
    "apple.com", "www.apple.com", "icloud.com", "mzstatic.com",
    "amazon.com", "www.amazon.com", "amazonaws.com", "aws.amazon.com", "amazon.co.uk",
    "facebook.com", "www.facebook.com", "fb.com", "meta.com", "fb.me",
    "twitter.com", "x.com", "twimg.com", "t.co",
    "linkedin.com", "www.linkedin.com", "licdn.com",
    "github.com", "www.github.com", "githubusercontent.com", "github.io",
    "youtube.com", "www.youtube.com", "youtu.be", "ytimg.com", "yt.be",
    "instagram.com", "www.instagram.com", "cdninstagram.com",
    "tiktok.com", "www.tiktok.com",
    "pinterest.com", "pinimg.com",
    "reddit.com", "www.reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
    "snapchat.com", "snap.com",
    "whatsapp.com", "whatsapp.net",
    "telegram.org", "telegram.me", "t.me",
    "discord.com", "discord.gg", "discordapp.com",
    
    # === Email Providers ===
    "gmail.com", "mail.google.com", "googlemail.com",
    "yahoo.com", "mail.yahoo.com", "ymail.com", "yahoo.co.uk",
    "protonmail.com", "proton.me", "pm.me",
    "zoho.com", "zohomail.com",
    "aol.com", "mail.aol.com",
    "icloud.com", "me.com", "mac.com",
    
    # === CDNs and Infrastructure ===
    "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com", "cdnjs.cloudflare.com",
    "akamai.com", "akamaized.net", "akamaihd.net", "akamaitechnologies.com",
    "fastly.net", "fastlylb.net", "fastly.com",
    "cloudfront.net", "d1.awsstatic.com", "s3.amazonaws.com",
    "gstatic.com", "ggpht.com", "googleusercontent.com",
    "fbcdn.net", "fbsbx.com", "facebook.net",
    "twimg.com", "abs.twimg.com",
    "pinimg.com", "pinterest.com",
    "imgur.com", "i.imgur.com",
    "staticflickr.com", "flickr.com",
    "vimeo.com", "vimeocdn.com",
    "bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "jsdelivr.net", "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.com",
    
    # === Common SaaS ===
    "salesforce.com", "force.com", "salesforceliveagent.com",
    "slack.com", "slack-edge.com", "slackb.com",
    "zoom.us", "zoomgov.com", "zoom.com",
    "dropbox.com", "dropboxstatic.com", "dropboxusercontent.com",
    "box.com", "boxcdn.net", "box.net",
    "notion.so", "notion.com", "notion.site",
    "atlassian.com", "atlassian.net", "jira.com", "bitbucket.org", "trello.com",
    "zendesk.com", "zdassets.com", "zopim.com",
    "hubspot.com", "hsforms.com", "hubspotusercontent.com", "hs-analytics.net",
    "mailchimp.com", "mailchimpapp.com", "list-manage.com", "campaign-archive.com",
    "sendgrid.net", "sendgrid.com",
    "constantcontact.com", "ctctcdn.com",
    "mailgun.com", "mailgun.org",
    "typeform.com",
    "calendly.com",
    "docusign.com", "docusign.net",
    "adobe.com", "adobelogin.com", "typekit.net", "creativecloud.com",
    "canva.com", "canva.cn",
    "figma.com",
    "miro.com",
    "asana.com",
    "monday.com",
    "clickup.com",
    "basecamp.com",
    "evernote.com",
    "todoist.com",
    "stripe.com", "stripe.network",
    "paypal.com", "paypalobjects.com",
    "squareup.com", "square.com",
    "shopify.com", "myshopify.com", "shopifycdn.com",
    "wix.com", "wixstatic.com",
    "squarespace.com", "sqspcdn.com",
    "webflow.com", "webflow.io",
    "godaddy.com",
    "namecheap.com",
    "cloudinary.com", "res.cloudinary.com",
    "twilio.com", "twilio.org",
    "plaid.com",
    "okta.com", "oktacdn.com",
    "auth0.com",
    
    # === Analytics/Tracking (safe but not threat) ===
    "google-analytics.com", "googletagmanager.com", "googleoptimize.com",
    "googlesyndication.com", "googleadservices.com", "doubleclick.net",
    "facebook.net", "connect.facebook.net",
    "analytics.twitter.com",
    "hotjar.com", "hotjar.io",
    "mixpanel.com",
    "segment.com", "segment.io",
    "amplitude.com",
    "heap.io", "heapanalytics.com",
    "fullstory.com",
    "crazyegg.com",
    "mouseflow.com",
    "luckyorange.com",
    "intercom.io", "intercomcdn.com",
    "crisp.chat",
    "drift.com", "driftt.com",
    "tawk.to",
    "zopim.com",
    "freshdesk.com", "freshchat.com",
    "olark.com",
    "livechatinc.com",
    "optimizely.com",
    "launchdarkly.com",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "onesignal.com",
    "pusher.com",
    "pubnub.com",
    "ably.io",
    "sentry.io",
    "bugsnag.com",
    "newrelic.com",
    "datadoghq.com",
    "pingdom.com",
    "statuspage.io",
    
    # === Font Providers ===
    "fonts.googleapis.com", "fonts.gstatic.com",
    "use.typekit.net", "typekit.net", "p.typekit.net",
    "use.fontawesome.com", "fontawesome.com", "kit.fontawesome.com",
    "fonts.bunny.net",
    "fonts.adobe.com",
    
    # === Development/Technical ===
    "npmjs.com", "registry.npmjs.org",
    "pypi.org", "pythonhosted.org",
    "rubygems.org",
    "nuget.org",
    "maven.org", "mvnrepository.com",
    "packagist.org",
    "crates.io",
    "docker.com", "docker.io", "dockerhub.com",
    "kubernetes.io",
    "terraform.io",
    "ansible.com",
    "jenkins.io",
    "circleci.com",
    "travis-ci.org", "travis-ci.com",
    "gitlab.com",
    "bitbucket.org",
    "codepen.io",
    "jsfiddle.net",
    "codesandbox.io",
    "replit.com",
    "vercel.com", "vercel.app",
    "netlify.com", "netlify.app",
    "heroku.com", "herokuapp.com",
    "render.com", "onrender.com",
    "railway.app",
    "fly.io",
    "digitalocean.com",
    "linode.com",
    "vultr.com",
    
    # === Media/News (commonly in emails) ===
    "nytimes.com", "washingtonpost.com", "wsj.com",
    "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com",
    "medium.com", "substack.com",
    "wordpress.com", "wp.com", "wordpress.org",
    "blogger.com", "blogspot.com",
    "tumblr.com",
    
    # === Other Common Safe ===
    "wikipedia.org", "wikimedia.org", "wiktionary.org",
    "stackoverflow.com", "stackexchange.com", "askubuntu.com",
    "quora.com",
    "yelp.com",
    "tripadvisor.com",
    "booking.com",
    "airbnb.com",
    "uber.com",
    "lyft.com",
    "doordash.com",
    "grubhub.com",
    "instacart.com",
    "target.com",
    "walmart.com",
    "bestbuy.com",
    "costco.com",
    "homedepot.com",
    "lowes.com",
    "etsy.com",
    "ebay.com",
    "craigslist.org",
    "zillow.com",
    "realtor.com",
    "indeed.com",
    "glassdoor.com",
    "monster.com",
    "linkedin.com",
    "w3.org", "www.w3.org",
    "ietf.org",
    "iso.org",
    "ieee.org",
    "gravatar.com",
    "disqus.com",
    "recaptcha.net", "gstatic.com",
    "hcaptcha.com",
    "turnstile.com",
}

# File extensions that indicate non-threat assets
SAFE_EXTENSIONS = {
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp", ".tiff",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Styles
    ".css",
    # Other assets
    ".map",
}

# Patterns that indicate tracking/analytics (not threats)
TRACKING_PATTERNS = [
    # Pixel tracking
    r"/track", r"/pixel", r"/beacon", r"/1x1", r"/spacer",
    r"/open\?", r"/click\?", r"/__utm", r"/collect\?",
    r"/tr\?", r"/t\.gif", r"/blank\.gif", r"/clear\.gif",
    r"unsubscribe", r"/unsub", r"/optout", r"/opt-out",
    r"/preferences", r"/manage",
    # Email tracking pixels
    r"/o\.gif", r"/e\.gif", r"/i\.gif", r"/p\.gif",
    r"wf\.gif", r"trk\.gif", r"read\.gif",
    r"/open/", r"/read/", r"/view/",
    r"mailtrack", r"emailtrack", r"tracker",
    r"/cl/", r"/ck/", r"/lnk/",  # Click tracking
    # Analytics endpoints
    r"/analytics", r"/stats", r"/metrics",
    r"/event", r"/log", r"/ping",
    r"bat\.bing\.com", r"b\.scorecardresearch",
    r"px\.ads", r"cm\.g\.doubleclick",
    # Marketing/Email service tracking
    r"list-manage", r"campaign-archive",
    r"sendgrid\.net/wf/", r"sendgrid\.net/mpss/",
    r"mailchimp.*track", r"constantcontact.*track",
    r"hubspot.*track", r"pardot",
]

# Patterns that indicate suspicious URLs (should check these!)
SUSPICIOUS_PATTERNS = [
    # === Authentication/Account Phishing ===
    r"signin", r"sign-in", r"sign_in", r"login", r"log-in", r"log_in", r"logon", r"log-on",
    r"verify", r"verif", r"confirm", r"validate", r"authenticate", r"auth",
    r"secure", r"security", r"account", r"myaccount", r"my-account",
    r"password", r"passwd", r"credential", r"cred",
    r"update.*account", r"account.*update", r"update.*info", r"update.*detail",
    r"unlock", r"restore", r"recover", r"reset",
    
    # === Urgency/Threat Keywords ===
    r"suspend", r"locked", r"disabled", r"limited", r"restrict",
    r"unusual", r"alert", r"warning", r"urgent", r"immediate",
    r"expire", r"expir", r"deadline", r"within.*hours", r"within.*day",
    r"action.*required", r"required.*action", r"must.*verify",
    r"problem.*with", r"issue.*with", r"trouble",
    
    # === Financial/Payment ===
    r"paypal", r"paypa1", r"paypai", r"paypol",  # PayPal + typos
    r"payment", r"pay-ment", r"billing", r"invoice", r"receipt",
    r"banking", r"bank-", r"-bank", r"netbank", r"online.*bank",
    r"wallet", r"transaction", r"transfer", r"wire",
    r"credit.*card", r"debit.*card", r"card.*detail",
    r"refund", r"reimburse", r"cashback",
    r"crypto", r"bitcoin", r"btc", r"ethereum", r"eth", r"usdt",
    
    # === Brand Impersonation (common targets) ===
    r"microsoft", r"micros0ft", r"microsft", r"m1crosoft", r"mircosoft",
    r"apple", r"app1e", r"applе", r"icloud", r"icl0ud",
    r"google", r"g00gle", r"googie", r"gmail", r"gmai1",
    r"amazon", r"amaz0n", r"amazn", r"aws",
    r"facebook", r"faceb00k", r"fb", r"meta",
    r"netflix", r"netf1ix", r"netfiix",
    r"instagram", r"1nstagram", r"instagrm",
    r"twitter", r"twltter", r"x\.com",
    r"linkedin", r"linkedln", r"1inkedin",
    r"dropbox", r"dr0pbox", r"dropb0x",
    r"docusign", r"d0cusign", r"docusing",
    r"adobe", r"ad0be", r"adobе",
    r"zoom", r"z00m", r"zooom",
    r"slack", r"s1ack", r"slаck",
    r"office", r"0ffice", r"office365", r"o365",
    r"outlook", r"0utlook", r"outl00k",
    r"onedrive", r"0nedrive", r"one-drive",
    r"sharepoint", r"sharep0int",
    r"teams", r"t3ams",
    r"webex", r"webеx",
    r"dhl", r"dh1", r"fedex", r"fed-ex", r"ups", r"usps",
    r"wellsfargo", r"wells-fargo", r"chase", r"citi", r"bofa",
    
    # === Suspicious File Extensions in URL ===
    r"\.exe", r"\.scr", r"\.bat", r"\.cmd", r"\.msi", r"\.dll",
    r"\.vbs", r"\.vbe", r"\.js(?!on)", r"\.jse", r"\.wsf", r"\.wsh",
    r"\.ps1", r"\.psm1", r"\.psd1",
    r"\.hta", r"\.cpl", r"\.msc", r"\.jar",
    r"\.iso", r"\.img", r"\.dmg",
    r"\.zip", r"\.rar", r"\.7z", r"\.tar", r"\.gz",
    r"\.doc[xm]?(?!s)", r"\.xls[xmb]?", r"\.ppt[xm]?",  # Office with macros
    
    # === Suspicious URL Structures ===
    r"\.php\?", r"\.asp\?", r"\.aspx\?", r"\.jsp\?", r"\.cgi\?",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP in URL
    r":\d{4,5}/",  # Unusual ports
    r"@",  # @ in URL (credential confusion)
    r"//.*//",  # Double slashes
    r"\.\.\/", r"\.\.\\",  # Path traversal
    r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",  # Heavy URL encoding
    r"base64", r"data:",  # Data URIs
    r"javascript:", r"vbscript:",  # Script protocols
    r"redirect", r"redir", r"goto", r"jump", r"bounce", r"click",
    r"track.*click", r"click.*track", r"link.*track",
    
    # === URL Shorteners (commonly abused) ===
    r"bit\.ly", r"bitly\.com", r"tinyurl", r"t\.co", r"goo\.gl", r"ow\.ly",
    r"is\.gd", r"v\.gd", r"buff\.ly", r"adf\.ly", r"bc\.vc",
    r"cutt\.ly", r"rb\.gy", r"shorturl", r"short\.link",
    r"tiny\.cc", r"s\.id", r"shorten", r"lnk\.", r"link\.",
    r"rebrand\.ly", r"bl\.ink", r"clck\.ru",
    
    # === Suspicious TLDs (free/cheap, commonly abused) ===
    r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"\.gq$",  # Freenom
    r"\.xyz$", r"\.top$", r"\.club$", r"\.work$", r"\.click$",
    r"\.link$", r"\.info$", r"\.site$", r"\.online$", r"\.live$",
    r"\.icu$", r"\.buzz$", r"\.fun$", r"\.space$", r"\.website$",
    r"\.pw$", r"\.cc$", r"\.ws$", r"\.su$", r"\.ru$",
    r"\.cn$", r"\.zip$", r"\.mov$",  # New Google TLDs abused for phishing
    
    # === Homograph/Lookalike Characters ===
    r"[а-яА-Я]",  # Cyrillic characters
    r"[αβγδεζηθικλμνξοπρστυφχψω]",  # Greek characters
    r"0(?=.*[a-z])|[a-z].*0",  # Zero mixed with letters (l0gin, g00gle)
    r"1(?=.*[a-z])|[a-z].*1",  # One mixed with letters (1ogin, pay1)
    r"rn(?=[a-z])",  # rn looks like m
    r"vv(?=[a-z])",  # vv looks like w
    r"cl(?=[a-z])",  # cl looks like d
    
    # === Web Shells / Malicious Paths ===
    r"/wp-admin", r"/wp-includes", r"/wp-content",
    r"/admin", r"/administrator", r"/manager",
    r"/shell", r"/cmd", r"/console",
    r"/filemanager", r"/webshell",
    r"/c99", r"/r57", r"/b374k",  # Known web shells
    
    # === Suspicious Query Parameters ===
    r"[?&]cmd=", r"[?&]exec=", r"[?&]command=",
    r"[?&]token=", r"[?&]session=", r"[?&]auth=",
    r"[?&]password=", r"[?&]pwd=", r"[?&]pass=",
    r"[?&]email=", r"[?&]user=", r"[?&]username=",
    r"[?&]redirect=", r"[?&]next=", r"[?&]return=", r"[?&]url=",
]


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except:
        return ""


def is_safe_domain(url: str) -> bool:
    """Check if URL is from a known safe domain."""
    domain = get_domain(url)
    if not domain:
        return False
    
    # Check exact match
    if domain in SAFE_DOMAINS:
        return True
    
    # Check if it's a subdomain of a safe domain
    for safe in SAFE_DOMAINS:
        if domain.endswith('.' + safe):
            return True
    
    return False


def is_asset_url(url: str) -> bool:
    """Check if URL is an image/font/css asset."""
    url_lower = url.lower()
    
    # Check file extension
    for ext in SAFE_EXTENSIONS:
        if ext in url_lower:
            # Make sure it's actually the extension, not part of domain
            if url_lower.endswith(ext) or ext + "?" in url_lower or ext + "#" in url_lower:
                return True
    
    return False


def is_tracking_url(url: str) -> bool:
    """Check if URL is a tracking pixel or analytics."""
    url_lower = url.lower()
    
    for pattern in TRACKING_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    
    return False


def is_suspicious_url(url: str) -> bool:
    """Check if URL has suspicious patterns worth checking."""
    url_lower = url.lower()
    
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    
    return False


def calculate_url_priority(url: str) -> int:
    """
    Calculate priority score for URL (higher = should check first).
    
    Returns:
        -1: Skip (safe domain, asset, tracking)
        0: Low priority (normal URL)
        1-20: Higher priority based on suspicious indicators
    """
    # Skip known safe domains
    if is_safe_domain(url):
        return -1
    
    # Skip asset URLs
    if is_asset_url(url):
        return -1
    
    # Skip tracking pixels
    if is_tracking_url(url):
        return -1
    
    # Calculate suspiciousness
    priority = 0
    url_lower = url.lower()
    domain = get_domain(url)
    domain_lower = domain.lower()
    
    # === Check for suspicious patterns (major red flags) ===
    pattern_matches = 0
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url_lower, re.I):
            pattern_matches += 1
    
    # More matches = more suspicious
    if pattern_matches >= 5:
        priority += 8
    elif pattern_matches >= 3:
        priority += 5
    elif pattern_matches >= 1:
        priority += 2
    
    # === Domain-based heuristics ===
    
    # Very long domain (suspicious)
    if len(domain) > 40:
        priority += 3
    elif len(domain) > 30:
        priority += 2
    elif len(domain) > 25:
        priority += 1
    
    # Many subdomains (suspicious)
    subdomain_count = domain.count('.')
    if subdomain_count > 4:
        priority += 3
    elif subdomain_count > 3:
        priority += 2
    
    # Numbers in domain (often suspicious)
    if re.search(r'\d{4,}', domain):
        priority += 3  # Long number sequences very suspicious
    elif re.search(r'\d{2,}', domain):
        priority += 1
    
    # Random-looking domain (consonant clusters, no vowels)
    vowels = sum(1 for c in domain_lower if c in 'aeiou')
    consonants = sum(1 for c in domain_lower if c.isalpha() and c not in 'aeiou')
    if consonants > 0 and vowels / max(consonants, 1) < 0.15:
        priority += 3  # Very few vowels = random
    
    # Long random-looking strings
    if re.search(r'[a-z]{12,}', domain_lower):
        # Check if it's a known word pattern
        known_words = ['microsoft', 'facebook', 'instagram', 'google', 'amazon', 
                      'cloudflare', 'wordpress', 'squarespace', 'mailchimp', 'constant']
        if not any(word in domain_lower for word in known_words):
            priority += 2
    
    # Hyphens in domain (common in phishing)
    hyphen_count = domain.count('-')
    if hyphen_count >= 3:
        priority += 3
    elif hyphen_count >= 2:
        priority += 1
    
    # Mixed letters and numbers (l33t speak, typosquatting)
    if re.search(r'[a-z]+\d+[a-z]+|\d+[a-z]+\d+', domain_lower):
        priority += 2
    
    # Homograph characters (Cyrillic, etc.)
    if re.search(r'[а-яА-Яαβγδεζηθικλμνξοπρστυφχψω]', domain):
        priority += 5  # Very suspicious!
    
    # === URL structure heuristics ===
    
    # IP address in URL
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        priority += 4
    
    # Unusual port
    if re.search(r':\d{4,5}/', url):
        priority += 3
    
    # @ symbol in URL (credential confusion attack)
    if '@' in url:
        priority += 4
    
    # URL-encoded characters (obfuscation)
    percent_count = url.count('%')
    if percent_count > 10:
        priority += 4
    elif percent_count > 5:
        priority += 2
    elif percent_count > 3:
        priority += 1
    
    # Very long URL (often obfuscation or data exfil)
    if len(url) > 500:
        priority += 3
    elif len(url) > 300:
        priority += 2
    elif len(url) > 200:
        priority += 1
    
    # Suspicious file extensions
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.dll', '.vbs', 
                          '.js', '.jar', '.ps1', '.hta', '.iso', '.img']
    for ext in dangerous_extensions:
        if ext in url_lower:
            priority += 4
            break
    
    # Archive extensions (often malware delivery)
    if any(ext in url_lower for ext in ['.zip', '.rar', '.7z', '.tar', '.gz']):
        priority += 2
    
    # Data URI or javascript protocol
    if url_lower.startswith(('data:', 'javascript:', 'vbscript:')):
        priority += 5
    
    # Double URL encoding
    if '%25' in url:
        priority += 3
    
    # Path traversal attempts
    if '../' in url or '..\\' in url:
        priority += 4
    
    # SQL injection patterns
    if re.search(r"['\"].*(?:or|and|union|select|insert|update|delete)", url_lower):
        priority += 3
    
    # Base64 in URL
    if 'base64' in url_lower or re.search(r'[A-Za-z0-9+/]{50,}={0,2}', url):
        priority += 2
    
    return min(priority, 20)  # Cap at 20


def filter_urls_for_ti(
    urls: List[str],
    max_urls: int = 5,
    include_all_suspicious: bool = True,
) -> Tuple[List[str], List[str]]:
    """
    Filter and prioritize URLs for threat intelligence checking.
    
    Args:
        urls: List of URLs to filter
        max_urls: Maximum number of URLs to return for checking
        include_all_suspicious: If True, include all suspicious URLs even if over limit
    
    Returns:
        Tuple of (urls_to_check, urls_skipped)
    """
    if not urls:
        return [], []
    
    # Deduplicate
    urls = list(dict.fromkeys(urls))
    
    # Calculate priority for each URL
    url_priorities = []
    for url in urls:
        priority = calculate_url_priority(url)
        url_priorities.append((url, priority))
    
    # Separate into categories
    to_check = []
    skipped = []
    
    for url, priority in url_priorities:
        if priority < 0:
            skipped.append(url)
            logger.debug(f"Skipping safe/asset URL: {url[:50]}...")
        else:
            to_check.append((url, priority))
    
    # Sort by priority (highest first)
    to_check.sort(key=lambda x: x[1], reverse=True)
    
    # Apply limit
    if include_all_suspicious:
        # Include all URLs with priority > 0, plus fill up to max with others
        suspicious = [(u, p) for u, p in to_check if p > 0]
        normal = [(u, p) for u, p in to_check if p == 0]
        
        result = [u for u, p in suspicious]
        remaining_slots = max_urls - len(result)
        if remaining_slots > 0:
            result.extend([u for u, p in normal[:remaining_slots]])
    else:
        result = [u for u, p in to_check[:max_urls]]
    
    # Log summary
    if skipped:
        logger.info(f"URL filter: checking {len(result)}/{len(urls)} URLs, skipped {len(skipped)} safe/asset URLs")
    else:
        logger.info(f"URL filter: checking {len(result)}/{len(urls)} URLs")
    
    return result, skipped


def filter_single_url(url: str) -> bool:
    """
    Quick check if a single URL should be sent to TI.
    
    Returns:
        True if URL should be checked, False if should be skipped
    """
    priority = calculate_url_priority(url)
    return priority >= 0
