# NiksES v3.3.3 - Advanced URL Intelligence Filter

## 🧠 Enterprise-Grade URL Filtering

Comprehensive URL filtering that saves API quota while catching ALL threats!

### Filter Statistics
| Category | Count |
|----------|-------|
| **Safe Domains** | 345+ |
| **Suspicious Patterns** | 302+ |
| **Tracking Patterns** | 53+ |
| **Total Rules** | 700+ |

## 🎯 What It Detects

### Brand Impersonation (with typosquatting)
```
✓ paypa1-secure.com       (PayPal typosquat)
✓ micros0ft-login.click   (Microsoft typosquat)
✓ amaz0n.support.top      (Amazon typosquat)
✓ g00gle-verify.ml        (Google typosquat)
✓ faceb00k-security.xyz   (Facebook typosquat)
```

### Suspicious TLDs
```
✓ .tk, .ml, .ga, .cf, .gq  (Freenom - commonly abused)
✓ .xyz, .top, .club, .work, .click
✓ .icu, .buzz, .fun, .space, .website
✓ .zip, .mov  (New Google TLDs abused for phishing)
```

### Attack Patterns
```
✓ Path traversal: /../../../etc/passwd
✓ IP in URL: https://192.168.1.1/login
✓ Credential URLs: https://user:pass@evil.com
✓ Command injection: ?cmd=whoami
✓ SQL injection: ?id=1' OR '1'='1
✓ Executable downloads: .exe, .scr, .bat, .ps1
✓ Base64/encoded payloads
```

### Homograph/Lookalike Detection
```
✓ Cyrillic characters: аррӏе.com (fake apple.com)
✓ Greek characters: αmazon.com (fake amazon.com)
✓ l33t speak: g00gle, pay1, micr0soft
✓ Visual tricks: rn→m, vv→w, cl→d
```

## 🚫 What It Skips (Saves API Quota)

### 345+ Safe Domains
- Tech giants: google, microsoft, apple, amazon, facebook
- Email: gmail, outlook, yahoo, protonmail
- SaaS: slack, zoom, dropbox, notion, salesforce
- CDNs: cloudflare, akamai, fastly, cloudfront
- Dev: github, npm, pypi, docker, vercel

### Asset URLs
- Images: .png, .jpg, .gif, .webp, .ico, .svg
- Fonts: .woff, .woff2, .ttf, .eot
- Styles: .css

### 53+ Tracking Patterns
- Pixels: /pixel, /beacon, /1x1.gif, /track
- Analytics: /collect, /__utm, /analytics
- Email tracking: sendgrid, mailchimp, hubspot

## 📊 Priority Scoring (0-20)

| Priority | Description | Example |
|----------|-------------|---------|
| 13+ | Critical threat | IP + payment keywords |
| 10-12 | High threat | Typosquatting + suspicious TLD |
| 7-9 | Medium threat | Free TLD + random domain |
| 4-6 | Low threat | Executable download |
| 1-3 | Minimal risk | URL shortener |
| 0 | Unknown | Normal URL |
| -1 | Skip | Safe domain/asset |

## 💰 API Quota Savings

Typical email with 50 URLs:
```
Before:  50 API calls (quota exhausted!)
After:   5-10 API calls (only suspicious ones)
Savings: 80-90% API quota!
```

## 📁 Files
- `backend/app/services/enrichment/url_filter.py` (700+ rules)
- `backend/app/services/analysis/orchestrator.py` (integration)

## ✅ All Previous Fixes Included
- Dynamic TI thresholds
- URL parsing fix
- Session leak fixes
- Better logging
