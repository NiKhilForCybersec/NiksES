# NiksES v3.2.9 - Graceful VT Timeout Handling

## 🔧 Improvements

### VirusTotal Timeouts Now Expected
VT free tier has strict rate limits (4 requests/min). System now:
- Logs timeouts as INFO not WARNING (less noise)
- Clearly shows which sources were used vs skipped
- Continues analysis with available sources

### Better TI Fusion Logging

**Before:**
```
WARNING - TI source virustotal: unavailable - Timeout
INFO - TI fusion complete: 3/4 sources available, 0 flagged
```

**After:**
```
INFO - TI source virustotal: timeout - using other sources
INFO - TI fusion: 3/4 sources (used: ipqualityscore, google_safebrowsing, urlhaus, skipped: virustotal)
```

### How Scoring Works With Missing Sources

When VT times out:
1. Other sources (IPQS, GSB, AbuseIPDB, URLhaus) still provide data
2. Fused score calculated from available sources only
3. Confidence adjusted: `available / checked` (e.g., 3/4 = 0.75)
4. Analysis continues normally - never blocked by API failures

### Example Flow
```
TI checks: ['google_safebrowsing', 'ipqualityscore', 'virustotal', 'urlhaus']
  ✓ google_safebrowsing: available, score=0, verdict=CLEAN
  ✓ ipqualityscore: available, score=89, verdict=MALICIOUS  
  ⏱ virustotal: timeout - using other sources
  ✓ urlhaus: available, score=0, verdict=UNKNOWN
TI fusion: 3/4 sources (used: ipqualityscore, google_safebrowsing, urlhaus, skipped: virustotal)
Fused score: 89 (from IPQS)
Confidence: 0.75
```

## ✅ All Fixes Summary (v3.2.7 - v3.2.9)

| Version | Fix |
|---------|-----|
| v3.2.7 | EmailAddress.email, get_settings import, BRAND_IMPERSONATION |
| v3.2.8 | Unclosed aiohttp sessions, better logging structure |
| v3.2.9 | VT timeout handling, cleaner TI fusion logs |

## 📦 Package
- 281 files, 1.6MB compressed
