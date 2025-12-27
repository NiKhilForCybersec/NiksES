# NiksES v3.4.6 - Increased API Timeouts

## 🔧 Fixed: VirusTotal Timeout Issues

**Problem:** VirusTotal API calls timing out after 15 seconds, causing:
```
TI source virustotal: timeout - using other sources
```

**Solution:** Increased all API timeouts from 10-15s to 45s

### Timeout Changes

| Setting | Before | After |
|---------|--------|-------|
| API_TIMEOUT_ENRICHMENT | 10s | 45s |
| TI Fusion per-source | 15s | 45s |
| Google Safe Browsing | 15s | 45s |
| IPQualityScore | 15s | 45s |
| WHOIS | 10s | 15s |
| DNS | 5s | 10s |

### Files Changed

1. **app/utils/constants.py**
   - `API_TIMEOUT_ENRICHMENT: 10 → 45`
   - `WHOIS_TIMEOUT: 10 → 15`
   - `DNS_TIMEOUT: 5 → 10`

2. **app/services/enrichment/ti_fusion.py**
   - `DEFAULT_TIMEOUT: 15.0 → 45.0`

3. **app/services/enrichment/google_safebrowsing.py**
   - `ClientTimeout(total=15) → ClientTimeout(total=45)`

4. **app/services/enrichment/ipqualityscore.py**
   - `ClientTimeout(total=15) → ClientTimeout(total=45)`

---

## 📊 Expected Behavior

- Analysis may take 45-60 seconds for complex emails
- VirusTotal checks will complete instead of timing out
- More complete threat intelligence results
- No more "timeout - using other sources" warnings

---

## ✅ All Previous v3.4.x Features

- Type-specific history buttons (Email/URL/SMS)
- Complete null safety in TextAnalysisResults
- Gmail phishing content fix
- Comprehensive scoring engine
