# NiksES v3.3.0 - Fully Dynamic TI Scoring

## 🎯 Major Change: Zero Hardcoded TI Thresholds

All threat intelligence scoring thresholds are now 100% dynamic and configurable!

### Before (Hardcoded)
```python
# ti_fusion.py had hardcoded values everywhere!
if risk_score >= 85:  # HARDCODED!
    verdict = MALICIOUS
if malicious >= 3:    # HARDCODED!
    verdict = MALICIOUS
if score >= 75:       # HARDCODED!
    verdict = MALICIOUS
```

### After (Dynamic from Config)
```python
# Now uses centralized scoring config
config = get_scoring_config()
ti = config.ti_thresholds

if risk_score >= ti.ipqs_malicious:     # From config: 85
    verdict = MALICIOUS
if malicious >= ti.vt_malicious_engines: # From config: 3
    verdict = MALICIOUS
if score >= ti.abuseipdb_malicious:     # From config: 75
    verdict = MALICIOUS
```

## 📊 Dynamic Thresholds Now Used

| Source | Threshold | Default | Config Key |
|--------|-----------|---------|------------|
| **IPQualityScore** | Malicious | 85 | `ti_thresholds.ipqs_malicious` |
| **IPQualityScore** | Suspicious | 75 | `ti_thresholds.ipqs_suspicious` |
| **IPQualityScore** | Risky | 50 | `ti_thresholds.ipqs_risky` |
| **VirusTotal** | Malicious | 3 engines | `ti_thresholds.vt_malicious_engines` |
| **VirusTotal** | Suspicious | 1 engine | `ti_thresholds.vt_suspicious_engines` |
| **AbuseIPDB** | Malicious | 75 | `ti_thresholds.abuseipdb_malicious` |
| **AbuseIPDB** | Suspicious | 25 | `ti_thresholds.abuseipdb_suspicious` |

## 🔧 Configure via Environment Variables

```bash
# Adjust IPQS sensitivity
TI_IPQS_MALICIOUS=90      # Higher = less false positives
TI_IPQS_SUSPICIOUS=80

# Adjust VT sensitivity  
TI_VT_MALICIOUS_ENGINES=5  # Require more engines to flag

# Adjust AbuseIPDB sensitivity
TI_ABUSEIPDB_MALICIOUS=80
```

## 📁 Files Updated

- `app/services/enrichment/ti_fusion.py` - All 6 check methods now use config:
  - `_check_ipqualityscore_url()`
  - `_check_virustotal_url()`
  - `_check_virustotal_domain()`
  - `_check_virustotal_ip()`
  - `_check_virustotal_hash()`
  - `_check_abuseipdb()`

## ✅ All Fixes Summary (v3.2.7 - v3.3.0)

| Version | Fix |
|---------|-----|
| v3.2.7 | EmailAddress.email, get_settings, BRAND_IMPERSONATION |
| v3.2.8 | Unclosed aiohttp sessions, better logging |
| v3.2.9 | VT timeout handling, cleaner logs |
| **v3.3.0** | **100% dynamic TI thresholds** |

## 📦 Package
- 281 files, 1.6MB compressed
