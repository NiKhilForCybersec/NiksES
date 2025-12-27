# NiksES v3.2.7 - Critical Bug Fixes

## 🐛 Bugs Fixed

### 1. EmailAddress Attribute Error (CRITICAL)
**Error**: `'EmailAddress' object has no attribute 'address'`
**Impact**: Two-Pass AI analysis was completely failing

**Fix**: Changed `email.sender.address` to `email.sender.email`
```python
# Before (broken)
"sender": f"{email.sender.address}" if email.sender else ""

# After (fixed)
"sender": f"{email.sender.email}" if email.sender else ""
```

### 2. IPQualityScore Not Being Called (CRITICAL)
**Error**: `cannot import name 'get_settings' from 'app.config'`
**Impact**: IPQS was completely disabled in text/URL analysis!

**Cause**: Python was importing from `app/config/` package instead of `app/config.py` module

**Fix**: Changed import in analyze_text.py:
```python
# Before (broken)
from app.config import get_settings

# After (fixed)  
from app.api.dependencies import get_settings
```

### 3. Dynamic Scoring Classification Error
**Error**: `Dynamic scoring failed, using legacy: IMPERSONATION`
**Impact**: Dynamic scoring was falling back to legacy scorer

**Cause**: Using non-existent enum `EmailClassification.IMPERSONATION`

**Fix**: Updated class_mapping in orchestrator.py:
```python
# Before (broken)
"brand_impersonation": EmailClassification.IMPERSONATION,
"suspicious": EmailClassification.SUSPICIOUS,

# After (fixed)
"brand_impersonation": EmailClassification.BRAND_IMPERSONATION,
"impersonation": EmailClassification.BRAND_IMPERSONATION,
"suspicious": EmailClassification.UNKNOWN,
```

## ✅ What Now Works

After these fixes:
- ✅ Two-Pass AI Analysis runs correctly
- ✅ IPQualityScore is called for URL analysis
- ✅ Dynamic scoring completes without fallback
- ✅ All classification mappings are valid

## 📋 Logs You Should Now See

```
IPQualityScore: Scanning URL https://example.com with strictness=2
IPQualityScore: URL https://example.com -> risk_score=89, phishing=True
Two-Pass AI complete: threat=75, se=60
Dynamic score: 72 (high) confidence=0.85 chains=2
```

## 📦 Package
- 281 files
- 1.6MB compressed
