# NiksES v3.4.7 - Fixed Frontend Timeout (30000ms Error)

## 🐛 The Problem

User saw popup error: "30000ms timeout"
- Backend analysis completes and saves to history ✅
- But frontend gives up after 30 seconds ❌
- UI doesn't display the result

## 🔧 The Fix

**Frontend timeout increased from 30s to 120s (2 minutes)**

```typescript
// BEFORE
export const API_TIMEOUT = 30000; // 30 seconds

// AFTER
export const API_TIMEOUT = 120000; // 2 minutes
```

## ⏱️ All Timeout Settings Now

| Component | Setting | Value |
|-----------|---------|-------|
| **Frontend** | API_TIMEOUT | **120s** (was 30s) |
| **Backend** | API_TIMEOUT_ENRICHMENT | 45s |
| **Backend** | TI Fusion per-source | 45s |
| **Backend** | Google Safe Browsing | 45s |
| **Backend** | IPQualityScore | 45s |

## 📊 How It Works Now

```
User uploads email
     │
     ▼
Frontend sends to backend (waits up to 120s)
     │
     ▼
Backend runs analysis:
  ├── Detection rules: ~1s
  ├── AI content analysis: ~5s
  ├── TI checks (parallel): ~45s max per source
  │   ├── VirusTotal: responds or timeout
  │   ├── AbuseIPDB: responds or timeout
  │   └── Others: responds or timeout
  └── AI synthesis: ~5s
     │
     ▼
Backend returns result (typically 30-60s)
     │
     ▼
Frontend displays result ✅
```

## 📁 Files Changed

1. **frontend/src/utils/constants.ts**
   - `API_TIMEOUT: 30000 → 120000`

---

## ✅ All v3.4.x Features Included

- Type-specific history buttons
- Complete null safety
- Gmail phishing fix
- Comprehensive scoring
- Backend timeout increases
