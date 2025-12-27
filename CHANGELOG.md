# NiksES v3.3.4 - Quota Warning Modal

## 🆕 New Feature: API Quota Warning

Users now see a friendly warning popup on first use explaining the free tier limitations.

### Warning Modal Features

![Quota Warning](quota-warning-preview.png)

- **Shows once per session** (uses localStorage)
- **"Don't show for 7 days"** checkbox option
- **Clear quota information** for each API:
  - VirusTotal: ~4/min, 500/day
  - IPQualityScore: ~200/day
  - AbuseIPDB: ~1000/day
  - URLScan.io: ~50/day
- **Smart usage tips** explaining auto-filtering
- **Reassurance** that AI analysis has no limits

### Modal Design
- Dark theme matching the app
- Yellow/orange warning gradient header
- Clean grid showing API limits
- Blue accent for positive information
- Professional, non-alarming tone

### User Experience
1. First visit → Modal appears
2. User reads the warning
3. Optional: Check "Don't show for 7 days"
4. Click "I Understand" to dismiss
5. Modal won't show again (or for 7 days)

## 📁 New Files
- `frontend/src/components/QuotaWarningModal.tsx`

## 📦 All Features (v3.3.0 - v3.3.4)

| Version | Feature |
|---------|---------|
| v3.3.0 | 100% dynamic TI thresholds |
| v3.3.1 | URL parsing fix |
| v3.3.2 | Smart URL filtering |
| v3.3.3 | 700+ detection rules |
| **v3.3.4** | **Quota warning modal** |
