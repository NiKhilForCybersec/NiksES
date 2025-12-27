# NiksES v3.2.5 - UI Fixes

## 🔧 Fixes in v3.2.5

### API Count Display Fixed
- **Before**: Hardcoded "8/6 APIs" (wrong!)
- **After**: Dynamic "X/10 APIs" (correct!)

Fixed in two locations:
1. `App.tsx` - Header API status tile
2. `APIStatusIndicator.tsx` - Dropdown API status

Now correctly shows configured/total based on actual API keys tracked:
- VirusTotal
- AbuseIPDB  
- PhishTank
- MXToolbox
- IPQualityScore
- Google Safe Browsing
- URLScan
- Anthropic
- OpenAI
- Hybrid Analysis

### Detection Engine UI (from v3.2.4)
- Removed dramatic cards (TI is King, Correlation, etc.)
- Clean informational section instead

## ✅ All Features

- Two-Pass AI Analysis
- Non-blocking Sandbox (3-5 min)
- Dynamic Scoring (configurable thresholds)
- 68+ Detection Rules
- 7 TI Sources
- 10 API Integrations
