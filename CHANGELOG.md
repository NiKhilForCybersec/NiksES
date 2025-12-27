# NiksES v3.4.1 - Null Safety Fix + Comprehensive Scoring

## 🐛 Fixed: TypeError on History View

**Error:** `Cannot read properties of undefined (reading 'toLowerCase')`

This crashed the app when clicking "View Analysis" on URL/SMS analyses from history.

### Files Fixed (Null Safety)

1. **TextAnalysisResults.tsx**
   - `getRiskColor()` - handles undefined level
   - `getSeverityColor()` - handles undefined severity  
   - `getSourceIcon()` - handles undefined source

2. **AnalysisView.tsx**
   - `getVerdictColor()` - handles undefined verdict
   - `getVerdictBgColor()` - handles undefined verdict
   - `getSeverityColor()` - handles undefined severity
   - `getAuthStatusIcon()` - handles undefined result

3. **ScoringBreakdown.tsx**
   - `getLevelConfig()` - handles undefined level
   - `getCategoryIcon()` - handles undefined category

4. **AdvancedAnalysisView.tsx**
   - API status display - handles undefined status

### Pattern Applied
```typescript
// BEFORE (crashes on undefined):
switch (level.toLowerCase()) { ... }

// AFTER (safe):
switch ((level || '').toLowerCase()) { ... }
```

---

## 🎯 v3.4.0 Features (Included)

### Comprehensive Scoring System

**10 Combination Bonuses:**
- Auth FAIL + content indicator → +15
- Brand ≥70 + credential request → +20
- URL shortener + brand mention → +15
- 3+ SE techniques → +15
- TI flagged + content indicator → +20
- BEC pattern (full) → +25
- And more...

**12 Minimum Floors:**
- TI confirmed malicious → Floor 80
- Brand ≥85 + Content ≥80 → Floor 75
- Auth FAIL + high indicator → Floor 75
- BEC pattern detected → Floor 70
- And more...

**Enhanced Header Analysis:**
- Free email provider detection
- Display name spoofing detection
- Executive impersonation detection
- Reply-to mismatch detection

**New Attack Chains:**
- brand_credential_phishing
- social_engineering_attack

---

## 📊 Expected Results

### Test Phishing Email (Microsoft impersonation)
```
BEFORE v3.4.x:
  Overall: 23 (MEDIUM) ❌

AFTER v3.4.x:
  Overall: 75-90 (CRITICAL) ✅
```

---

## 📁 Files Changed

### Frontend (Null Safety)
- `src/components/analysis/TextAnalysisResults.tsx`
- `src/components/analysis/AnalysisView.tsx`
- `src/components/analysis/AdvancedAnalysisView.tsx`
- `src/components/detection-viz/ScoringBreakdown.tsx`

### Backend (Scoring Engine)
- `app/services/detection/dynamic_scorer.py`
- `app/services/detection/evidence.py`

---

## 📦 Version History

| Version | Feature |
|---------|---------|
| v3.3.x | URL filtering, history fix, quota modal |
| v3.4.0 | Comprehensive scoring engine |
| **v3.4.1** | **Null safety fix for history view** |
