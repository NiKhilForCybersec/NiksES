# NiksES v3.0.0 - Dynamic Intelligent Detection Architecture (DIDA)

## 🚀 Major Changes

### Zero-Hardcoding Scoring System

This release completely reimagines how NiksES calculates threat scores. Instead of
fixed severity values (e.g., "HIGH = 35 points"), all scores are now calculated
dynamically from:

- **Evidence Quality**: Each detection signal becomes an Evidence object with quality metrics
- **TI Validation**: External validation significantly boosts confidence
- **Attack Chain Detection**: Correlated patterns recognized and scored together
- **Confidence-Adjusted Thresholds**: Same score + different confidence = different verdict

## 🏗️ New Architecture

### Evidence System (`evidence.py`)

```python
# Every detection signal is now an Evidence object
@dataclass
class Evidence:
    evidence_type: EvidenceType
    category: EvidenceCategory
    source: EvidenceSource
    
    # Quality metrics (calculated, not hardcoded)
    source_reliability: float  # 0-1, from source type + API health
    specificity: float         # 0-1, how targeted is this evidence
    external_validation: float # 0-1, confirmed by TI sources
    
    @property
    def quality_score(self) -> float:
        # Dynamic calculation, not fixed severity
```

### Dynamic Scorer (`dynamic_scorer.py`)

- `ThreatIntelScorer`: Calculates scores from TI consensus
- `AttackChainDetector`: Detects attack patterns from evidence combinations
- `DynamicEvidenceWeighter`: Calculates weight from quality, validation, correlation
- `DynamicScoreCalculator`: Main scorer with confidence-adjusted thresholds

### SMS/URL Scorer (`sms_dynamic_scorer.py`)

Same principles applied to SMS/URL analysis:
- Pattern-based evidence collection
- Smishing attack chain detection
- URL risk indicator analysis

## 📊 How Scoring Works Now

### Old Way (Hardcoded)
```python
if severity == "critical": score += 50
if severity == "high": score += 35
```

### New Way (Dynamic)
```python
score = (
    evidence_quality × 
    validation_multiplier × 
    correlation_boost × 
    context_factor
)
```

### Confidence-Adjusted Levels

Same score yields different levels based on confidence:

| Score | High Confidence (>70%) | Medium (40-70%) | Low (<40%) |
|-------|------------------------|-----------------|------------|
| 75    | CRITICAL              | HIGH            | HIGH       |
| 55    | HIGH                  | MEDIUM          | MEDIUM     |
| 35    | MEDIUM                | LOW             | LOW        |

## ⛓️ Attack Chain Detection

Recognized attack patterns:
- `credential_phishing`: Auth fail + lookalike + urgency + credential form
- `bec_wire_fraud`: Executive spoof + wire request + urgency
- `malware_delivery`: Suspicious attachment + macro + password in body
- `brand_impersonation`: Brand mismatch + lookalike + external link
- `smishing_financial`: Financial keywords + URL + urgency

## 📈 Benefits

1. **No Magic Numbers**: Every value calculated from evidence
2. **TI is King**: External validation heavily weights the score
3. **Quality over Quantity**: 3 strong evidence > 10 weak ones
4. **Explainable**: Every decision has clear reasoning
5. **Adaptive**: Thresholds adjust based on data quality

## 🔧 Integration

The new scoring is automatically used when analyzing emails and SMS/URLs.
Legacy scoring is used as fallback if dynamic scoring fails.

## 📁 New Files

- `backend/app/services/detection/evidence.py` - Evidence models
- `backend/app/services/detection/dynamic_scorer.py` - Email dynamic scoring
- `backend/app/services/detection/sms_dynamic_scorer.py` - SMS/URL dynamic scoring

## 🧪 Testing

```python
from app.services.detection import calculate_dynamic_score, calculate_sms_dynamic_score

# Test SMS
result = calculate_sms_dynamic_score(
    text="URGENT: Your bank account locked. Click: bit.ly/scam",
    urls=["bit.ly/scam"],
)
print(f"Score: {result.value}, Level: {result.level}, Confidence: {result.confidence}")
```
