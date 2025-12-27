# NiksES v3.2.2 - Complete Package

## 📦 Package Contents

- **236 files** total
- **4.5MB** uncompressed
- Backend: 139 Python files
- Frontend: 87 source files + built dist
- Documentation + Screenshots

## 🎯 Key Features

### 1. Two-Pass AI Analysis (v3.2.0)
- **Pass 1**: Content analysis (intent + 7-dimension SE scoring)
- **Pass 2**: Full synthesis (SE + TI + Detection + Headers)

### 2. Fully Dynamic Scoring (v3.2.2)
ALL scoring is configurable via API or environment variables:

```
GET  /api/v1/scoring           - View config
PATCH /api/v1/scoring          - Update config
POST /api/v1/scoring/reset     - Reset defaults
POST /api/v1/scoring/presets/{name} - Apply preset
```

### 3. 7 Threat Intelligence Sources
- VirusTotal
- Google Safe Browsing  
- IPQualityScore
- AbuseIPDB
- URLhaus
- PhishTank
- Hybrid Analysis (sandbox)

### 4. 68+ Detection Rules
- Authentication (SPF/DKIM/DMARC)
- Social Engineering
- Brand Impersonation
- Lookalike Domains
- IP Reputation
- Content Patterns

## 🔧 Configuration Options

### Risk Thresholds
```json
{
  "thresholds": {
    "critical": 75,
    "high": 50,
    "medium": 25,
    "low": 10
  }
}
```

### TI Source Weights
```json
{
  "ti_weights": {
    "virustotal": 0.25,
    "google_safebrowsing": 0.20,
    "ipqualityscore": 0.20,
    "abuseipdb": 0.15
  }
}
```

### Scoring Presets
- `default` - Balanced detection
- `aggressive` - More detections, higher FP rate
- `conservative` - Fewer FPs, may miss some
- `zero_trust` - Flag everything suspicious

## 🚀 Deployment

### Railway (Recommended)
1. Create new project
2. Add backend service from `backend/`
3. Add frontend service from `frontend/`
4. Set environment variables
5. Deploy!

### Docker
```bash
docker-compose up -d
```

### Manual
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run build
npm run preview
```

## 📋 Environment Variables

### Required
```env
OPENAI_API_KEY=sk-...
```

### Optional TI Sources
```env
VIRUSTOTAL_API_KEY=...
GOOGLE_SAFEBROWSING_API_KEY=...
IPQUALITYSCORE_API_KEY=...
ABUSEIPDB_API_KEY=...
HYBRID_ANALYSIS_API_KEY=...
```

### Optional Scoring Overrides
```env
RISK_THRESHOLD_CRITICAL=75
RISK_THRESHOLD_HIGH=50
RISK_THRESHOLD_MEDIUM=25
RISK_THRESHOLD_LOW=10
```

## 📁 File Structure

```
nikses-v3.2.2-complete/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # API endpoints
│   │   ├── config/              # Scoring config (NEW)
│   │   ├── models/              # Pydantic models
│   │   ├── services/
│   │   │   ├── ai/              # AI analyzers
│   │   │   ├── analysis/        # Orchestration
│   │   │   ├── detection/       # Rule engine + scoring
│   │   │   ├── enrichment/      # TI providers
│   │   │   ├── export/          # PDF/SIEM export
│   │   │   ├── soc/             # SOC tools
│   │   │   └── ...
│   │   └── utils/
│   ├── data/                    # SQLite database
│   ├── tests/                   # Test files
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── services/            # API services
│   │   ├── hooks/               # Custom hooks
│   │   └── ...
│   ├── dist/                    # Built production files
│   ├── package.json
│   ├── package-lock.json
│   └── Dockerfile
├── docker-compose.yml
├── README.md
├── DEPLOY.md
├── RAILWAY_DEPLOY.md
├── SECURITY_AUDIT.md
├── image*.png                   # Screenshots
└── CHANGELOG.md
```

## 🔒 Security Features

- Rate limiting
- Input validation
- CORS protection
- No hardcoded secrets
- API key encryption

## 📊 Version History

| Version | Feature |
|---------|---------|
| v3.2.2 | Fully dynamic scoring |
| v3.2.0 | Two-pass AI analysis |
| v3.1.4 | Hybrid Analysis sandbox |
| v3.1.3 | 7 TI sources in fusion |
| v3.1.2 | Railway env vars |
| v3.0.0 | DIDA scoring engine |
