# NiksES Railway Deployment Guide

## Quick Deploy

### 1. Deploy Backend
1. Create new project in Railway
2. Connect your GitHub repo OR deploy from this folder
3. Set root directory to `/backend`
4. Add environment variables (see below)
5. Deploy!

### 2. Deploy Frontend
1. Add new service to same project
2. Set root directory to `/frontend`
3. Set `VITE_API_URL` to your backend URL
4. Deploy!

---

## Environment Variables (Railway Dashboard > Variables)

### Required
```
SECRET_KEY=your-secure-random-string-here
```

### Threat Intelligence APIs (Optional but Recommended)

#### URL/Domain Reputation
```
VIRUSTOTAL_API_KEY=your_key
IPQUALITYSCORE_API_KEY=your_key
GOOGLE_SAFEBROWSING_API_KEY=your_key
PHISHTANK_API_KEY=your_key
```

#### IP Reputation
```
ABUSEIPDB_API_KEY=your_key
```

#### Email/DNS
```
MXTOOLBOX_API_KEY=your_key
```

#### Sandbox Analysis
```
HYBRID_ANALYSIS_API_KEY=your_key
```

### AI Analysis APIs
```
ANTHROPIC_API_KEY=your_key
OPENAI_API_KEY=your_key
```

---

## Get Free API Keys

| API | Free Tier | Sign Up |
|-----|-----------|---------|
| **IPQualityScore** | 5,000 req/month | https://www.ipqualityscore.com/create-account |
| **Google Safe Browsing** | 10,000 req/day | https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com |
| **VirusTotal** | 4 req/min | https://www.virustotal.com/gui/join-us |
| **AbuseIPDB** | 1,000 req/day | https://www.abuseipdb.com/register |
| **PhishTank** | Unlimited | https://phishtank.org/register.php |
| **MXToolbox** | Limited | https://mxtoolbox.com/User/Api/ |
| **Hybrid Analysis** | 100/month | https://www.hybrid-analysis.com/apikeys/info |
| **Anthropic** | Pay-as-you-go | https://console.anthropic.com |
| **OpenAI** | Pay-as-you-go | https://platform.openai.com |

---

## Railway Configuration Files

### Backend (already configured)
- `Dockerfile` - Builds Python backend
- `requirements.txt` - Python dependencies
- Reads `PORT` from Railway automatically

### Frontend (already configured)  
- `Dockerfile` - Builds React app with nginx
- `nginx.conf` - Production server config
- Set `VITE_API_URL` during build

---

## Folder Structure
```
nikses/
├── backend/           # FastAPI backend
│   ├── app/
│   │   ├── api/       # API routes
│   │   ├── models/    # Data models
│   │   ├── services/  # Business logic
│   │   │   ├── detection/   # DIDA scoring engine
│   │   │   ├── enrichment/  # TI integrations
│   │   │   └── ai/          # AI analysis
│   │   └── config.py  # Railway env config
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/          # React frontend
│   ├── src/
│   │   ├── components/
│   │   └── App.tsx
│   ├── Dockerfile
│   └── nginx.conf
│
└── docker-compose.yml # Local development
```

---

## Health Check

After deployment, verify at:
- Backend: `https://your-backend.railway.app/health`
- Frontend: `https://your-frontend.railway.app`

---

## Troubleshooting

### Backend won't start
- Check `SECRET_KEY` is set
- Check Railway logs for errors

### API keys not working
- Verify keys in Railway Variables (no quotes needed)
- Check Settings page in UI shows green checkmarks

### CORS errors
- Backend CORS already allows all origins (`*`)
- Check `VITE_API_URL` is correct in frontend

---

## Version Info
- **Version**: 3.1.0
- **Detection Engine**: DIDA v3.0 (Dynamic Intelligent Detection)
- **TI Sources**: 8 (VT, IPQS, GSB, PhishTank, URLhaus, AbuseIPDB, MXToolbox, HybridAnalysis)
- **AI Providers**: Anthropic Claude, OpenAI GPT
