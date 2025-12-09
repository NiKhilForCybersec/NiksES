# NiksES - AI-Powered Email Security Analysis

## Railway Deployment

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/nikses.git
git push -u origin main
```

### Step 2: Deploy Backend on Railway

1. Go to https://railway.app → New Project → Deploy from GitHub
2. Select your repo
3. **Settings tab:**
   - Root Directory: `backend`
   - Builder: `Dockerfile`
4. **Variables tab - Add these:**
   ```
   OPENAI_API_KEY=sk-your-key-here
   AI_ENABLED=true
   AI_PROVIDER=openai
   SECRET_KEY=any-random-32-char-string
   VIRUSTOTAL_API_KEY=your-vt-key
   ABUSEIPDB_API_KEY=your-abuseipdb-key
   ```
5. Deploy and copy the generated URL

### Step 3: Deploy Frontend on Railway

1. In same project, click **+ New** → GitHub Repo → Same repo
2. **Settings tab:**
   - Root Directory: `frontend`
   - Builder: `Dockerfile`
3. **Variables tab:**
   ```
   VITE_API_URL=https://your-backend-url.up.railway.app
   ```
4. Deploy

### Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | OpenAI API key for AI analysis |
| `AI_ENABLED` | Yes | Set to `true` |
| `AI_PROVIDER` | Yes | Set to `openai` |
| `SECRET_KEY` | Yes | Random string for security |
| `VIRUSTOTAL_API_KEY` | Recommended | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | Recommended | AbuseIPDB API key |
| `PHISHTANK_API_KEY` | Optional | PhishTank API key |
| `VITE_API_URL` | Frontend only | Backend URL (no trailing slash) |

### Test Deployment

Backend health check:
```
https://your-backend-url.up.railway.app/api/v1/health
```

Should return:
```json
{"status": "healthy", "service": "nikses-api", "version": "1.0.0"}
```
