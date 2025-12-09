# NiksES Railway Deployment Guide

## Overview

This guide will help you deploy NiksES on Railway with two services:
- **Backend** (FastAPI) - Handles all API requests
- **Frontend** (React/Nginx) - Serves the web interface

---

## Prerequisites

1. **Railway Account**: Sign up at https://railway.app (free tier available)
2. **GitHub Account**: Your code needs to be on GitHub
3. **API Keys** (at minimum):
   - OpenAI API Key (for AI analysis): https://platform.openai.com/api-keys

---

## Step 1: Push to GitHub

If you haven't already, push your code to GitHub:

```bash
cd nikses
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/nikses.git
git push -u origin main
```

---

## Step 2: Create Railway Project

1. Go to https://railway.app/dashboard
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Connect your GitHub account and select your `nikses` repository

---

## Step 3: Deploy Backend

### 3.1 Create Backend Service

1. In your Railway project, click **"New Service"**
2. Select **"GitHub Repo"** → Select your repo
3. Railway will auto-detect the Dockerfile

### 3.2 Configure Backend

Click on the backend service, then go to **Settings**:

**Root Directory:** `backend`

Go to **Variables** tab and add these environment variables:

```
# REQUIRED - Your OpenAI API key
OPENAI_API_KEY=sk-your-openai-key-here

# AI Configuration
AI_ENABLED=true
AI_PROVIDER=openai

# Optional - Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-random-secret-key-here

# Database
DATABASE_URL=sqlite:///./data/nikses.db

# Debug (set to false for production)
DEBUG=false
```

### 3.3 Get Backend URL

After deployment, Railway will give you a URL like:
```
https://nikses-backend-production.up.railway.app
```

**Copy this URL** - you'll need it for the frontend.

---

## Step 4: Deploy Frontend

### 4.1 Create Frontend Service

1. Click **"New Service"** again
2. Select **"GitHub Repo"** → Same repo

### 4.2 Configure Frontend

Go to **Settings**:

**Root Directory:** `frontend`

Go to **Variables** tab and add:

```
# Backend URL (from Step 3.3) - NO trailing slash!
VITE_API_URL=https://nikses-backend-production.up.railway.app
```

### 4.3 Build Configuration

Railway should auto-detect the Dockerfile. The frontend will build with the `VITE_API_URL` embedded.

---

## Step 5: Verify Deployment

### Check Backend Health

Visit: `https://YOUR-BACKEND-URL/api/v1/health`

Should return:
```json
{
  "status": "healthy",
  "timestamp": "2024-...",
  "service": "nikses-api",
  "version": "1.0.0"
}
```

### Check Frontend

Visit your frontend URL. You should see the NiksES interface.

---

## Environment Variables Reference

### Backend Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes* | Your OpenAI API key |
| `AI_ENABLED` | No | Enable AI analysis (true/false) |
| `AI_PROVIDER` | No | `openai` or `anthropic` |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key |
| `PHISHTANK_API_KEY` | No | PhishTank API key |
| `ANTHROPIC_API_KEY` | No | Anthropic API key (if using Claude) |
| `SECRET_KEY` | Yes | Random string for encryption |
| `DATABASE_URL` | No | SQLite path (default works) |
| `DEBUG` | No | Set `false` for production |

*Required if you want AI features

### Frontend Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_API_URL` | Yes | Full backend URL (no trailing slash) |

---

## Troubleshooting

### Frontend can't connect to backend

1. Check `VITE_API_URL` is set correctly (no trailing slash)
2. Verify backend is running: visit `/api/v1/health`
3. Check CORS - backend allows all origins by default

### Backend deployment fails

1. Check logs in Railway dashboard
2. Ensure all required dependencies are in `requirements.txt`
3. Verify Dockerfile syntax

### AI analysis not working

1. Verify `OPENAI_API_KEY` is set correctly
2. Check `AI_ENABLED=true`
3. Test with `/api/v1/settings` endpoint

### Analysis slow or timing out

1. VirusTotal free tier is limited (4 req/min)
2. Consider adding `API_TIMEOUT_ENRICHMENT=30`

---

## Cost Estimation

### Railway Free Tier
- 500 hours/month execution time
- Enough for personal/testing use

### API Costs (Pay-as-you-go)
- **OpenAI**: ~$0.01-0.05 per email analysis
- **VirusTotal**: Free tier (4 req/min)
- **AbuseIPDB**: Free tier (1000 req/day)

---

## Custom Domain (Optional)

1. Go to your frontend service **Settings**
2. Click **"Generate Domain"** or **"Add Custom Domain"**
3. Follow DNS instructions for custom domain

---

## Quick Deploy Commands (Alternative)

If you prefer CLI:

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy backend
cd backend
railway up

# Deploy frontend (in new terminal)
cd frontend
railway up
```

---

## Support

- Railway Docs: https://docs.railway.app
- NiksES Issues: [Your GitHub repo]/issues
