#!/usr/bin/env python3
"""
NiksES Quick Diagnostic
Run this to verify your setup is working correctly.
"""

import os
import sys

# Load .env file
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("NIKSES DIAGNOSTIC")
print("=" * 60)

# Check 1: Environment variables
print("\n[1] ENVIRONMENT VARIABLES")
keys = {
    'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
    'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
    'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY'),
    'AI_ENABLED': os.getenv('AI_ENABLED'),
    'AI_PROVIDER': os.getenv('AI_PROVIDER'),
}

all_set = True
for name, value in keys.items():
    if value:
        display = value[:20] + '...' if len(value) > 20 else value
        print(f"  ✓ {name}: {display}")
    else:
        print(f"  ✗ {name}: NOT SET")
        if name in ['OPENAI_API_KEY', 'AI_ENABLED']:
            all_set = False

if not all_set:
    print("\n  ⚠️  Make sure you have a .env file with your API keys!")
    print("  Copy .env.example to .env and add your keys.")

# Check 2: Test API connections
print("\n[2] API CONNECTIVITY TESTS")

import asyncio
import aiohttp

async def test_apis():
    results = {}
    
    # Test VirusTotal
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key and vt_key != 'your_virustotal_api_key_here':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://www.virustotal.com/api/v3/domains/google.com",
                    headers={"x-apikey": vt_key},
                    timeout=10
                ) as resp:
                    if resp.status == 200:
                        print("  ✓ VirusTotal API: WORKING")
                        results['vt'] = True
                    elif resp.status == 401:
                        print("  ✗ VirusTotal API: INVALID KEY")
                        results['vt'] = False
                    else:
                        print(f"  ✗ VirusTotal API: Error {resp.status}")
                        results['vt'] = False
        except Exception as e:
            print(f"  ✗ VirusTotal API: Connection failed - {e}")
            results['vt'] = False
    else:
        print("  ○ VirusTotal API: Not configured")
        results['vt'] = None

    # Test AbuseIPDB
    abuse_key = os.getenv('ABUSEIPDB_API_KEY')
    if abuse_key and abuse_key != 'your_abuseipdb_api_key_here':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
                    timeout=10
                ) as resp:
                    if resp.status == 200:
                        print("  ✓ AbuseIPDB API: WORKING")
                        results['abuse'] = True
                    elif resp.status == 401:
                        print("  ✗ AbuseIPDB API: INVALID KEY")
                        results['abuse'] = False
                    else:
                        print(f"  ✗ AbuseIPDB API: Error {resp.status}")
                        results['abuse'] = False
        except Exception as e:
            print(f"  ✗ AbuseIPDB API: Connection failed - {e}")
            results['abuse'] = False
    else:
        print("  ○ AbuseIPDB API: Not configured")
        results['abuse'] = None

    # Test OpenAI
    openai_key = os.getenv('OPENAI_API_KEY')
    if openai_key and openai_key != 'your_openai_api_key_here':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {openai_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "Say OK"}],
                        "max_tokens": 5
                    },
                    timeout=30
                ) as resp:
                    if resp.status == 200:
                        print("  ✓ OpenAI API: WORKING")
                        results['openai'] = True
                    elif resp.status == 401:
                        print("  ✗ OpenAI API: INVALID KEY")
                        results['openai'] = False
                    else:
                        text = await resp.text()
                        print(f"  ✗ OpenAI API: Error {resp.status} - {text[:100]}")
                        results['openai'] = False
        except Exception as e:
            print(f"  ✗ OpenAI API: Connection failed - {e}")
            results['openai'] = False
    else:
        print("  ○ OpenAI API: Not configured")
        results['openai'] = None
    
    return results

results = asyncio.run(test_apis())

# Check 3: Database
print("\n[3] DATABASE")
from pathlib import Path
db_path = Path(__file__).parent / "data" / "analyses.db"
if db_path.exists():
    size = db_path.stat().st_size
    print(f"  ✓ SQLite database exists: {size} bytes")
else:
    print("  ○ SQLite database will be created on first analysis")

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)

if results.get('openai'):
    print("  ✓ AI Analysis: READY (OpenAI)")
elif os.getenv('OPENAI_API_KEY'):
    print("  ✗ AI Analysis: OpenAI key set but not working")
else:
    print("  ✗ AI Analysis: Not configured (add OPENAI_API_KEY to .env)")

if results.get('vt'):
    print("  ✓ Threat Intel: VirusTotal READY")
else:
    print("  ○ Threat Intel: VirusTotal not configured")

if results.get('abuse'):
    print("  ✓ IP Reputation: AbuseIPDB READY")
else:
    print("  ○ IP Reputation: AbuseIPDB not configured")

print("\n" + "=" * 60)
print("To start NiksES:")
print("  Backend:  python3 -m uvicorn app.main:app --reload --port 8000")
print("  Frontend: cd ../frontend && npm run dev")
print("=" * 60)
