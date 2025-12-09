#!/usr/bin/env python3
"""
Full diagnostic test for NiksES API integration
"""
import os
import asyncio
import json

# Set API keys directly
os.environ['VIRUSTOTAL_API_KEY'] = '833102560105ca38388a96b7be2d726dce79862cbd8f799babc6b6ffef8a49ab'
os.environ['ABUSEIPDB_API_KEY'] = '03c5abb7c1fdbb45d2224a71e6e7498992bcdfbb07aa46f4c827892ca8f06b871275134f8792109e'
os.environ['OPENAI_API_KEY'] = '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'
os.environ['AI_ENABLED'] = 'true'
os.environ['AI_PROVIDER'] = 'openai'

print("=" * 60)
print("NIKSES FULL DIAGNOSTIC TEST")
print("=" * 60)

# Test 1: Check environment
print("\n[1] ENVIRONMENT CHECK")
print(f"  VIRUSTOTAL_API_KEY: {'SET (' + os.getenv('VIRUSTOTAL_API_KEY')[:20] + '...)' if os.getenv('VIRUSTOTAL_API_KEY') else 'NOT SET'}")
print(f"  ABUSEIPDB_API_KEY: {'SET (' + os.getenv('ABUSEIPDB_API_KEY')[:20] + '...)' if os.getenv('ABUSEIPDB_API_KEY') else 'NOT SET'}")
print(f"  OPENAI_API_KEY: {'SET (' + os.getenv('OPENAI_API_KEY')[:20] + '...)' if os.getenv('OPENAI_API_KEY') else 'NOT SET'}")
print(f"  AI_ENABLED: {os.getenv('AI_ENABLED')}")
print(f"  AI_PROVIDER: {os.getenv('AI_PROVIDER')}")

# Test 2: Direct VirusTotal API test
print("\n[2] VIRUSTOTAL DIRECT API TEST")
try:
    import aiohttp
    async def test_vt():
        url = "https://www.virustotal.com/api/v3/domains/google.com"
        headers = {"x-apikey": os.getenv('VIRUSTOTAL_API_KEY')}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as resp:
                print(f"  Status: {resp.status}")
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    print(f"  ✓ VirusTotal API working! google.com stats: {stats}")
                    return True
                elif resp.status == 401:
                    print(f"  ✗ Invalid API key!")
                else:
                    text = await resp.text()
                    print(f"  ✗ Error: {text[:200]}")
                return False
    vt_works = asyncio.run(test_vt())
except Exception as e:
    print(f"  ✗ Error: {e}")
    vt_works = False

# Test 3: Direct AbuseIPDB test
print("\n[3] ABUSEIPDB DIRECT API TEST")
try:
    async def test_abuse():
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": os.getenv('ABUSEIPDB_API_KEY'), "Accept": "application/json"}
        params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                print(f"  Status: {resp.status}")
                if resp.status == 200:
                    data = await resp.json()
                    score = data.get('data', {}).get('abuseConfidenceScore', 0)
                    print(f"  ✓ AbuseIPDB API working! 8.8.8.8 abuse score: {score}%")
                    return True
                elif resp.status == 401:
                    print(f"  ✗ Invalid API key!")
                else:
                    text = await resp.text()
                    print(f"  ✗ Error: {text[:200]}")
                return False
    abuse_works = asyncio.run(test_abuse())
except Exception as e:
    print(f"  ✗ Error: {e}")
    abuse_works = False

# Test 4: Direct OpenAI test
print("\n[4] OPENAI DIRECT API TEST")
try:
    async def test_openai():
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Say 'API working' in 2 words"}],
            "max_tokens": 10
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=data, timeout=30) as resp:
                print(f"  Status: {resp.status}")
                if resp.status == 200:
                    result = await resp.json()
                    reply = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                    print(f"  ✓ OpenAI API working! Response: {reply}")
                    return True
                elif resp.status == 401:
                    text = await resp.text()
                    print(f"  ✗ Invalid API key! {text[:100]}")
                else:
                    text = await resp.text()
                    print(f"  ✗ Error: {text[:200]}")
                return False
    openai_works = asyncio.run(test_openai())
except Exception as e:
    print(f"  ✗ Error: {e}")
    openai_works = False

# Test 5: Full analysis through API
print("\n[5] FULL ANALYSIS TEST")
try:
    from fastapi.testclient import TestClient
    from app.main import app
    from io import BytesIO
    
    test_email = b'''From: attacker@malicious-phish.xyz
To: victim@company.com
Subject: URGENT: Your account will be suspended!
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test123@malicious-phish.xyz>
Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=malicious-phish.xyz;
    dkim=fail header.d=malicious-phish.xyz;
    dmarc=fail header.from=malicious-phish.xyz
Received: from mail.malicious-phish.xyz (185.220.101.1) by mx.company.com with SMTP
Content-Type: text/html

<html>
<body>
<p>Dear Customer,</p>
<p>Your account has been compromised! Click here immediately:</p>
<p><a href="https://paypa1-security.xyz/verify">Verify Account</a></p>
<p>Or call us at 1-800-555-1234</p>
<p>Send $500 in gift cards to resolve this issue.</p>
</body>
</html>
'''
    
    with TestClient(app) as client:
        # Check settings first
        settings_resp = client.get('/api/v1/settings')
        settings = settings_resp.json()
        print(f"  Settings loaded:")
        print(f"    AI enabled: {settings.get('ai_enabled')}")
        print(f"    AI provider: {settings.get('ai_provider')}")
        print(f"    API keys configured: {settings.get('api_keys_configured')}")
        
        # Run analysis
        files = {'file': ('phish.eml', BytesIO(test_email), 'message/rfc822')}
        data = {'enable_enrichment': 'true', 'enable_ai': 'true'}
        
        print(f"\n  Running full analysis...")
        response = client.post('/api/v1/analyze', files=files, data=data)
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\n  === RESULTS ===")
            print(f"  Analysis ID: {result.get('analysis_id', 'N/A')[:8]}...")
            print(f"  Duration: {result.get('analysis_duration_ms')}ms")
            
            print(f"\n  --- DETECTION ---")
            det = result.get('detection', {})
            print(f"  Risk Score: {det.get('risk_score')}/100")
            print(f"  Risk Level: {det.get('risk_level')}")
            print(f"  Classification: {det.get('primary_classification')}")
            print(f"  Rules Triggered: {len(det.get('rules_triggered', []))}")
            
            print(f"\n  --- AUTHENTICATION ---")
            email_data = result.get('email', {})
            spf = email_data.get('spf_result') or email_data.get('header_analysis', {}).get('spf_result')
            dkim = email_data.get('dkim_result') or email_data.get('header_analysis', {}).get('dkim_result')
            dmarc = email_data.get('dmarc_result') or email_data.get('header_analysis', {}).get('dmarc_result')
            print(f"  SPF: {spf.get('result') if spf else 'NOT FOUND'}")
            print(f"  DKIM: {dkim.get('result') if dkim else 'NOT FOUND'}")
            print(f"  DMARC: {dmarc.get('result') if dmarc else 'NOT FOUND'}")
            
            print(f"\n  --- ENRICHMENT ---")
            enrich = result.get('enrichment', {})
            sender_domain = enrich.get('sender_domain')
            if sender_domain:
                print(f"  Sender Domain: {sender_domain.get('domain')}")
                print(f"    VT Verdict: {sender_domain.get('virustotal_verdict', 'N/A')}")
                print(f"    Has SPF: {sender_domain.get('has_spf_record')}")
                print(f"    Has DMARC: {sender_domain.get('has_dmarc_record')}")
            else:
                print(f"  Sender Domain: NOT ENRICHED")
            
            orig_ip = enrich.get('originating_ip')
            if orig_ip:
                print(f"  Originating IP: {orig_ip.get('ip_address')}")
                print(f"    Country: {orig_ip.get('country')}")
                print(f"    ASN: {orig_ip.get('asn')}")
                print(f"    Abuse Score: {orig_ip.get('abuse_confidence_score')}%")
            else:
                print(f"  Originating IP: NOT ENRICHED")
            
            print(f"\n  --- AI TRIAGE ---")
            ai = result.get('ai_triage')
            if ai:
                print(f"  ✓ AI Analysis Available!")
                print(f"    Model: {ai.get('model_used')}")
                print(f"    Summary: {ai.get('summary', '')[:100]}...")
                actions = ai.get('recommended_actions', [])
                print(f"    Recommended Actions: {len(actions)}")
            else:
                print(f"  ✗ AI Analysis NOT available")
                
            print(f"\n  --- API KEYS USED ---")
            print(f"  {result.get('api_keys_used', [])}")
            
            print(f"\n  --- ENRICHMENT ERRORS ---")
            errors = result.get('enrichment_errors', [])
            if errors:
                for err in errors[:5]:
                    print(f"  ! {err}")
            else:
                print(f"  None")
                
        else:
            print(f"  ✗ Error: {response.status_code}")
            print(f"  {response.text[:500]}")
            
except Exception as e:
    import traceback
    print(f"  ✗ Error: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("DIAGNOSTIC COMPLETE")
print("=" * 60)
