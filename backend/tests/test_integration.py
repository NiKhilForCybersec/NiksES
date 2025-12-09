"""
NiksES Session 11 - Integration Tests

End-to-end tests for the complete analysis pipeline.
"""

import sys
sys.path.insert(0, '/home/claude/nikses/backend')

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch


# Sample test email content
SAMPLE_PHISHING_EML = """From: security@paypa1.com
To: victim@example.com
Subject: Urgent: Verify Your Account Now!
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test123@paypa1.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

<html>
<body>
<p>Dear Customer,</p>
<p>Your account will be suspended within 24 hours unless you verify immediately!</p>
<p>Click here to verify: <a href="http://paypa1-secure.com/verify?id=12345">Verify Now</a></p>
<p>Act now or lose access to your funds!</p>
<p>PayPal Security Team</p>
</body>
</html>
"""

SAMPLE_CLEAN_EML = """From: john.doe@company.com
To: jane.smith@company.com
Subject: Meeting Tomorrow
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <meeting123@company.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass

Hi Jane,

Just wanted to confirm our meeting tomorrow at 2 PM in the conference room.

Best regards,
John
"""

SAMPLE_BEC_EML = """From: "CEO John Smith" <ceo.john.smith@gmai1.com>
To: accounting@company.com
Reply-To: ceo.personal@yahoo.com
Subject: Urgent Wire Transfer Required - Confidential
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <urgent123@gmai1.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi,

I need you to process an urgent wire transfer immediately. This is confidential - do not discuss with anyone.

Amount: $47,500
Account: 1234567890
Bank: International Bank
Reference: Acquisition Deal

Please confirm when done. I'm in meetings all day so email only.

Thanks,
John Smith
CEO
"""


def create_email_address(email: str, display_name: str = None):
    """Helper to create EmailAddress objects."""
    from app.models.email import EmailAddress
    
    parts = email.split('@')
    local = parts[0] if len(parts) > 0 else ''
    domain = parts[1] if len(parts) > 1 else ''
    
    return EmailAddress(
        raw=f'"{display_name}" <{email}>' if display_name else email,
        email=email,
        display_name=display_name,
        domain=domain,
        local_part=local,
    )


class TestEmailParsing:
    """Tests for email parsing integration."""
    
    def test_parse_phishing_email(self):
        """Test parsing a phishing email."""
        from app.services.parser import parse_eml_bytes
        
        async def run_test():
            result = await parse_eml_bytes(SAMPLE_PHISHING_EML.encode())
            
            assert result is not None
            assert result.subject == "Urgent: Verify Your Account Now!"
            assert result.sender.email == "security@paypa1.com"
            assert result.sender.domain == "paypa1.com"
            assert len(result.urls) > 0
            
            return result
        
        return asyncio.run(run_test())
    
    def test_parse_clean_email(self):
        """Test parsing a clean email."""
        from app.services.parser import parse_eml_bytes
        
        async def run_test():
            result = await parse_eml_bytes(SAMPLE_CLEAN_EML.encode())
            
            assert result is not None
            assert result.subject == "Meeting Tomorrow"
            assert result.sender.domain == "company.com"
            
            return result
        
        return asyncio.run(run_test())
    
    def test_parse_bec_email(self):
        """Test parsing a BEC email."""
        from app.services.parser import parse_eml_bytes
        
        async def run_test():
            result = await parse_eml_bytes(SAMPLE_BEC_EML.encode())
            
            assert result is not None
            assert "wire transfer" in result.subject.lower()
            
            return result
        
        return asyncio.run(run_test())


class TestDetectionPipeline:
    """Tests for detection engine integration."""
    
    def test_detect_phishing(self):
        """Test detection of phishing indicators."""
        from app.services.parser import parse_eml_bytes
        from app.services.detection import get_detection_engine
        
        async def run_test():
            # Parse email
            email = await parse_eml_bytes(SAMPLE_PHISHING_EML.encode())
            
            # Run detection
            engine = get_detection_engine()
            results = await engine.analyze(email, None)
            
            # Verify detection
            assert results.risk_score >= 40, f"Expected medium+ risk score, got {results.risk_score}"
            assert len(results.rules_triggered) > 0
            
            return results
        
        return asyncio.run(run_test())
    
    def test_detect_clean_email(self):
        """Test that clean emails get low risk scores."""
        from app.services.parser import parse_eml_bytes
        from app.services.detection import get_detection_engine
        
        async def run_test():
            email = await parse_eml_bytes(SAMPLE_CLEAN_EML.encode())
            
            engine = get_detection_engine()
            results = await engine.analyze(email, None)
            
            # Clean email should have low risk
            assert results.risk_score < 50, f"Expected low risk score, got {results.risk_score}"
            
            return results
        
        return asyncio.run(run_test())
    
    def test_detect_bec(self):
        """Test detection of BEC indicators."""
        from app.services.parser import parse_eml_bytes
        from app.services.detection import get_detection_engine
        
        async def run_test():
            email = await parse_eml_bytes(SAMPLE_BEC_EML.encode())
            
            engine = get_detection_engine()
            results = await engine.analyze(email, None)
            
            # BEC should have some risk
            assert results.risk_score >= 30, f"Expected medium risk, got {results.risk_score}"
            
            return results
        
        return asyncio.run(run_test())


class TestExportIntegration:
    """Tests for export functionality."""
    
    def test_json_export_complete(self):
        """Test complete JSON export."""
        from app.services.parser import parse_eml_bytes
        from app.services.detection import get_detection_engine
        from app.services.export import export_to_json
        from app.models.analysis import AnalysisResult, ExtractedIOCs
        from app.models.enrichment import EnrichmentResults
        import json
        
        async def run_test():
            # Parse and detect
            email = await parse_eml_bytes(SAMPLE_PHISHING_EML.encode())
            
            engine = get_detection_engine()
            detection = await engine.analyze(email, None)
            
            # Create analysis result
            result = AnalysisResult(
                analysis_id="test-123",
                analyzed_at=datetime.now(timezone.utc),
                analysis_duration_ms=100,
                email=email,
                enrichment=EnrichmentResults(),
                detection=detection,
                ai_triage=None,
                iocs=ExtractedIOCs(
                    domains=["paypa1.com", "paypa1-secure.com"],
                    urls=["http://paypa1-secure.com/verify?id=12345"],
                    ips=[],
                    email_addresses=["security@paypa1.com"],
                    file_hashes_sha256=[],
                    file_hashes_md5=[],
                    phone_numbers=[],
                ),
                api_keys_used=[],
                enrichment_errors=[],
            )
            
            # Export to JSON
            json_output = export_to_json(result, pretty=True)
            
            # Verify JSON is valid
            parsed = json.loads(json_output)
            assert parsed['analysis_id'] == "test-123"
            
            return json_output
        
        return asyncio.run(run_test())
    
    def test_stix_export(self):
        """Test STIX export."""
        from app.services.export.stix_export import export_to_stix, create_indicator
        from app.models.analysis import AnalysisResult, ExtractedIOCs
        from app.models.detection import DetectionResults, RiskLevel, EmailClassification
        from app.models.email import ParsedEmail
        from app.models.enrichment import EnrichmentResults
        import json
        
        # Create minimal result for STIX export
        result = AnalysisResult(
            analysis_id="test-stix",
            analyzed_at=datetime.now(timezone.utc),
            analysis_duration_ms=50,
            email=ParsedEmail(
                message_id="test",
                subject="Test",
                sender=create_email_address("test@test.com"),
                recipients=[],
                urls=[],
                attachments=[],
            ),
            enrichment=EnrichmentResults(),
            detection=DetectionResults(
                risk_score=75,
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                primary_classification=EmailClassification.CREDENTIAL_HARVESTING,
                secondary_classifications=[],
                rules_triggered=[],
                rules_passed=[],
            ),
            ai_triage=None,
            iocs=ExtractedIOCs(
                domains=["evil.com"],
                urls=["http://evil.com/phish"],
                ips=["192.168.1.1"],
                email_addresses=["attacker@evil.com"],
                file_hashes_sha256=["abc123"],
                file_hashes_md5=[],
                phone_numbers=[],
            ),
            api_keys_used=[],
            enrichment_errors=[],
        )
        
        stix_output = export_to_stix(result)
        parsed = json.loads(stix_output)
        
        assert parsed['type'] == 'bundle'
        assert len(parsed['objects']) > 0
        
        # Check for indicators
        indicators = [o for o in parsed['objects'] if o['type'] == 'indicator']
        assert len(indicators) > 0
    
    def test_markdown_export(self):
        """Test markdown export."""
        from app.services.export.markdown_export import export_to_markdown
        from app.models.analysis import AnalysisResult, ExtractedIOCs
        from app.models.detection import DetectionResults, RiskLevel, EmailClassification
        from app.models.email import ParsedEmail
        from app.models.enrichment import EnrichmentResults
        
        result = AnalysisResult(
            analysis_id="test-md",
            analyzed_at=datetime.now(timezone.utc),
            analysis_duration_ms=50,
            email=ParsedEmail(
                message_id="test",
                subject="Test Subject",
                sender=create_email_address("sender@test.com"),
                recipients=[],
                urls=[],
                attachments=[],
            ),
            enrichment=EnrichmentResults(),
            detection=DetectionResults(
                risk_score=45,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                primary_classification=EmailClassification.SPAM,
                secondary_classifications=[],
                rules_triggered=[],
                rules_passed=[],
            ),
            ai_triage=None,
            iocs=ExtractedIOCs(
                domains=[],
                urls=[],
                ips=[],
                email_addresses=[],
                file_hashes_sha256=[],
                file_hashes_md5=[],
                phone_numbers=[],
            ),
            api_keys_used=[],
            enrichment_errors=[],
        )
        
        md_output = export_to_markdown(result)
        
        assert "# Email Security Analysis Report" in md_output
        assert "test-md" in md_output
        assert "Test Subject" in md_output


class TestAPIIntegration:
    """Tests for API endpoint integration."""
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        from fastapi.testclient import TestClient
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
    
    def test_capabilities_endpoint(self):
        """Test capabilities endpoint."""
        from fastapi.testclient import TestClient
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/api/v1/health/capabilities")
        
        assert response.status_code == 200
        data = response.json()
        assert 'analysis' in data
        assert 'detection' in data
        assert data['detection']['rule_count'] == 51
    
    def test_settings_endpoint(self):
        """Test settings endpoint."""
        from fastapi.testclient import TestClient
        from app.main import app
        
        client = TestClient(app)
        response = client.get("/api/v1/settings")
        
        assert response.status_code == 200
        data = response.json()
        assert 'enrichment_enabled' in data
        assert 'detection_rules_count' in data


class TestFullPipeline:
    """Tests for the complete analysis pipeline."""
    
    def test_full_analysis_pipeline(self):
        """Test complete analysis from parsing to export."""
        from app.services.parser import parse_eml_bytes
        from app.services.detection import get_detection_engine
        from app.services.export import export_to_json, export_to_markdown
        from app.models.analysis import AnalysisResult, ExtractedIOCs
        from app.models.enrichment import EnrichmentResults
        import json
        
        async def run_test():
            # Step 1: Parse email
            email = await parse_eml_bytes(SAMPLE_PHISHING_EML.encode())
            assert email is not None, "Parsing failed"
            
            # Step 2: Run detection
            engine = get_detection_engine()
            detection = await engine.analyze(email, None)
            assert detection is not None, "Detection failed"
            assert detection.risk_score > 0, "No risk detected"
            
            # Step 3: Extract IOCs
            iocs = ExtractedIOCs(
                domains=[email.sender.domain] if email.sender else [],
                urls=[u.url for u in email.urls],
                ips=[],
                email_addresses=[email.sender.email] if email.sender else [],
                file_hashes_sha256=[],
                file_hashes_md5=[],
                phone_numbers=[],
            )
            
            # Step 4: Create analysis result
            result = AnalysisResult(
                analysis_id="pipeline-test",
                analyzed_at=datetime.now(timezone.utc),
                analysis_duration_ms=150,
                email=email,
                enrichment=EnrichmentResults(),
                detection=detection,
                ai_triage=None,
                iocs=iocs,
                api_keys_used=[],
                enrichment_errors=[],
            )
            
            # Step 5: Export
            json_out = export_to_json(result)
            md_out = export_to_markdown(result)
            
            # Verify outputs
            parsed_json = json.loads(json_out)
            assert parsed_json['analysis_id'] == "pipeline-test"
            assert "# Email Security Analysis Report" in md_out
            
            return {
                'email': email,
                'detection': detection,
                'result': result,
            }
        
        return asyncio.run(run_test())


def run_tests():
    """Run all integration tests."""
    test_classes = [
        TestEmailParsing,
        TestDetectionPipeline,
        TestExportIntegration,
        TestAPIIntegration,
        TestFullPipeline,
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        print(f"\n{test_class.__name__}:")
        instance = test_class()
        methods = [m for m in dir(instance) if m.startswith('test_')]
        
        for method_name in methods:
            total_tests += 1
            try:
                method = getattr(instance, method_name)
                method()
                passed_tests += 1
                print(f"  ✓ {method_name}")
            except Exception as e:
                failed_tests.append((f"{test_class.__name__}.{method_name}", str(e)))
                print(f"  ✗ {method_name}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Integration Tests: {passed_tests}/{total_tests} passed")
    
    if failed_tests:
        print(f"\nFailed tests:")
        for name, error in failed_tests:
            print(f"  - {name}: {error[:100]}")
    
    return len(failed_tests) == 0


if __name__ == "__main__":
    print("NiksES Session 11 - Integration Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
