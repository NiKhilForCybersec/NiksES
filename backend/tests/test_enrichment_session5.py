"""
NiksES Session 5 - Enrichment Module Tests

Tests for all enrichment providers without making actual API calls.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

# Add path for imports
import sys
sys.path.insert(0, '/home/claude/nikses/backend')

from app.models.enrichment import (
    ThreatIntelVerdict,
    DomainEnrichment,
    IPEnrichment,
    URLEnrichment,
    AttachmentEnrichment,
    EnrichmentResults,
)
from app.utils.exceptions import (
    EnrichmentError,
    APIConnectionError,
    APIAuthenticationError,
    APIRateLimitError,
)


class TestGeoIPProvider:
    """Tests for GeoIP provider."""
    
    def test_provider_initialization(self):
        """Test GeoIP provider initializes correctly."""
        from app.services.enrichment.geoip import GeoIPProvider
        
        provider = GeoIPProvider()
        assert provider.is_configured == True
        assert provider.requires_api_key == False
        assert provider.is_free == True
    
    def test_parse_asn(self):
        """Test ASN parsing from AS string."""
        from app.services.enrichment.geoip import GeoIPProvider
        
        provider = GeoIPProvider()
        
        # Standard format
        assert provider._parse_asn("AS15169 Google LLC") == 15169
        
        # Just AS number
        assert provider._parse_asn("AS12345") == 12345
        
        # Empty
        assert provider._parse_asn("") is None
        assert provider._parse_asn(None) is None


class TestDNSResolver:
    """Tests for DNS resolver."""
    
    def test_resolver_initialization(self):
        """Test DNS resolver initializes correctly."""
        from app.services.enrichment.dns_resolver import DNSResolver
        
        resolver = DNSResolver()
        assert resolver.is_configured == True
        assert resolver.requires_api_key == False


class TestWHOISProvider:
    """Tests for WHOIS provider."""
    
    def test_provider_initialization(self):
        """Test WHOIS provider initializes correctly."""
        from app.services.enrichment.whois_lookup import WHOISProvider
        
        provider = WHOISProvider()
        assert provider.is_configured == True
        assert provider.requires_api_key == False
    
    def test_get_registrable_domain(self):
        """Test extraction of registrable domain."""
        from app.services.enrichment.whois_lookup import WHOISProvider
        
        provider = WHOISProvider()
        
        # Simple domain
        assert provider._get_registrable_domain("example.com") == "example.com"
        
        # Subdomain
        assert provider._get_registrable_domain("mail.example.com") == "example.com"
        
        # Deep subdomain
        assert provider._get_registrable_domain("a.b.c.example.com") == "example.com"
        
        # Country TLD
        assert provider._get_registrable_domain("www.example.co.uk") == "example.co.uk"
    
    def test_parse_date(self):
        """Test date parsing from various formats."""
        from app.services.enrichment.whois_lookup import WHOISProvider
        
        provider = WHOISProvider()
        
        # datetime object
        dt = datetime(2024, 1, 15, 12, 0, 0)
        assert provider._parse_date(dt) == dt
        
        # ISO format string
        result = provider._parse_date("2024-01-15")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        
        # List (first element)
        result = provider._parse_date([datetime(2024, 1, 15)])
        assert result.year == 2024
        
        # None
        assert provider._parse_date(None) is None
    
    def test_get_first(self):
        """Test first value extraction."""
        from app.services.enrichment.whois_lookup import WHOISProvider
        
        provider = WHOISProvider()
        
        assert provider._get_first("single") == "single"
        assert provider._get_first(["first", "second"]) == "first"
        assert provider._get_first([]) is None
        assert provider._get_first(None) is None


class TestVirusTotalProvider:
    """Tests for VirusTotal provider."""
    
    def test_provider_not_configured_without_key(self):
        """Test provider requires API key."""
        from app.services.enrichment.virustotal import VirusTotalProvider
        
        provider = VirusTotalProvider()
        assert provider.is_configured == False
        
        provider_with_key = VirusTotalProvider(api_key="test_key")
        assert provider_with_key.is_configured == True
    
    def test_determine_verdict(self):
        """Test verdict determination from stats."""
        from app.services.enrichment.virustotal import VirusTotalProvider
        
        provider = VirusTotalProvider()
        
        # Malicious (3+ detections)
        stats = {'malicious': 5, 'suspicious': 0, 'harmless': 50, 'undetected': 10}
        assert provider._determine_verdict(stats) == ThreatIntelVerdict.MALICIOUS
        
        # Suspicious (1-2 malicious or 3+ suspicious)
        stats = {'malicious': 1, 'suspicious': 0, 'harmless': 60, 'undetected': 5}
        assert provider._determine_verdict(stats) == ThreatIntelVerdict.SUSPICIOUS
        
        stats = {'malicious': 0, 'suspicious': 5, 'harmless': 55, 'undetected': 5}
        assert provider._determine_verdict(stats) == ThreatIntelVerdict.SUSPICIOUS
        
        # Clean
        stats = {'malicious': 0, 'suspicious': 0, 'harmless': 60, 'undetected': 5}
        assert provider._determine_verdict(stats) == ThreatIntelVerdict.CLEAN
        
        # Unknown
        assert provider._determine_verdict({}) == ThreatIntelVerdict.UNKNOWN
        assert provider._determine_verdict(None) == ThreatIntelVerdict.UNKNOWN
    
    def test_headers(self):
        """Test API headers include key."""
        from app.services.enrichment.virustotal import VirusTotalProvider
        
        provider = VirusTotalProvider(api_key="my_api_key")
        headers = provider._get_headers()
        
        assert headers['x-apikey'] == 'my_api_key'
        assert 'Accept' in headers


class TestAbuseIPDBProvider:
    """Tests for AbuseIPDB provider."""
    
    def test_provider_not_configured_without_key(self):
        """Test provider requires API key."""
        from app.services.enrichment.abuseipdb import AbuseIPDBProvider
        
        provider = AbuseIPDBProvider()
        assert provider.is_configured == False
        
        provider_with_key = AbuseIPDBProvider(api_key="test_key")
        assert provider_with_key.is_configured == True
    
    def test_determine_verdict(self):
        """Test verdict determination from abuse score."""
        from app.services.enrichment.abuseipdb import AbuseIPDBProvider
        
        provider = AbuseIPDBProvider()
        
        # Malicious (80+)
        assert provider._determine_verdict(90) == ThreatIntelVerdict.MALICIOUS
        assert provider._determine_verdict(80) == ThreatIntelVerdict.MALICIOUS
        
        # Suspicious (25-79)
        assert provider._determine_verdict(50) == ThreatIntelVerdict.SUSPICIOUS
        assert provider._determine_verdict(25) == ThreatIntelVerdict.SUSPICIOUS
        
        # Clean (0)
        assert provider._determine_verdict(0) == ThreatIntelVerdict.CLEAN
        
        # Low suspicious (1-24)
        assert provider._determine_verdict(10) == ThreatIntelVerdict.SUSPICIOUS
    
    def test_categories_mapping(self):
        """Test category ID to name mapping."""
        from app.services.enrichment.abuseipdb import AbuseIPDBProvider
        
        provider = AbuseIPDBProvider()
        
        assert provider.CATEGORIES[7] == "Phishing"
        assert provider.CATEGORIES[14] == "Port Scan"
        assert provider.CATEGORIES[18] == "Brute-Force"


class TestURLhausProvider:
    """Tests for URLhaus provider."""
    
    def test_provider_initialization(self):
        """Test URLhaus provider initializes correctly."""
        from app.services.enrichment.urlhaus import URLhausProvider
        
        provider = URLhausProvider()
        assert provider.is_configured == True
        assert provider.requires_api_key == False
        assert provider.is_free == True


class TestPhishTankProvider:
    """Tests for PhishTank provider."""
    
    def test_provider_initialization(self):
        """Test PhishTank provider initializes correctly."""
        from app.services.enrichment.phishtank import PhishTankProvider
        
        provider = PhishTankProvider()
        assert provider.is_configured == True
        assert provider.requires_api_key == False
        
        provider_with_key = PhishTankProvider(api_key="optional_key")
        assert provider_with_key.is_configured == True


class TestEnrichmentOrchestrator:
    """Tests for enrichment orchestrator."""
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initializes all providers."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator()
        
        # Check all providers exist
        assert orchestrator.geoip is not None
        assert orchestrator.dns is not None
        assert orchestrator.whois is not None
        assert orchestrator.virustotal is not None
        assert orchestrator.abuseipdb is not None
        assert orchestrator.urlhaus is not None
        assert orchestrator.phishtank is not None
    
    def test_configure_api_keys(self):
        """Test API key configuration."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator()
        
        # Initially not configured
        assert orchestrator.virustotal.is_configured == False
        
        # Configure
        orchestrator.configure_api_keys(
            virustotal_api_key="vt_key",
            abuseipdb_api_key="abuse_key"
        )
        
        assert orchestrator.virustotal.is_configured == True
        assert orchestrator.abuseipdb.is_configured == True
    
    def test_combine_verdicts(self):
        """Test verdict combination logic."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator()
        
        # Malicious takes priority
        verdicts = [ThreatIntelVerdict.CLEAN, ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.UNKNOWN]
        assert orchestrator._combine_verdicts(verdicts) == ThreatIntelVerdict.MALICIOUS
        
        # Suspicious next
        verdicts = [ThreatIntelVerdict.CLEAN, ThreatIntelVerdict.SUSPICIOUS, ThreatIntelVerdict.UNKNOWN]
        assert orchestrator._combine_verdicts(verdicts) == ThreatIntelVerdict.SUSPICIOUS
        
        # Clean over unknown
        verdicts = [ThreatIntelVerdict.CLEAN, ThreatIntelVerdict.UNKNOWN]
        assert orchestrator._combine_verdicts(verdicts) == ThreatIntelVerdict.CLEAN
        
        # All unknown
        verdicts = [ThreatIntelVerdict.UNKNOWN, ThreatIntelVerdict.UNKNOWN]
        assert orchestrator._combine_verdicts(verdicts) == ThreatIntelVerdict.UNKNOWN
    
    def test_extract_domain(self):
        """Test domain extraction from URL."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator()
        
        assert orchestrator._extract_domain("https://example.com/path") == "example.com"
        assert orchestrator._extract_domain("http://sub.example.com:8080/path") == "sub.example.com:8080"
        assert orchestrator._extract_domain("invalid") == ""
    
    def test_get_provider_status(self):
        """Test provider status reporting."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator(virustotal_api_key="test_key")
        
        status = orchestrator.get_provider_status()
        
        assert 'geoip' in status
        assert status['geoip']['configured'] == True
        assert status['geoip']['requires_key'] == False
        
        assert 'virustotal' in status
        assert status['virustotal']['configured'] == True
        assert status['virustotal']['requires_key'] == True
    
    def test_cache_operations(self):
        """Test cache set and get."""
        from app.services.enrichment.orchestrator import EnrichmentOrchestrator
        
        orchestrator = EnrichmentOrchestrator()
        
        # Set cache
        orchestrator._set_cache("test_key", {"data": "value"})
        
        # Get cache
        cached = orchestrator._get_cache("test_key")
        assert cached == {"data": "value"}
        
        # Non-existent key
        assert orchestrator._get_cache("nonexistent") is None
        
        # Clear cache
        orchestrator.clear_cache()
        assert orchestrator._get_cache("test_key") is None


class TestEnrichmentModels:
    """Tests for enrichment Pydantic models."""
    
    def test_domain_enrichment_model(self):
        """Test DomainEnrichment model creation."""
        enrichment = DomainEnrichment(
            domain="example.com",
            registrar="GoDaddy",
            age_days=365,
            is_newly_registered=False,
            has_mx_records=True,
            has_spf_record=True,
            has_dmarc_record=True,
        )
        
        assert enrichment.domain == "example.com"
        assert enrichment.age_days == 365
        assert enrichment.is_newly_registered == False
    
    def test_ip_enrichment_model(self):
        """Test IPEnrichment model creation."""
        enrichment = IPEnrichment(
            ip_address="8.8.8.8",
            country="United States",
            country_code="US",
            asn=15169,
            as_org="Google LLC",
            abuseipdb_score=0,
            abuseipdb_verdict=ThreatIntelVerdict.CLEAN,
        )
        
        assert enrichment.ip_address == "8.8.8.8"
        assert enrichment.asn == 15169
        assert enrichment.abuseipdb_verdict == ThreatIntelVerdict.CLEAN
    
    def test_url_enrichment_model(self):
        """Test URLEnrichment model creation."""
        enrichment = URLEnrichment(
            url="https://example.com/test",
            domain="example.com",
            virustotal_positives=0,
            virustotal_total=70,
            final_verdict=ThreatIntelVerdict.CLEAN,
        )
        
        assert enrichment.url == "https://example.com/test"
        assert enrichment.final_verdict == ThreatIntelVerdict.CLEAN
    
    def test_attachment_enrichment_model(self):
        """Test AttachmentEnrichment model creation."""
        enrichment = AttachmentEnrichment(
            sha256="a" * 64,
            md5="b" * 32,
            filename="document.pdf",
            virustotal_positives=5,
            virustotal_total=70,
            final_verdict=ThreatIntelVerdict.MALICIOUS,
        )
        
        assert enrichment.filename == "document.pdf"
        assert enrichment.final_verdict == ThreatIntelVerdict.MALICIOUS


class TestExceptions:
    """Tests for custom exceptions."""
    
    def test_enrichment_error(self):
        """Test EnrichmentError exception."""
        error = EnrichmentError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
    
    def test_api_connection_error(self):
        """Test APIConnectionError exception."""
        error = APIConnectionError("Connection failed")
        assert isinstance(error, EnrichmentError)
        assert "Connection failed" in str(error)
    
    def test_api_authentication_error(self):
        """Test APIAuthenticationError exception."""
        error = APIAuthenticationError("Invalid API key")
        assert isinstance(error, EnrichmentError)
    
    def test_api_rate_limit_error(self):
        """Test APIRateLimitError exception."""
        error = APIRateLimitError("Rate limit exceeded")
        assert isinstance(error, EnrichmentError)


def run_tests():
    """Run all tests and report results."""
    test_classes = [
        TestGeoIPProvider,
        TestDNSResolver,
        TestWHOISProvider,
        TestVirusTotalProvider,
        TestAbuseIPDBProvider,
        TestURLhausProvider,
        TestPhishTankProvider,
        TestEnrichmentOrchestrator,
        TestEnrichmentModels,
        TestExceptions,
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        instance = test_class()
        methods = [m for m in dir(instance) if m.startswith('test_')]
        
        for method_name in methods:
            total_tests += 1
            try:
                method = getattr(instance, method_name)
                method()
                passed_tests += 1
                print(f"  ✓ {test_class.__name__}.{method_name}")
            except Exception as e:
                failed_tests.append((f"{test_class.__name__}.{method_name}", str(e)))
                print(f"  ✗ {test_class.__name__}.{method_name}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Tests: {passed_tests}/{total_tests} passed")
    
    if failed_tests:
        print(f"\nFailed tests:")
        for name, error in failed_tests:
            print(f"  - {name}: {error}")
    
    return len(failed_tests) == 0


if __name__ == "__main__":
    print("NiksES Session 5 - Enrichment Module Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
