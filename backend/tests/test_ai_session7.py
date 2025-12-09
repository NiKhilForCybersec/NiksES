"""
NiksES Session 7 - AI Module Tests

Tests for AI providers, prompts, context, and analyzer.
"""

import asyncio
import sys
sys.path.insert(0, '/home/claude/nikses/backend')

from app.models.email import (
    ParsedEmail,
    EmailAddress,
    ExtractedURL,
    AttachmentInfo,
    AuthenticationResult,
)
from app.models.enrichment import (
    EnrichmentResults,
    DomainEnrichment,
    IPEnrichment,
    URLEnrichment,
    ThreatIntelVerdict,
)
from app.models.detection import (
    DetectionResults,
    DetectionRule,
    RiskLevel,
    EmailClassification,
)


def create_test_email(**kwargs):
    """Create a test email with default values."""
    defaults = {
        'subject': 'Urgent: Verify Your Account',
        'body_text': 'Please click the link below to verify your account immediately.',
        'sender': EmailAddress(
            raw='security@paypa1.com',
            email='security@paypa1.com',
            display_name='PayPal Security',
            domain='paypa1.com',
            local_part='security',
        ),
        'to_recipients': [
            EmailAddress(
                raw='user@company.com',
                email='user@company.com',
                domain='company.com',
                local_part='user',
            )
        ],
        'urls': [
            ExtractedURL(
                url='https://paypa1.com/verify',
                normalized_url='https://paypa1.com/verify',
                domain='paypa1.com',
                scheme='https',
                source='body_text',
                is_shortened=False,
            )
        ],
        'attachments': [],
        'qr_codes': [],
        'phone_numbers': [],
        'reply_to': [],
    }
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


def create_test_enrichment():
    """Create test enrichment results."""
    return EnrichmentResults(
        sender_domain=DomainEnrichment(
            domain='paypa1.com',
            is_newly_registered=True,
            age_days=5,
            has_mx_records=True,
            has_spf_record=False,
            virustotal_verdict=ThreatIntelVerdict.SUSPICIOUS,
        ),
        urls=[
            URLEnrichment(
                url='https://paypa1.com/verify',
                domain='paypa1.com',
                final_verdict=ThreatIntelVerdict.MALICIOUS,
                virustotal_positives=15,
                virustotal_total=70,
                phishtank_verified=True,
            )
        ],
    )


def create_test_detection():
    """Create test detection results."""
    return DetectionResults(
        rules_triggered=[
            DetectionRule(
                rule_id='PHISH-001',
                rule_name='Malicious URL',
                category='phishing',
                description='URL flagged as malicious',
                severity=RiskLevel.CRITICAL,
                score_impact=25,
                triggered=True,
                evidence=['URL detected by VirusTotal'],
            ),
            DetectionRule(
                rule_id='LOOK-002',
                rule_name='Typosquat Domain',
                category='lookalike',
                description='Domain similar to paypal.com',
                severity=RiskLevel.HIGH,
                score_impact=15,
                triggered=True,
                evidence=['paypa1.com similar to paypal.com'],
            ),
        ],
        rules_passed=[],
        risk_score=75,
        risk_level=RiskLevel.HIGH,
        confidence=0.85,
        primary_classification=EmailClassification.PHISHING,
        secondary_classifications=[EmailClassification.BRAND_IMPERSONATION],
        urgency_score=5,
        authority_score=3,
        fear_score=4,
        reward_score=0,
        impersonated_brand='PayPal',
        brand_confidence=0.9,
    )


class TestBaseProvider:
    """Tests for base AI provider."""
    
    def test_provider_interface(self):
        """Test that base provider defines required interface."""
        from app.services.ai.base import BaseAIProvider
        
        # Should be abstract
        import abc
        assert hasattr(BaseAIProvider, '__abstractmethods__')
        assert 'generate' in BaseAIProvider.__abstractmethods__
        assert 'test_connection' in BaseAIProvider.__abstractmethods__
    
    def test_json_parsing(self):
        """Test JSON response parsing."""
        from app.services.ai.base import BaseAIProvider
        
        class TestProvider(BaseAIProvider):
            async def generate(self, *args, **kwargs):
                pass
            async def test_connection(self):
                return True
        
        provider = TestProvider()
        
        # Test plain JSON
        result = provider._parse_json_response('{"key": "value"}')
        assert result == {'key': 'value'}
        
        # Test JSON in markdown
        result = provider._parse_json_response('```json\n{"key": "value"}\n```')
        assert result == {'key': 'value'}
        
        # Test JSON with extra text
        result = provider._parse_json_response('Here is the result: {"key": "value"} end')
        assert result == {'key': 'value'}


class TestAnthropicProvider:
    """Tests for Anthropic provider."""
    
    def test_provider_initialization(self):
        """Test provider initializes correctly."""
        from app.services.ai.anthropic_provider import AnthropicProvider
        
        provider = AnthropicProvider(api_key='test-key')
        
        assert provider.api_key == 'test-key'
        assert provider.is_configured()
        assert 'claude' in provider.model
    
    def test_not_configured_without_key(self):
        """Test provider reports not configured without key."""
        from app.services.ai.anthropic_provider import AnthropicProvider
        
        provider = AnthropicProvider()
        
        assert not provider.is_configured()
    
    def test_headers(self):
        """Test API headers are correct."""
        from app.services.ai.anthropic_provider import AnthropicProvider
        
        provider = AnthropicProvider(api_key='test-key')
        headers = provider._get_headers()
        
        assert 'x-api-key' in headers
        assert headers['x-api-key'] == 'test-key'
        assert 'anthropic-version' in headers


class TestOpenAIProvider:
    """Tests for OpenAI provider."""
    
    def test_provider_initialization(self):
        """Test provider initializes correctly."""
        from app.services.ai.openai_provider import OpenAIProvider
        
        provider = OpenAIProvider(api_key='test-key')
        
        assert provider.api_key == 'test-key'
        assert provider.is_configured()
        assert 'gpt' in provider.model
    
    def test_not_configured_without_key(self):
        """Test provider reports not configured without key."""
        from app.services.ai.openai_provider import OpenAIProvider
        
        provider = OpenAIProvider()
        
        assert not provider.is_configured()
    
    def test_headers(self):
        """Test API headers are correct."""
        from app.services.ai.openai_provider import OpenAIProvider
        
        provider = OpenAIProvider(api_key='test-key')
        headers = provider._get_headers()
        
        assert 'Authorization' in headers
        assert 'Bearer test-key' in headers['Authorization']


class TestPrompts:
    """Tests for prompt templates."""
    
    def test_system_prompt_exists(self):
        """Test system prompt is defined."""
        from app.services.ai.prompts import SYSTEM_PROMPT
        
        assert len(SYSTEM_PROMPT) > 100
        assert 'email' in SYSTEM_PROMPT.lower()
        assert 'security' in SYSTEM_PROMPT.lower()
    
    def test_output_schema_valid_json(self):
        """Test output schema is valid JSON."""
        import json
        from app.services.ai.prompts import OUTPUT_SCHEMA
        
        schema = json.loads(OUTPUT_SCHEMA)
        assert 'summary' in schema
        assert 'recommended_actions' in schema
    
    def test_build_analysis_prompt(self):
        """Test analysis prompt building."""
        from app.services.ai.prompts import build_analysis_prompt
        
        email_data = {
            'sender': {'email': 'test@example.com', 'display_name': 'Test'},
            'subject': 'Test Subject',
            'body_text': 'Test body',
            'urls': [],
            'attachments': [],
            'to_recipients': [],
        }
        
        prompt = build_analysis_prompt(email_data, {}, {})
        
        assert 'test@example.com' in prompt
        assert 'Test Subject' in prompt
        assert 'JSON' in prompt


class TestContext:
    """Tests for analysis context."""
    
    def test_context_creation(self):
        """Test context creation from components."""
        from app.services.ai.context import build_context
        
        email = create_test_email()
        enrichment = create_test_enrichment()
        detection = create_test_detection()
        
        context = build_context(email, enrichment, detection)
        
        assert context.email == email
        assert context.enrichment == enrichment
        assert context.detection == detection
    
    def test_email_dict_conversion(self):
        """Test email to dictionary conversion."""
        from app.services.ai.context import build_context
        
        email = create_test_email()
        context = build_context(email)
        
        email_dict = context.to_email_dict()
        
        assert 'sender' in email_dict
        assert email_dict['sender']['email'] == 'security@paypa1.com'
        assert email_dict['subject'] == 'Urgent: Verify Your Account'
    
    def test_enrichment_dict_conversion(self):
        """Test enrichment to dictionary conversion."""
        from app.services.ai.context import build_context
        
        email = create_test_email()
        enrichment = create_test_enrichment()
        context = build_context(email, enrichment)
        
        enrichment_dict = context.to_enrichment_dict()
        
        assert 'sender_domain' in enrichment_dict
        assert enrichment_dict['sender_domain']['domain'] == 'paypa1.com'
        assert enrichment_dict['sender_domain']['is_newly_registered'] == True
    
    def test_detection_dict_conversion(self):
        """Test detection to dictionary conversion."""
        from app.services.ai.context import build_context
        
        email = create_test_email()
        detection = create_test_detection()
        context = build_context(email, detection=detection)
        
        detection_dict = context.to_detection_dict()
        
        assert detection_dict['risk_score'] == 75
        assert detection_dict['primary_classification'] == 'phishing'
        assert len(detection_dict['rules_triggered']) == 2
    
    def test_summary_stats(self):
        """Test summary statistics generation."""
        from app.services.ai.context import build_context
        
        email = create_test_email()
        detection = create_test_detection()
        context = build_context(email, detection=detection)
        
        stats = context.get_summary_stats()
        
        assert stats['has_urls'] == True
        assert stats['url_count'] == 1
        assert stats['risk_score'] == 75


class TestAIAnalyzer:
    """Tests for AI analyzer."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        from app.services.ai.analyzer import AIAnalyzer
        
        analyzer = AIAnalyzer(
            anthropic_api_key='test-key',
            openai_api_key='test-key',
        )
        
        assert analyzer.is_configured()
        assert len(analyzer.get_configured_providers()) == 2
    
    def test_analyzer_not_configured(self):
        """Test analyzer reports not configured without keys."""
        from app.services.ai.analyzer import AIAnalyzer
        
        analyzer = AIAnalyzer()
        
        assert not analyzer.is_configured()
        assert len(analyzer.get_configured_providers()) == 0
    
    def test_get_provider(self):
        """Test getting provider by name."""
        from app.services.ai.analyzer import AIAnalyzer
        
        analyzer = AIAnalyzer(anthropic_api_key='test-key')
        
        provider = analyzer.get_provider('anthropic')
        assert provider is not None, "Anthropic provider should be returned"
        assert provider.provider_name == 'anthropic'
        
        # OpenAI not configured, should return None when specifically requested
        # But get_provider without args returns the first configured provider
        provider2 = analyzer.get_provider()
        assert provider2 is not None, "Should return preferred/available provider"
    
    def test_fallback_summary(self):
        """Test fallback summary generation without AI."""
        from app.services.ai.analyzer import AIAnalyzer
        from app.services.ai.context import build_context
        
        analyzer = AIAnalyzer()  # No API keys
        
        email = create_test_email()
        detection = create_test_detection()
        context = build_context(email, detection=detection)
        
        summary = analyzer._generate_fallback_summary(context)
        
        assert 'phishing' in summary.lower()
        assert '75' in summary
    
    def test_fallback_recommendations(self):
        """Test fallback recommendations without AI."""
        from app.services.ai.analyzer import AIAnalyzer
        from app.services.ai.context import build_context
        
        analyzer = AIAnalyzer()
        
        email = create_test_email()
        detection = create_test_detection()
        context = build_context(email, detection=detection)
        
        recommendations = analyzer._generate_fallback_recommendations(context)
        
        assert len(recommendations) > 0
        # High risk score should trigger block recommendation
        actions = [r.action.lower() for r in recommendations]
        assert any('block' in a for a in actions)
    
    def test_parse_recommendations(self):
        """Test parsing recommendations from AI response."""
        from app.services.ai.analyzer import AIAnalyzer
        
        analyzer = AIAnalyzer()
        
        response = """1. Block the sender domain immediately
2. Quarantine the email for investigation
3. Alert the user about the phishing attempt
4. Add URL to blocklist"""
        
        recommendations = analyzer._parse_recommendations(response)
        
        assert len(recommendations) == 4
        assert recommendations[0].priority == 1


class TestAIModuleImports:
    """Test that AI module imports work correctly."""
    
    def test_all_exports(self):
        """Test all module exports are accessible."""
        from app.services.ai import (
            BaseAIProvider,
            AIResponse,
            AnthropicProvider,
            OpenAIProvider,
            AnalysisContext,
            build_context,
            AIAnalyzer,
            init_ai_analyzer,
            get_ai_analyzer,
            SYSTEM_PROMPT,
            build_analysis_prompt,
        )
        
        assert BaseAIProvider is not None
        assert AIResponse is not None
        assert AnthropicProvider is not None
        assert OpenAIProvider is not None
        assert AnalysisContext is not None
        assert build_context is not None
        assert AIAnalyzer is not None


def run_tests():
    """Run all tests and report results."""
    test_classes = [
        TestBaseProvider,
        TestAnthropicProvider,
        TestOpenAIProvider,
        TestPrompts,
        TestContext,
        TestAIAnalyzer,
        TestAIModuleImports,
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
    print(f"Tests: {passed_tests}/{total_tests} passed")
    
    if failed_tests:
        print(f"\nFailed tests:")
        for name, error in failed_tests:
            print(f"  - {name}: {error}")
    
    return len(failed_tests) == 0


if __name__ == "__main__":
    print("NiksES Session 7 - AI Module Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
