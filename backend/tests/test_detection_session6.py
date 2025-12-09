"""
NiksES Session 6 - Detection Module Tests

Tests for detection rules and engine.
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
    HeaderAnalysis,
)
from app.models.enrichment import (
    EnrichmentResults,
    DomainEnrichment,
    URLEnrichment,
    ThreatIntelVerdict,
)
from app.models.detection import RiskLevel, EmailClassification


def create_test_email(**kwargs):
    """Create a test email with default values."""
    defaults = {
        'subject': 'Test Email',
        'body_text': 'This is a test email.',
        'sender': EmailAddress(
            raw='sender@example.com',
            email='sender@example.com',
            domain='example.com',
            local_part='sender',
        ),
        'to_recipients': [
            EmailAddress(
                raw='recipient@company.com',
                email='recipient@company.com',
                domain='company.com',
                local_part='recipient',
            )
        ],
        'urls': [],
        'attachments': [],
        'qr_codes': [],
        'phone_numbers': [],
        'reply_to': [],
    }
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


class TestRuleBase:
    """Tests for detection rule base class."""
    
    def test_rule_registry(self):
        """Test that rules are registered."""
        from app.services.detection.rules import rule_registry
        
        rules = rule_registry.get_all_rules()
        assert len(rules) > 0
        print(f"  Total rules registered: {len(rules)}")
    
    def test_rule_categories(self):
        """Test rule category organization."""
        from app.services.detection.rules import rule_registry
        
        expected_categories = ['authentication', 'phishing', 'malware', 'bec', 'lookalike', 'social_engineering']
        
        for category in expected_categories:
            rules = rule_registry.get_rules_by_category(category)
            assert len(rules) > 0, f"No rules in category: {category}"
            print(f"  Category '{category}': {len(rules)} rules")
    
    def test_severity_scores(self):
        """Test severity score mapping."""
        from app.services.detection.rules.base import SEVERITY_SCORES
        
        assert SEVERITY_SCORES[RiskLevel.CRITICAL] == 25
        assert SEVERITY_SCORES[RiskLevel.HIGH] == 15
        assert SEVERITY_SCORES[RiskLevel.MEDIUM] == 10
        assert SEVERITY_SCORES[RiskLevel.LOW] == 5
        assert SEVERITY_SCORES[RiskLevel.INFORMATIONAL] == 2


class TestAuthenticationRules:
    """Tests for authentication rules."""
    
    def test_spf_fail_rule(self):
        """Test SPF failure detection."""
        async def run():
            from app.services.detection.rules.authentication import SPFFailRule
            
            rule = SPFFailRule()
            
            # Email with SPF fail
            email = create_test_email(
                spf_result=AuthenticationResult(
                    mechanism='spf',
                    result='fail',
                    domain='example.com',
                )
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert 'SPF result: fail' in match.evidence[0]
        
        asyncio.run(run())
    
    def test_reply_to_mismatch_rule(self):
        """Test Reply-To mismatch detection."""
        async def run():
            from app.services.detection.rules.authentication import ReplyToMismatchRule
            
            rule = ReplyToMismatchRule()
            
            # Email with mismatched reply-to
            email = create_test_email(
                sender=EmailAddress(
                    raw='sender@company.com',
                    email='sender@company.com',
                    domain='company.com',
                    local_part='sender',
                ),
                reply_to=[
                    EmailAddress(
                        raw='attacker@evil.com',
                        email='attacker@evil.com',
                        domain='evil.com',
                        local_part='attacker',
                    )
                ]
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert 'evil.com' in str(match.evidence)
        
        asyncio.run(run())


class TestPhishingRules:
    """Tests for phishing detection rules."""
    
    def test_phishing_keywords_rule(self):
        """Test phishing keyword detection."""
        async def run():
            from app.services.detection.rules.phishing import PhishingKeywordsRule
            
            rule = PhishingKeywordsRule()
            
            email = create_test_email(
                subject='Urgent: Verify your account immediately',
                body_text='Your account has been compromised. Verify within 24 hours or it will be suspended.',
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert len(match.indicators) > 0
        
        asyncio.run(run())
    
    def test_shortened_url_rule(self):
        """Test URL shortener detection."""
        async def run():
            from app.services.detection.rules.phishing import URLShortenerRule
            
            rule = URLShortenerRule()
            
            email = create_test_email(
                urls=[
                    ExtractedURL(
                        url='https://bit.ly/abc123',
                        normalized_url='https://bit.ly/abc123',
                        domain='bit.ly',
                        scheme='https',
                        source='body_text',
                        is_shortened=True,
                    )
                ]
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())
    
    def test_malicious_url_rule(self):
        """Test malicious URL detection with enrichment."""
        async def run():
            from app.services.detection.rules.phishing import MaliciousURLRule
            
            rule = MaliciousURLRule()
            
            email = create_test_email(
                urls=[
                    ExtractedURL(
                        url='https://evil.com/phish',
                        normalized_url='https://evil.com/phish',
                        domain='evil.com',
                        scheme='https',
                        source='body_text',
                        is_shortened=False,
                    )
                ]
            )
            
            enrichment = EnrichmentResults(
                urls=[
                    URLEnrichment(
                        url='https://evil.com/phish',
                        domain='evil.com',
                        final_verdict=ThreatIntelVerdict.MALICIOUS,
                        virustotal_positives=10,
                        virustotal_total=70,
                    )
                ]
            )
            
            match = await rule.evaluate(email, enrichment)
            assert match is not None
            assert match.severity == RiskLevel.CRITICAL
        
        asyncio.run(run())


class TestMalwareRules:
    """Tests for malware detection rules."""
    
    def test_executable_attachment_rule(self):
        """Test executable attachment detection."""
        async def run():
            from app.services.detection.rules.malware import ExecutableAttachmentRule
            
            rule = ExecutableAttachmentRule()
            
            email = create_test_email(
                attachments=[
                    AttachmentInfo(
                        filename='invoice.exe',
                        content_type='application/x-msdownload',
                        size_bytes=1024,
                        md5='a' * 32,
                        sha256='b' * 64,
                        is_executable=True,
                        extension='.exe',
                    )
                ]
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert match.severity == RiskLevel.HIGH
        
        asyncio.run(run())
    
    def test_double_extension_rule(self):
        """Test double extension detection."""
        async def run():
            from app.services.detection.rules.malware import DoubleExtensionRule
            
            rule = DoubleExtensionRule()
            
            email = create_test_email(
                attachments=[
                    AttachmentInfo(
                        filename='invoice.pdf.exe',
                        content_type='application/x-msdownload',
                        size_bytes=1024,
                        md5='a' * 32,
                        sha256='b' * 64,
                        is_executable=True,
                        extension='.exe',
                    )
                ]
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert match.severity == RiskLevel.CRITICAL
        
        asyncio.run(run())
    
    def test_macro_enabled_rule(self):
        """Test macro-enabled Office detection."""
        async def run():
            from app.services.detection.rules.malware import MacroEnabledOfficeRule
            
            rule = MacroEnabledOfficeRule()
            
            email = create_test_email(
                attachments=[
                    AttachmentInfo(
                        filename='document.docm',
                        content_type='application/vnd.ms-word.document.macroEnabled.12',
                        size_bytes=50000,
                        md5='a' * 32,
                        sha256='b' * 64,
                        is_office_with_macros=True,
                        extension='.docm',
                    )
                ]
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())


class TestBECRules:
    """Tests for BEC detection rules."""
    
    def test_executive_impersonation_rule(self):
        """Test executive impersonation detection."""
        async def run():
            from app.services.detection.rules.bec import ExecutiveImpersonationRule
            
            rule = ExecutiveImpersonationRule()
            
            email = create_test_email(
                sender=EmailAddress(
                    raw='John Smith CEO <john.smith.ceo@gmail.com>',
                    email='john.smith.ceo@gmail.com',
                    display_name='John Smith CEO',
                    domain='gmail.com',
                    local_part='john.smith.ceo',
                )
            )
            
            match = await rule.evaluate(email)
            assert match is not None
            assert match.severity == RiskLevel.CRITICAL
        
        asyncio.run(run())
    
    def test_wire_transfer_rule(self):
        """Test wire transfer request detection."""
        async def run():
            from app.services.detection.rules.bec import WireTransferRequestRule
            
            rule = WireTransferRequestRule()
            
            email = create_test_email(
                body_text='Please process this wire transfer immediately. The new bank account details are attached. Send the payment today.',
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())
    
    def test_gift_card_rule(self):
        """Test gift card scam detection."""
        async def run():
            from app.services.detection.rules.bec import GiftCardScamRule
            
            rule = GiftCardScamRule()
            
            email = create_test_email(
                body_text='I need you to purchase some iTunes gift cards for a client. Get 5 cards and send the codes.',
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())


class TestLookalikeRules:
    """Tests for lookalike domain detection rules."""
    
    def test_subdomain_spoof_rule(self):
        """Test subdomain spoofing detection."""
        async def run():
            from app.services.detection.rules.lookalike import SubdomainSpoofRule
            
            rule = SubdomainSpoofRule()
            
            email = create_test_email(
                sender=EmailAddress(
                    raw='support@microsoft.evil.com',
                    email='support@microsoft.evil.com',
                    domain='microsoft.evil.com',
                    local_part='support',
                )
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())


class TestSocialEngineeringRules:
    """Tests for social engineering detection rules."""
    
    def test_urgency_rule(self):
        """Test urgency tactic detection."""
        async def run():
            from app.services.detection.rules.social_engineering import UrgencyRule
            
            rule = UrgencyRule()
            
            email = create_test_email(
                body_text='This requires immediate action. Your account expires today. Act now or face termination.',
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())
    
    def test_fear_rule(self):
        """Test fear tactic detection."""
        async def run():
            from app.services.detection.rules.social_engineering import FearRule
            
            rule = FearRule()
            
            email = create_test_email(
                body_text='Your account will be closed. We detected unauthorized access. Legal action may follow.',
            )
            
            match = await rule.evaluate(email)
            assert match is not None
        
        asyncio.run(run())


class TestRiskScorer:
    """Tests for risk scoring."""
    
    def test_score_calculation(self):
        """Test score calculation from matches."""
        from app.services.detection.scorer import RiskScorer
        from app.services.detection.rules.base import RuleMatch
        
        scorer = RiskScorer()
        
        matches = [
            RuleMatch(
                rule_id='TEST-001',
                rule_name='Test Rule 1',
                category='test',
                severity=RiskLevel.HIGH,
                description='Test',
                evidence=['test'],
            ),
            RuleMatch(
                rule_id='TEST-002',
                rule_name='Test Rule 2',
                category='test',
                severity=RiskLevel.MEDIUM,
                description='Test',
                evidence=['test'],
            ),
        ]
        
        score = scorer.calculate_score(matches)
        assert score == 25  # HIGH(15) + MEDIUM(10)
    
    def test_risk_level_thresholds(self):
        """Test risk level determination."""
        from app.services.detection.scorer import RiskScorer
        
        scorer = RiskScorer()
        
        assert scorer.get_risk_level(10) == RiskLevel.INFORMATIONAL
        assert scorer.get_risk_level(30) == RiskLevel.LOW
        assert scorer.get_risk_level(50) == RiskLevel.MEDIUM
        assert scorer.get_risk_level(70) == RiskLevel.HIGH
        assert scorer.get_risk_level(90) == RiskLevel.CRITICAL
    
    def test_verdict_determination(self):
        """Test verdict from score."""
        from app.services.detection.scorer import RiskScorer
        
        scorer = RiskScorer()
        
        assert scorer.get_verdict(10) == 'clean'
        assert scorer.get_verdict(40) == 'suspicious'
        assert scorer.get_verdict(70) == 'malicious'


class TestDetectionEngine:
    """Tests for detection engine."""
    
    def test_engine_initialization(self):
        """Test engine initializes with rules."""
        from app.services.detection.engine import DetectionEngine
        
        engine = DetectionEngine()
        
        assert len(engine.rules) > 0
        print(f"  Engine loaded {len(engine.rules)} rules")
    
    def test_rule_summary(self):
        """Test rule summary generation."""
        from app.services.detection.engine import DetectionEngine
        
        engine = DetectionEngine()
        summary = engine.get_rule_summary()
        
        assert summary['total_rules'] > 0
        assert len(summary['by_category']) > 0
        print(f"  Rule summary: {summary}")
    
    def test_full_analysis(self):
        """Test full email analysis."""
        async def run():
            from app.services.detection.engine import DetectionEngine
            
            engine = DetectionEngine()
            
            # Create suspicious email
            email = create_test_email(
                sender=EmailAddress(
                    raw='CEO John <ceo@gmail.com>',
                    email='ceo@gmail.com',
                    display_name='CEO John',
                    domain='gmail.com',
                    local_part='ceo',
                ),
                subject='URGENT: Wire Transfer Needed',
                body_text='I need you to process a wire transfer immediately. This is urgent and confidential. Send payment to new bank account.',
                reply_to=[
                    EmailAddress(
                        raw='attacker@evil.com',
                        email='attacker@evil.com',
                        domain='evil.com',
                        local_part='attacker',
                    )
                ],
            )
            
            results = await engine.analyze(email)
            
            assert results.risk_score > 0
            assert len(results.rules_triggered) > 0
            print(f"  Analysis result: score={results.risk_score}, triggered={len(results.rules_triggered)}")
        
        asyncio.run(run())
    
    def test_clean_email(self):
        """Test analysis of clean email."""
        async def run():
            from app.services.detection.engine import DetectionEngine
            
            engine = DetectionEngine()
            
            # Create clean email
            email = create_test_email(
                subject='Meeting Tomorrow',
                body_text='Hi, just wanted to confirm our meeting tomorrow at 2pm. Best regards.',
            )
            
            results = await engine.analyze(email)
            
            # Should have low score
            assert results.risk_score < 20
            print(f"  Clean email score: {results.risk_score}")
        
        asyncio.run(run())


def run_tests():
    """Run all tests and report results."""
    test_classes = [
        TestRuleBase,
        TestAuthenticationRules,
        TestPhishingRules,
        TestMalwareRules,
        TestBECRules,
        TestLookalikeRules,
        TestSocialEngineeringRules,
        TestRiskScorer,
        TestDetectionEngine,
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
    print("NiksES Session 6 - Detection Module Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
