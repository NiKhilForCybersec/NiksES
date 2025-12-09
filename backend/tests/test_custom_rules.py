"""
NiksES Custom Rules Tests
"""

import sys
sys.path.insert(0, '/home/claude/nikses/backend')


def make_email_address(email_str: str):
    """Helper to create EmailAddress with all required fields."""
    from app.models.email import EmailAddress
    parts = email_str.split('@')
    return EmailAddress(
        raw=email_str,
        email=email_str,
        domain=parts[1] if len(parts) > 1 else "",
        local_part=parts[0],
    )


class TestCustomRuleEngine:
    """Tests for custom rule engine."""
    
    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        from app.services.detection.custom_rules import get_custom_rule_engine
        
        engine = get_custom_rule_engine()
        assert engine is not None
        
        rules = engine.list_rules()
        assert len(rules) >= 0
    
    def test_create_rule(self):
        """Test creating a custom rule."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Test Rule",
            description="A test rule",
            category="test",
            severity=RiskLevel.MEDIUM,
            conditions=[
                {"field": "subject", "match_type": "contains", "value": "test"}
            ],
        )
        
        assert rule.rule_id.startswith("CUSTOM-")
        assert rule.name == "Test Rule"
        assert rule.enabled == True
    
    def test_toggle_rule(self):
        """Test enabling/disabling a rule."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Toggle Test",
            description="Test",
            category="test",
            severity=RiskLevel.LOW,
            conditions=[
                {"field": "body", "match_type": "contains", "value": "test"}
            ],
        )
        
        assert rule.enabled == True
        
        engine.toggle_rule(rule.rule_id, False)
        updated = engine.get_rule(rule.rule_id)
        assert updated.enabled == False
    
    def test_delete_rule(self):
        """Test deleting a rule."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Delete Test",
            description="Test",
            category="test",
            severity=RiskLevel.LOW,
            conditions=[
                {"field": "subject", "match_type": "equals", "value": "delete me"}
            ],
        )
        
        assert engine.delete_rule(rule.rule_id) == True
        assert engine.get_rule(rule.rule_id) is None
    
    def test_rule_evaluation(self):
        """Test evaluating a rule against an email."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        from app.models.email import ParsedEmail
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Urgency Test",
            description="Detects urgent emails",
            category="social_engineering",
            severity=RiskLevel.MEDIUM,
            conditions=[
                {"field": "subject", "match_type": "contains", "value": "urgent"}
            ],
        )
        
        # Email that should trigger
        email = ParsedEmail(
            message_id="test-1",
            subject="URGENT: Please respond immediately",
            body_text="This is urgent",
            sender=make_email_address("test@example.com"),
        )
        
        match = engine.evaluate_rule(rule, email)
        assert match is not None
        assert match.rule_id == rule.rule_id
        
        # Email that should NOT trigger
        email2 = ParsedEmail(
            message_id="test-2",
            subject="Hello there",
            body_text="Normal email",
            sender=make_email_address("test@example.com"),
        )
        
        match2 = engine.evaluate_rule(rule, email2)
        assert match2 is None
    
    def test_regex_matching(self):
        """Test regex matching in conditions."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        from app.models.email import ParsedEmail
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Phone Number Detection",
            description="Detects phone numbers",
            category="custom",
            severity=RiskLevel.LOW,
            conditions=[
                {"field": "body", "match_type": "regex", "value": r"\d{3}-\d{3}-\d{4}"}
            ],
        )
        
        email = ParsedEmail(
            message_id="test",
            subject="Contact",
            body_text="Call me at 555-123-4567",
            sender=make_email_address("test@example.com"),
        )
        
        match = engine.evaluate_rule(rule, email)
        assert match is not None
    
    def test_or_logic(self):
        """Test OR logic for conditions."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        from app.models.email import ParsedEmail
        
        engine = CustomRuleEngine()
        
        rule = engine.create_rule(
            name="Payment Keywords",
            description="Detects payment-related keywords",
            category="bec",
            severity=RiskLevel.HIGH,
            conditions=[
                {"field": "subject", "match_type": "contains", "value": "wire transfer"},
                {"field": "subject", "match_type": "contains", "value": "bitcoin"},
            ],
            logic="OR",
        )
        
        email = ParsedEmail(
            message_id="test",
            subject="Please send bitcoin",
            body_text="Payment needed",
            sender=make_email_address("test@example.com"),
        )
        
        match = engine.evaluate_rule(rule, email)
        assert match is not None
    
    def test_export_import(self):
        """Test exporting and importing rules."""
        from app.services.detection.custom_rules import CustomRuleEngine
        from app.models.detection import RiskLevel
        
        engine = CustomRuleEngine()
        
        engine.create_rule(
            name="Export Test",
            description="Test",
            category="test",
            severity=RiskLevel.LOW,
            conditions=[
                {"field": "subject", "match_type": "contains", "value": "export"}
            ],
        )
        
        json_export = engine.export_rules()
        assert "Export Test" in json_export
        
        engine2 = CustomRuleEngine()
        count = engine2.import_rules(json_export)
        assert count >= 1


class TestCustomRulesAPI:
    """Tests for custom rules API routes."""
    
    def test_rules_router_import(self):
        """Test that rules router imports correctly."""
        from app.api.routes.rules import router
        assert router is not None
    
    def test_rule_create_model(self):
        """Test rule create model validation."""
        from app.api.routes.rules import RuleCreate, ConditionCreate
        
        condition = ConditionCreate(
            field="subject",
            match_type="contains",
            value="test",
            case_sensitive=False,
        )
        
        rule = RuleCreate(
            name="Test Rule",
            description="A test description",
            category="custom",
            severity="medium",
            conditions=[condition],
            logic="AND",
        )
        
        assert rule.name == "Test Rule"
        assert len(rule.conditions) == 1


def run_tests():
    """Run all tests."""
    test_classes = [
        TestCustomRuleEngine,
        TestCustomRulesAPI,
    ]
    
    total = 0
    passed = 0
    failed = []
    
    for test_class in test_classes:
        print(f"\n{test_class.__name__}:")
        instance = test_class()
        
        for method_name in [m for m in dir(instance) if m.startswith('test_')]:
            total += 1
            try:
                getattr(instance, method_name)()
                passed += 1
                print(f"  ✓ {method_name}")
            except Exception as e:
                failed.append((f"{test_class.__name__}.{method_name}", str(e)))
                print(f"  ✗ {method_name}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Tests: {passed}/{total} passed")
    
    return len(failed) == 0


if __name__ == "__main__":
    print("NiksES Custom Rules Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
