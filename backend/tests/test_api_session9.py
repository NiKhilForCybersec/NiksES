"""
NiksES Session 9 - API Tests

Tests for API routes and dependencies.
"""

import sys
sys.path.insert(0, '/home/claude/nikses/backend')

from datetime import datetime


class TestDependencies:
    """Tests for API dependencies."""
    
    def test_settings_initialization(self):
        """Test settings initialization."""
        from app.api.dependencies import Settings, init_settings
        
        settings = init_settings(
            virustotal_api_key="test-vt-key",
            ai_enabled=True,
        )
        
        assert settings.virustotal_api_key == "test-vt-key"
        assert settings.ai_enabled == True
    
    def test_settings_defaults(self):
        """Test settings defaults."""
        from app.api.dependencies import Settings
        
        settings = Settings()
        
        assert settings.enrichment_enabled == True
        assert settings.ai_enabled == False
        assert settings.ai_provider == "anthropic"
        assert settings.max_file_size_mb == 50
    
    def test_analysis_store(self):
        """Test in-memory analysis store."""
        import asyncio
        from app.api.dependencies import InMemoryAnalysisStore
        
        store = InMemoryAnalysisStore()
        
        # Create mock analysis
        class MockAnalysis:
            analysis_id = "test-123"
            analyzed_at = datetime.utcnow()
        
        async def run_test():
            analysis = MockAnalysis()
            
            await store.save(analysis)
            
            retrieved = await store.get("test-123")
            assert retrieved is not None
            assert retrieved.analysis_id == "test-123"
            
            deleted = await store.delete("test-123")
            assert deleted == True
            
            retrieved = await store.get("test-123")
            assert retrieved is None
        
        asyncio.run(run_test())


class TestExportModule:
    """Tests for export module."""
    
    def test_json_export(self):
        """Test JSON export."""
        import json
        from app.services.export.json_export import DateTimeEncoder
        
        data = {"date": datetime.utcnow()}
        result = json.dumps(data, cls=DateTimeEncoder)
        
        assert "T" in result  # ISO format
    
    def test_stix_bundle(self):
        """Test STIX bundle creation."""
        from app.services.export.stix_export import create_stix_bundle, create_indicator
        
        indicator = create_indicator(
            pattern="[domain-name:value = 'evil.com']",
            pattern_type="stix",
            name="Test Indicator",
            description="Test",
            labels=["malicious"],
            valid_from=datetime.utcnow(),
        )
        
        bundle = create_stix_bundle([indicator])
        
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0]["type"] == "indicator"
    
    def test_markdown_export(self):
        """Test markdown generation."""
        from app.services.export.markdown_export import get_risk_emoji
        from app.models.detection import RiskLevel
        
        assert get_risk_emoji(RiskLevel.CRITICAL) == "🔴"
        assert get_risk_emoji(RiskLevel.HIGH) == "🟠"
        assert get_risk_emoji(RiskLevel.LOW) == "🟢"


class TestRouteModules:
    """Tests for route module imports."""
    
    def test_analyze_route_imports(self):
        """Test analyze route imports."""
        from app.api.routes.analyze import router
        assert router is not None
    
    def test_analyses_route_imports(self):
        """Test analyses route imports."""
        from app.api.routes.analyses import router
        assert router is not None
    
    def test_export_route_imports(self):
        """Test export route imports."""
        from app.api.routes.export import router
        assert router is not None
    
    def test_health_route_imports(self):
        """Test health route imports."""
        from app.api.routes.health import router
        assert router is not None
    
    def test_settings_route_imports(self):
        """Test settings route imports."""
        from app.api.routes.settings import router
        assert router is not None
    
    def test_api_router_creation(self):
        """Test main API router creation."""
        from app.api.routes import get_api_router
        
        router = get_api_router()
        assert router is not None
        assert len(router.routes) > 0


class TestMainApp:
    """Tests for main application."""
    
    def test_app_creation(self):
        """Test FastAPI app creation."""
        from app.main import app
        
        assert app is not None
        assert app.title == "NiksES API"
        assert app.version == "1.0.0"
    
    def test_app_routes(self):
        """Test that all routes are registered."""
        from app.main import app
        
        routes = [r.path for r in app.routes]
        
        # Check key routes exist
        assert "/" in routes
        assert "/docs" in routes or "/docs/" in routes


def run_tests():
    """Run all tests and report results."""
    test_classes = [
        TestDependencies,
        TestExportModule,
        TestRouteModules,
        TestMainApp,
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
    print("NiksES Session 8-9 - API & Export Tests")
    print("=" * 60)
    success = run_tests()
    exit(0 if success else 1)
