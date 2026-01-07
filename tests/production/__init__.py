"""
Production Testing Suite for RAGLOX V3

This package contains production-like tests that use real infrastructure:
- Real PostgreSQL database
- Real Redis blackboard
- Real API endpoints
- Real LLM integration
- Real test targets

Test Categories:
- Integration Tests: Test component interactions with real services
- E2E Tests: Test complete workflows end-to-end
- Performance Tests: Test system performance under load
- Security Tests: Test security measures and protections
- Chaos Tests: Test system resilience and recovery

Usage:
    # Run all production tests
    pytest tests/production/ -m production

    # Run only integration tests
    pytest tests/production/ -m "production and integration"

    # Run E2E tests
    pytest tests/production/ -m "production and e2e"

Requirements:
    - Docker and Docker Compose installed
    - Test infrastructure running (docker-compose.test-production.yml)
    - Environment variables configured (.env.test)
    - Test targets accessible
"""

__version__ = "1.0.0"
__author__ = "RAGLOX Team"

from .config import ProductionTestConfig, get_config, reload_config

__all__ = [
    "ProductionTestConfig",
    "get_config",
    "reload_config",
]
