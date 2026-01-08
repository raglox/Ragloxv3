# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Pytest Configuration
# Shared fixtures and configuration for tests
# ═══════════════════════════════════════════════════════════════

import pytest
import sys
import os
import secrets

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Configure pytest-asyncio
pytest_plugins = ['pytest_asyncio']


@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    """
    Configure test environment variables.
    This fixture runs automatically before all tests.
    """
    # Generate secure JWT secret (48 characters minimum for production-grade security)
    if not os.getenv("JWT_SECRET") or len(os.getenv("JWT_SECRET", "")) < 32:
        test_jwt_secret = secrets.token_urlsafe(48)
        os.environ["JWT_SECRET"] = test_jwt_secret
    
    # Set test database URL if not already set
    if not os.getenv("DATABASE_URL"):
        os.environ["DATABASE_URL"] = "postgresql://raglox:raglox_secure_2024@localhost:5432/raglox"
    
    # Set test Redis URL if not already set
    if not os.getenv("REDIS_URL"):
        os.environ["REDIS_URL"] = "redis://localhost:6379/0"
    
    # Set test OneProvider credentials if not set
    if not os.getenv("ONEPROVIDER_TOKEN"):
        os.environ["ONEPROVIDER_TOKEN"] = "test_token_" + secrets.token_hex(16)
    
    if not os.getenv("ONEPROVIDER_ENDPOINT"):
        os.environ["ONEPROVIDER_ENDPOINT"] = "https://api.oneprovider.example.com"
    
    # Set other test configurations
    os.environ["ENVIRONMENT"] = "test"
    os.environ["LOG_LEVEL"] = "WARNING"  # Reduce log noise during tests
    
    yield
    
    # Cleanup after all tests (if needed)
    pass


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()
