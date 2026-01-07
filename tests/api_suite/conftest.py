"""
Pytest configuration and shared fixtures for the RAGLOX API test suite.
"""

import pytest
import httpx
import uuid
from typing import Dict, Any, Generator


@pytest.fixture(scope="session")
def base_url() -> str:
    """Base URL for the API."""
    return "http://localhost:8000"


@pytest.fixture(scope="session")
def client(base_url: str) -> Generator[httpx.Client, None, None]:
    """HTTP client for making API requests."""
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        yield client


@pytest.fixture(scope="session")
def auth_token(client: httpx.Client) -> str:
    """
    Authenticate and return access token.
    Registers or logs in a test user and returns the JWT token.
    """
    test_user = {
        "email": "test@raglox.com",
        "password": "TestPassword123!",
        "full_name": "Test User"
    }
    
    # Try to register
    register_response = client.post("/api/v1/auth/register", json=test_user)
    
    if register_response.status_code == 409:  # User already exists
        # Login instead
        login_data = {
            "email": test_user["email"],
            "password": test_user["password"]
        }
        login_response = client.post("/api/v1/auth/login", json=login_data)
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        token = login_response.json()["access_token"]
    elif register_response.status_code == 201:
        # Registration successful
        token = register_response.json()["access_token"]
    else:
        raise AssertionError(f"Authentication failed: {register_response.status_code} - {register_response.text}")
    
    return token


@pytest.fixture(scope="session")
def auth_headers(auth_token: str) -> Dict[str, str]:
    """Return authorization headers with Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def authenticated_client(client: httpx.Client, auth_headers: Dict[str, str]) -> httpx.Client:
    """
    HTTP client with authentication headers.
    Use this fixture instead of 'client' for authenticated requests.
    """
    # Create a new client with auth headers
    authenticated = httpx.Client(
        base_url=client.base_url,
        timeout=client.timeout,
        headers=auth_headers
    )
    yield authenticated
    authenticated.close()


@pytest.fixture
def mission_id() -> str:
    """Sample mission ID for testing."""
    return str(uuid.uuid4())


@pytest.fixture
def target_id() -> str:
    """Sample target ID for testing."""
    return str(uuid.uuid4())


@pytest.fixture
def action_id() -> str:
    """Sample action ID for testing."""
    return str(uuid.uuid4())


@pytest.fixture
def technique_id() -> str:
    """Sample technique ID for testing."""
    return "T1003"


@pytest.fixture
def module_id() -> str:
    """Sample module ID for testing."""
    return "rx-t1003-001"


@pytest.fixture
def template_id() -> str:
    """Sample template ID for testing."""
    return "CVE-2021-44228"


@pytest.fixture
def cve_id() -> str:
    """Sample CVE ID for testing."""
    return "CVE-2021-44228"


@pytest.fixture
def tactic_id() -> str:
    """Sample tactic ID for testing."""
    return "TA0001"


@pytest.fixture
def sample_mission_create() -> Dict[str, Any]:
    """Sample mission creation payload."""
    return {
        "name": "Test Mission",
        "description": "A test mission for automated testing",
        "scope": ["192.168.1.0/24", "10.0.0.1"],
        "goals": ["domain_admin", "data_exfil"],
        "constraints": {"stealth": True}
    }


@pytest.fixture
def sample_mission_create_minimal() -> Dict[str, Any]:
    """Minimal mission creation payload."""
    return {
        "name": "Minimal Test Mission",
        "scope": ["192.168.1.0/24"],
        "goals": ["reconnaissance"]
    }


@pytest.fixture
def sample_chat_request() -> Dict[str, Any]:
    """Sample chat request payload."""
    return {
        "content": "Status report",
        "related_task_id": None,
        "related_action_id": None
    }


@pytest.fixture
def sample_approval_request() -> Dict[str, Any]:
    """Sample approval request payload."""
    return {
        "user_comment": "Approved for testing"
    }


@pytest.fixture
def sample_rejection_request() -> Dict[str, Any]:
    """Sample rejection request payload."""
    return {
        "rejection_reason": "Test rejection",
        "user_comment": "Rejected for testing purposes"
    }


@pytest.fixture
def sample_search_request() -> Dict[str, Any]:
    """Sample search request payload."""
    return {
        "query": "credential",
        "platform": "windows",
        "tactic": "TA0006",
        "limit": 20
    }


@pytest.fixture
def sample_task_module_request() -> Dict[str, Any]:
    """Sample task module request payload."""
    return {
        "tactic": "TA0006",
        "technique": "T1003",
        "platform": "windows",
        "executor_type": "powershell",
        "require_elevation": True
    }


@pytest.fixture
def created_mission(authenticated_client: httpx.Client, sample_mission_create: Dict[str, Any]) -> Dict[str, Any]:
    """Create a mission for testing and return its details."""
    response = authenticated_client.post("/api/v1/missions", json=sample_mission_create)
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def running_mission(authenticated_client: httpx.Client, created_mission: Dict[str, Any]) -> Dict[str, Any]:
    """Start a created mission and return its details."""
    mission_id = created_mission["mission_id"]
    response = authenticated_client.post(f"/api/v1/missions/{mission_id}/start")
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def paused_mission(authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> Dict[str, Any]:
    """Pause a running mission and return its details."""
    mission_id = running_mission["mission_id"]
    response = authenticated_client.post(f"/api/v1/missions/{mission_id}/pause")
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def stopped_mission(authenticated_client: httpx.Client, running_mission: Dict[str, Any]) -> Dict[str, Any]:
    """Stop a running mission and return its details."""
    mission_id = running_mission["mission_id"]
    response = authenticated_client.post(f"/api/v1/missions/{mission_id}/stop")
    assert response.status_code == 200
    return response.json()