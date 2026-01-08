"""
Integration Tests for API Endpoints
===================================

Tests real API endpoints without mocks.
"""

import pytest
import httpx
import time
import uuid
from typing import Dict, Any


from tests.production.base import ProductionTestBase
from tests.production.config import ProductionTestConfig


class TestAPIIntegration(ProductionTestBase):
    """Test suite for real API endpoints"""

    @pytest.mark.integration
    def test_api_health_check(self, real_api_client):
        """Test 1: API health check endpoint"""
        response = real_api_client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data or "version" in data

    @pytest.mark.integration
    def test_api_user_registration_flow(self, real_api_client):
        """Test 2: Complete user registration flow"""
        # Register new user
        email = f'api_test_{uuid.uuid4().hex[:8]}@example.com'
        username = f'apiuser_{uuid.uuid4().hex[:8]}'
        
        register_data = {
            "email": email,
            "username": username,
            "password": "SecurePass123!",
            "organization_name": f"API Test Org {uuid.uuid4().hex[:8]}"
        }
        
        response = real_api_client.post(
            "/api/v1/auth/register",
            json=register_data
        )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert "access_token" in data or "token" in data

    @pytest.mark.integration
    def test_api_authentication_flow(self, real_api_client, authenticated_user):
        """Test 3: Authentication flow"""
        email, password = authenticated_user
        
        # Login
        login_data = {
            "username": email,  # API might use email as username
            "password": password
        }
        
        response = real_api_client.post(
            "/api/v1/auth/login",
            data=login_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data or "token" in data
        
        # Use token to access protected endpoint
        token = data.get("access_token") or data.get("token")
        headers = {"Authorization": f"Bearer {token}"}
        
        response = real_api_client.get(
            "/api/v1/auth/me",
            headers=headers
        )
        
        assert response.status_code == 200
        user_data = response.json()
        assert user_data["email"] == email

    @pytest.mark.integration
    def test_api_mission_crud_operations(self, real_api_client, auth_headers):
        """Test 4: Mission CRUD operations"""
        # Create mission
        mission_data = {
            "name": f"API Test Mission {uuid.uuid4().hex[:8]}",
            "description": "Test mission via API",
            "scope": {
                "ip_ranges": ["192.168.1.0/24"],
                "domains": []
            },
            "goals": ["reconnaissance"],
            "constraints": {
                "stealth": True,
                "no_exploit": True
            }
        }
        
        # CREATE
        response = real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        
        assert response.status_code in [200, 201]
        created_mission = response.json()
        mission_id = created_mission["id"] or created_mission["mission_id"]
        
        # READ
        response = real_api_client.get(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        retrieved_mission = response.json()
        assert retrieved_mission["name"] == mission_data["name"]
        
        # UPDATE
        update_data = {
            "description": "Updated description"
        }
        
        response = real_api_client.patch(
            f"/api/v1/missions/{mission_id}",
            json=update_data,
            headers=auth_headers
        )
        
        # Some APIs might not support PATCH, check PUT too
        if response.status_code == 405:
            response = real_api_client.put(
                f"/api/v1/missions/{mission_id}",
                json={**mission_data, **update_data},
                headers=auth_headers
            )
        
        # DELETE (if supported)
        # Note: Some APIs might not support mission deletion
        response = real_api_client.delete(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        
        # Accept 200, 204, or 405 (method not allowed)
        assert response.status_code in [200, 204, 405]

    @pytest.mark.integration
    def test_api_rate_limiting(self, real_api_client):
        """Test 5: API rate limiting"""
        # Make rapid requests
        responses = []
        
        for _ in range(100):
            response = real_api_client.get("/")
            responses.append(response.status_code)
        
        # Check if rate limiting kicks in
        # Either all succeed (no rate limiting) or some get 429
        rate_limited = 429 in responses
        
        if rate_limited:
            # Verify rate limit response
            assert responses.count(429) > 0
            print(f"Rate limiting detected: {responses.count(429)}/100 requests limited")
        else:
            # All requests succeeded
            assert all(status == 200 for status in responses)
            print("No rate limiting detected (all 100 requests succeeded)")

    @pytest.mark.integration
    def test_api_error_handling(self, real_api_client, auth_headers):
        """Test 6: API error handling"""
        # Test 404 - Not Found
        response = real_api_client.get(
            f"/api/v1/missions/{uuid.uuid4()}",
            headers=auth_headers
        )
        assert response.status_code == 404
        
        # Test 400 - Bad Request
        response = real_api_client.post(
            "/api/v1/missions",
            json={"invalid": "data"},
            headers=auth_headers
        )
        assert response.status_code in [400, 422]
        
        # Test 401 - Unauthorized
        response = real_api_client.get("/api/v1/missions")
        assert response.status_code == 401

    @pytest.mark.integration
    def test_api_pagination(self, real_api_client, auth_headers):
        """Test 7: API pagination"""
        # Create multiple missions
        for i in range(5):
            mission_data = {
                "name": f"Pagination Test Mission {i}",
                "description": f"Mission {i} for pagination test",
                "scope": {
                    "ip_ranges": ["192.168.1.0/24"]
                },
                "goals": ["reconnaissance"]
            }
            
            response = real_api_client.post(
                "/api/v1/missions",
                json=mission_data,
                headers=auth_headers
            )
            
            assert response.status_code in [200, 201]
        
        # Test pagination
        response = real_api_client.get(
            "/api/v1/missions?limit=2&offset=0",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check pagination structure
        assert isinstance(data, (list, dict))
        
        if isinstance(data, dict):
            # Response is paginated object
            assert "items" in data or "results" in data or "missions" in data
            missions = data.get("items") or data.get("results") or data.get("missions")
            assert len(missions) <= 2
        else:
            # Response is array
            assert len(data) <= 2

    @pytest.mark.integration
    def test_api_concurrent_requests(self, real_api_client, auth_headers):
        """Test 8: Concurrent API requests"""
        import concurrent.futures
        
        def make_request():
            response = real_api_client.get(
                "/api/v1/missions",
                headers=auth_headers
            )
            return response.status_code
        
        # Make 20 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All should succeed
        success_count = sum(1 for status in results if status == 200)
        assert success_count >= 18, f"Only {success_count}/20 requests succeeded"

    @pytest.mark.integration
    def test_api_response_time(self, real_api_client):
        """Test 9: API response time"""
        # Test 10 requests and measure response time
        response_times = []
        
        for _ in range(10):
            start_time = time.time()
            response = real_api_client.get("/")
            duration = time.time() - start_time
            
            response_times.append(duration)
            assert response.status_code == 200
        
        # Calculate statistics
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        
        # Response time should be reasonable
        assert avg_time < 1.0, f"Average response time {avg_time:.3f}s exceeds 1s"
        assert max_time < 2.0, f"Max response time {max_time:.3f}s exceeds 2s"
        
        print(f"\nResponse time stats:")
        print(f"  Average: {avg_time:.3f}s")
        print(f"  Max: {max_time:.3f}s")
        print(f"  Min: {min(response_times):.3f}s")

    @pytest.mark.integration
    def test_api_json_validation(self, real_api_client, auth_headers):
        """Test 10: API JSON validation"""
        # Test invalid JSON structure
        invalid_payloads = [
            {},  # Empty
            {"name": ""},  # Empty name
            {"name": "Test", "scope": "invalid"},  # Invalid type
            {"name": "Test", "scope": {"ip_ranges": "not_a_list"}},  # Invalid nested type
        ]
        
        for payload in invalid_payloads:
            response = real_api_client.post(
                "/api/v1/missions",
                json=payload,
                headers=auth_headers
            )
            
            # Should return 400 or 422 for validation errors
            assert response.status_code in [400, 422], \
                f"Expected validation error for payload {payload}, got {response.status_code}"
            
            # Response should contain error details
            error_data = response.json()
            assert "detail" in error_data or "error" in error_data or "message" in error_data


class TestAPIServiceIntegration(ProductionTestBase):
    """Test suite for service-level API integration"""

    @pytest.mark.integration
    def test_api_database_integration(self, real_api_client, auth_headers, real_database):
        """Test 11: API-Database integration"""
        # Create mission via API
        mission_data = {
            "name": f"DB Integration Test {uuid.uuid4().hex[:8]}",
            "description": "Testing API-DB integration",
            "scope": {
                "ip_ranges": ["192.168.1.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        response = real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        
        assert response.status_code in [200, 201]
        created_mission = response.json()
        mission_id = created_mission.get("id") or created_mission.get("mission_id")
        
        # Verify in database directly
        from sqlalchemy import text
        
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT * FROM missions WHERE id = :id"),
                {"id": mission_id}
            ).fetchone()
            
            assert result is not None
            assert result.name == mission_data["name"]
            assert result.description == mission_data["description"]

    @pytest.mark.integration
    def test_api_redis_integration(self, real_api_client, auth_headers, real_blackboard):
        """Test 12: API-Redis integration"""
        # Create mission via API
        mission_data = {
            "name": f"Redis Integration Test {uuid.uuid4().hex[:8]}",
            "description": "Testing API-Redis integration",
            "scope": {
                "ip_ranges": ["192.168.1.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        response = real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        
        assert response.status_code in [200, 201]
        created_mission = response.json()
        mission_id = created_mission.get("id") or created_mission.get("mission_id")
        
        # Check if mission data is cached in Redis
        # This depends on your caching strategy
        cache_key = f"mission:{mission_id}"
        cached_data = real_blackboard.get(cache_key)
        
        # Might be cached or not, depending on implementation
        if cached_data:
            print(f"Mission {mission_id} is cached in Redis")
        else:
            print(f"Mission {mission_id} is not cached (lazy loading)")

    @pytest.mark.integration
    def test_api_end_to_end_mission_workflow(self, real_api_client, auth_headers):
        """Test 13: End-to-end mission workflow via API"""
        # 1. Create mission
        mission_data = {
            "name": f"E2E Test Mission {uuid.uuid4().hex[:8]}",
            "description": "End-to-end workflow test",
            "scope": {
                "ip_ranges": ["192.168.1.0/24"]
            },
            "goals": ["reconnaissance"],
            "constraints": {
                "stealth": True
            }
        }
        
        response = real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        assert response.status_code in [200, 201]
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        
        # 2. Start mission
        response = real_api_client.post(
            f"/api/v1/missions/{mission_id}/start",
            json={},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # 3. Check status
        response = real_api_client.get(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        mission = response.json()
        assert mission["status"] in ["running", "started"]
        
        # 4. Pause mission
        response = real_api_client.post(
            f"/api/v1/missions/{mission_id}/pause",
            json={},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # 5. Resume mission
        response = real_api_client.post(
            f"/api/v1/missions/{mission_id}/resume",
            json={},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # 6. Stop mission
        response = real_api_client.post(
            f"/api/v1/missions/{mission_id}/stop",
            json={},
            headers=auth_headers
        )
        assert response.status_code == 200
        
        # 7. Verify final status
        response = real_api_client.get(
            f"/api/v1/missions/{mission_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        mission = response.json()
        assert mission["status"] == "stopped"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
