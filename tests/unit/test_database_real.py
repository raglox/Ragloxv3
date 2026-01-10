# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Database REAL Tests (NO MOCKS)
# Testing PostgreSQL operations with real database
# ═══════════════════════════════════════════════════════════════

"""
Database Real Tests - 100% Real, 0% Mocks

This test suite uses REAL PostgreSQL (no mocks) to test database functionality.
All operations interact with actual PostgreSQL instance.

Philosophy:
- No mocks, no fakes
- Real PostgreSQL connection
- Real transactions
- Real constraints
- Real performance
- Test actual behavior, not mock expectations

Coverage Target: 0% → 80%+
"""

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4
import os

from src.core.database import DatabasePool, get_db_pool, init_db_pool
from src.core.database.user_repository import UserRepository
from src.core.database.organization_repository import OrganizationRepository
from src.core.database.mission_repository import MissionRepository
from src.core.config import get_settings

# Check if real services are available
USE_REAL_SERVICES = os.getenv("USE_REAL_SERVICES", "false").lower() == "true"

pytestmark = pytest.mark.skipif(
    not USE_REAL_SERVICES,
    reason="Real services not enabled. Set USE_REAL_SERVICES=true"
)


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def real_db_settings():
    """Get real database settings."""
    settings = get_settings()
    assert settings.database_url, "DATABASE_URL must be set"
    return settings


@pytest_asyncio.fixture
async def real_db_pool(real_db_settings):
    """
    Create DatabasePool connected to REAL PostgreSQL.
    
    This fixture:
    - Connects to real PostgreSQL
    - Cleans up test data after each test
    - No mocking whatsoever
    """
    pool = DatabasePool(
        database_url=real_db_settings.database_url,
        min_size=2,
        max_size=5
    )
    await pool.connect()
    
    # Verify connection
    health = await pool.health_check()
    assert health["healthy"], f"Database unhealthy: {health}"
    
    yield pool
    
    # Cleanup: delete test data (organizations, users, missions created in tests)
    # Tests should use unique IDs so cleanup is optional
    await pool.disconnect()


# ═══════════════════════════════════════════════════════════════
# Connection & Health Tests
# ═══════════════════════════════════════════════════════════════

class TestRealDatabaseConnection:
    """Test real PostgreSQL connection management."""
    
    @pytest.mark.asyncio
    async def test_connect_to_real_postgres(self, real_db_settings):
        """Test connecting to real PostgreSQL."""
        pool = DatabasePool(real_db_settings.database_url)
        await pool.connect()
        
        # Should be connected
        assert pool.is_connected
        
        health = await pool.health_check()
        assert health["healthy"]
        assert "version" in health
        assert "PostgreSQL" in health["version"]
        
        print(f"\n✅ PostgreSQL version: {health['version']}")
        print(f"✅ Pool size: {health['pool_size']}")
        
        await pool.disconnect()
        assert not pool.is_connected
    
    @pytest.mark.asyncio
    async def test_pool_size_configuration(self, real_db_settings):
        """Test connection pool sizing."""
        pool = DatabasePool(
            real_db_settings.database_url,
            min_size=3,
            max_size=10
        )
        await pool.connect()
        
        health = await pool.health_check()
        assert health["pool_size"] >= 3
        assert health["pool_size"] <= 10
        
        await pool.disconnect()
    
    @pytest.mark.asyncio
    async def test_simple_query(self, real_db_pool):
        """Test executing a simple query."""
        result = await real_db_pool.fetchval("SELECT 1")
        assert result == 1
        
        result = await real_db_pool.fetchval("SELECT 2 + 2")
        assert result == 4


# ═══════════════════════════════════════════════════════════════
# Transaction Tests
# ═══════════════════════════════════════════════════════════════

class TestRealTransactions:
    """Test transaction behavior with real database."""
    
    @pytest.mark.asyncio
    async def test_transaction_commit(self, real_db_pool):
        """Test transaction commits successfully."""
        org_id = str(uuid4())
        org_name = f"test_org_{uuid4().hex[:8]}"
        
        # Insert in transaction
        async with real_db_pool.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO organizations (id, name, plan, created_at)
                VALUES ($1, $2, $3, $4)
                """,
                org_id, org_name, "free", datetime.utcnow()
            )
        
        # Verify committed
        result = await real_db_pool.fetchrow(
            "SELECT * FROM organizations WHERE id = $1",
            org_id
        )
        assert result is not None
        assert result["name"] == org_name
    
    @pytest.mark.asyncio
    async def test_transaction_rollback_on_error(self, real_db_pool):
        """Test transaction rolls back on error."""
        org_id = str(uuid4())
        
        # Try transaction that will fail
        try:
            async with real_db_pool.transaction() as conn:
                # Valid insert
                await conn.execute(
                    """
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES ($1, $2, $3, $4)
                    """,
                    org_id, "valid_org", "free", datetime.utcnow()
                )
                
                # Invalid insert (NULL username - should fail)
                await conn.execute(
                    """
                    INSERT INTO users (id, email, username, hashed_password)
                    VALUES ($1, $2, $3, $4)
                    """,
                    str(uuid4()), f"test_{uuid4().hex}@test.com", None, "hash"
                )
        except Exception:
            pass  # Expected
        
        # Verify org was NOT inserted (rollback)
        result = await real_db_pool.fetchval(
            "SELECT COUNT(*) FROM organizations WHERE id = $1",
            org_id
        )
        assert result == 0


# ═══════════════════════════════════════════════════════════════
# Repository Tests (Organization)
# ═══════════════════════════════════════════════════════════════

class TestRealOrganizationRepository:
    """Test OrganizationRepository with real database."""
    
    @pytest.mark.asyncio
    async def test_create_organization(self, real_db_pool):
        """Test creating an organization."""
        repo = OrganizationRepository(real_db_pool)
        
        org_data = {
            "name": f"Test Org {uuid4().hex[:8]}",
            "plan": "free",
            "api_calls_limit": 1000,
            "storage_limit_gb": 10
        }
        
        org = await repo.create_organization(**org_data)
        
        assert org is not None
        assert org["name"] == org_data["name"]
        assert org["plan"] == "free"
        assert "id" in org
        assert "created_at" in org
    
    @pytest.mark.asyncio
    async def test_get_organization_by_id(self, real_db_pool):
        """Test retrieving organization by ID."""
        repo = OrganizationRepository(real_db_pool)
        
        # Create
        org = await repo.create_organization(
            name=f"Retrieve Test {uuid4().hex[:8]}",
            plan="pro"
        )
        org_id = org["id"]
        
        # Retrieve
        retrieved = await repo.get_organization(org_id)
        assert retrieved is not None
        assert retrieved["id"] == org_id
        assert retrieved["plan"] == "pro"
    
    @pytest.mark.asyncio
    async def test_update_organization(self, real_db_pool):
        """Test updating organization."""
        repo = OrganizationRepository(real_db_pool)
        
        # Create
        org = await repo.create_organization(
            name=f"Update Test {uuid4().hex[:8]}",
            plan="free"
        )
        
        # Update
        updated = await repo.update_organization(
            org["id"],
            {"plan": "enterprise", "api_calls_limit": 100000}
        )
        
        assert updated["plan"] == "enterprise"
        assert updated["api_calls_limit"] == 100000


# ═══════════════════════════════════════════════════════════════
# Repository Tests (User)
# ═══════════════════════════════════════════════════════════════

class TestRealUserRepository:
    """Test UserRepository with real database."""
    
    @pytest.mark.asyncio
    async def test_create_user(self, real_db_pool):
        """Test creating a user."""
        repo = UserRepository(real_db_pool)
        
        user_data = {
            "email": f"test_{uuid4().hex}@example.com",
            "username": f"user_{uuid4().hex[:8]}",
            "hashed_password": "hashed_password_123",
            "full_name": "Test User"
        }
        
        user = await repo.create_user(**user_data)
        
        assert user is not None
        assert user["email"] == user_data["email"]
        assert user["username"] == user_data["username"]
        assert "id" in user
        assert "created_at" in user
    
    @pytest.mark.asyncio
    async def test_get_user_by_email(self, real_db_pool):
        """Test retrieving user by email."""
        repo = UserRepository(real_db_pool)
        
        email = f"test_{uuid4().hex}@example.com"
        
        # Create
        user = await repo.create_user(
            email=email,
            username=f"user_{uuid4().hex[:8]}",
            hashed_password="hash"
        )
        
        # Retrieve by email
        retrieved = await repo.get_user_by_email(email)
        assert retrieved is not None
        assert retrieved["email"] == email
        assert retrieved["id"] == user["id"]
    
    @pytest.mark.asyncio
    async def test_unique_email_constraint(self, real_db_pool):
        """Test email uniqueness is enforced."""
        repo = UserRepository(real_db_pool)
        
        email = f"unique_{uuid4().hex}@example.com"
        
        # Create first user
        await repo.create_user(
            email=email,
            username=f"user1_{uuid4().hex[:8]}",
            hashed_password="hash1"
        )
        
        # Try to create duplicate (should fail)
        with pytest.raises(Exception):
            await repo.create_user(
                email=email,
                username=f"user2_{uuid4().hex[:8]}",
                hashed_password="hash2"
            )


# ═══════════════════════════════════════════════════════════════
# Repository Tests (Mission)
# ═══════════════════════════════════════════════════════════════

class TestRealMissionRepository:
    """Test MissionRepository with real database."""
    
    @pytest.mark.asyncio
    async def test_create_mission(self, real_db_pool):
        """Test creating a mission."""
        # First create org and user
        org_repo = OrganizationRepository(real_db_pool)
        user_repo = UserRepository(real_db_pool)
        
        org = await org_repo.create_organization(
            name=f"Mission Test Org {uuid4().hex[:8]}",
            plan="free"
        )
        
        user = await user_repo.create_user(
            email=f"mission_test_{uuid4().hex}@example.com",
            username=f"mission_user_{uuid4().hex[:8]}",
            hashed_password="hash",
            organization_id=org["id"]
        )
        
        # Create mission
        repo = MissionRepository(real_db_pool)
        mission = await repo.create_mission(
            name=f"Test Mission {uuid4().hex[:8]}",
            description="Real mission test",
            organization_id=org["id"],
            created_by=user["id"],
            scope=["192.168.1.0/24"],
            goals={"initial_access": "pending"}
        )
        
        assert mission is not None
        assert mission["name"].startswith("Test Mission")
        assert mission["organization_id"] == org["id"]
        assert mission["created_by"] == user["id"]
    
    @pytest.mark.asyncio
    async def test_get_missions_by_organization(self, real_db_pool):
        """Test retrieving missions for an organization."""
        # Setup
        org_repo = OrganizationRepository(real_db_pool)
        user_repo = UserRepository(real_db_pool)
        mission_repo = MissionRepository(real_db_pool)
        
        org = await org_repo.create_organization(
            name=f"Org {uuid4().hex[:8]}",
            plan="free"
        )
        
        user = await user_repo.create_user(
            email=f"test_{uuid4().hex}@example.com",
            username=f"user_{uuid4().hex[:8]}",
            hashed_password="hash",
            organization_id=org["id"]
        )
        
        # Create multiple missions
        for i in range(3):
            await mission_repo.create_mission(
                name=f"Mission {i}",
                organization_id=org["id"],
                created_by=user["id"]
            )
        
        # Retrieve
        missions = await mission_repo.get_missions_by_organization(org["id"])
        assert len(missions) >= 3


# ═══════════════════════════════════════════════════════════════
# Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestRealDatabasePerformance:
    """Test database performance with real PostgreSQL."""
    
    @pytest.mark.asyncio
    async def test_bulk_insert_performance(self, real_db_pool):
        """Test bulk insert performance."""
        import time
        
        org_id = str(uuid4())
        
        # Create org
        await real_db_pool.execute(
            """
            INSERT INTO organizations (id, name, plan, created_at)
            VALUES ($1, $2, $3, $4)
            """,
            org_id, f"bulk_org_{uuid4().hex[:8]}", "free", datetime.utcnow()
        )
        
        start = time.time()
        
        # Bulk insert 50 users
        async with real_db_pool.transaction() as conn:
            for i in range(50):
                await conn.execute(
                    """
                    INSERT INTO users (id, email, username, hashed_password, organization_id, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    str(uuid4()),
                    f"bulk_{i}_{uuid4().hex}@test.com",
                    f"bulk_user_{i}_{uuid4().hex[:8]}",
                    "hash",
                    org_id,
                    datetime.utcnow()
                )
        
        duration = time.time() - start
        
        # Should complete in < 3 seconds
        assert duration < 3.0, f"Took {duration:.2f}s, expected < 3s"
        
        # Verify count
        count = await real_db_pool.fetchval(
            "SELECT COUNT(*) FROM users WHERE organization_id = $1",
            org_id
        )
        assert count == 50
    
    @pytest.mark.asyncio
    async def test_concurrent_transactions(self, real_db_pool):
        """Test concurrent transaction handling."""
        async def create_org():
            org_id = str(uuid4())
            try:
                async with real_db_pool.transaction() as conn:
                    await conn.execute(
                        """
                        INSERT INTO organizations (id, name, plan, created_at)
                        VALUES ($1, $2, $3, $4)
                        """,
                        org_id, f"concurrent_{uuid4().hex[:8]}", "free", datetime.utcnow()
                    )
                return "success"
            except Exception as e:
                return f"error: {str(e)}"
        
        # Run 5 concurrent transactions
        results = await asyncio.gather(
            *[create_org() for _ in range(5)]
        )
        
        # All should succeed
        success_count = sum(1 for r in results if r == "success")
        assert success_count == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
