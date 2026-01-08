"""
Integration Tests for PostgreSQL Database
==========================================

Tests real database operations without mocks.
"""

import pytest
from sqlalchemy import text
from datetime import datetime
import uuid

from tests.production.base import ProductionTestBase


class TestDatabaseIntegration(ProductionTestBase):
    """Test suite for real database operations"""

    @pytest.mark.integration
    def test_user_registration_real_database(self, real_database):
        """Test 1: User registration with real database"""
        # Create a test user
        user_id = str(uuid.uuid4())
        user_data = {
            'id': user_id,
            'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
            'username': f'testuser_{uuid.uuid4().hex[:8]}',
            'hashed_password': 'test_hash',
            'is_active': True,
            'is_verified': True,
            'created_at': datetime.utcnow()
        }

        # Insert user
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO users (id, email, username, hashed_password, 
                                     is_active, is_verified, created_at)
                    VALUES (:id, :email, :username, :hashed_password,
                            :is_active, :is_verified, :created_at)
                """),
                user_data
            )
            session.commit()

        # Verify user exists
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT * FROM users WHERE id = :id"),
                {'id': user_id}
            ).fetchone()

            assert result is not None
            assert result.email == user_data['email']
            assert result.username == user_data['username']
            assert result.is_active == user_data['is_active']

    @pytest.mark.integration
    def test_data_persistence_across_sessions(self, real_database):
        """Test 2: Data persistence across sessions"""
        org_id = str(uuid.uuid4())
        org_name = f'test_org_{uuid.uuid4().hex[:8]}'

        # Session 1: Insert data
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': org_name,
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()

        # Session 2: Verify data persists
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT * FROM organizations WHERE id = :id"),
                {'id': org_id}
            ).fetchone()

            assert result is not None
            assert result.name == org_name
            assert result.plan == 'free'

    @pytest.mark.integration
    def test_transaction_rollback_on_error(self, real_database):
        """Test 3: Transaction rollback on error"""
        user_id = str(uuid.uuid4())

        # Try to insert invalid data (should rollback)
        with pytest.raises(Exception):
            with real_database.session_scope() as session:
                # Valid insert
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username, hashed_password)
                        VALUES (:id, :email, :username, :password)
                    """),
                    {
                        'id': user_id,
                        'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
                        'username': f'testuser_{uuid.uuid4().hex[:8]}',
                        'password': 'test_hash'
                    }
                )
                
                # Invalid insert (duplicate email - should fail)
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username, hashed_password)
                        VALUES (:id, :email, :username, :password)
                    """),
                    {
                        'id': str(uuid.uuid4()),
                        'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
                        'username': None,  # NULL constraint violation
                        'password': 'test_hash'
                    }
                )
                session.commit()

        # Verify rollback - user should NOT exist
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT COUNT(*) as count FROM users WHERE id = :id"),
                {'id': user_id}
            ).fetchone()

            assert result.count == 0

    @pytest.mark.integration
    def test_database_concurrent_access(self, real_database):
        """Test 4: Concurrent database access"""
        import threading
        import time

        org_id = str(uuid.uuid4())
        results = []

        def create_org():
            try:
                with real_database.session_scope() as session:
                    session.execute(
                        text("""
                            INSERT INTO organizations (id, name, plan, created_at)
                            VALUES (:id, :name, :plan, :created_at)
                        """),
                        {
                            'id': org_id,
                            'name': f'concurrent_org_{uuid.uuid4().hex[:8]}',
                            'plan': 'free',
                            'created_at': datetime.utcnow()
                        }
                    )
                    session.commit()
                    results.append('success')
            except Exception as e:
                results.append(f'error: {str(e)}')

        # Run 3 concurrent threads
        threads = [threading.Thread(target=create_org) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only one should succeed (unique ID constraint)
        success_count = sum(1 for r in results if r == 'success')
        assert success_count == 1

    @pytest.mark.integration
    def test_complex_query_with_joins(self, real_database):
        """Test 5: Complex query with joins"""
        # Create test data
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        mission_id = str(uuid.uuid4())

        with real_database.session_scope() as session:
            # Create user
            session.execute(
                text("""
                    INSERT INTO users (id, email, username, hashed_password, 
                                     organization_id, created_at)
                    VALUES (:id, :email, :username, :password, :org_id, :created_at)
                """),
                {
                    'id': user_id,
                    'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
                    'username': f'testuser_{uuid.uuid4().hex[:8]}',
                    'password': 'test_hash',
                    'org_id': org_id,
                    'created_at': datetime.utcnow()
                }
            )

            # Create organization
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': f'test_org_{uuid.uuid4().hex[:8]}',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )

            # Create mission
            session.execute(
                text("""
                    INSERT INTO missions (id, name, status, organization_id, 
                                        created_by, created_at)
                    VALUES (:id, :name, :status, :org_id, :user_id, :created_at)
                """),
                {
                    'id': mission_id,
                    'name': 'Test Mission',
                    'status': 'created',
                    'org_id': org_id,
                    'user_id': user_id,
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()

        # Complex query with joins
        with real_database.session_scope() as session:
            result = session.execute(
                text("""
                    SELECT 
                        m.id as mission_id,
                        m.name as mission_name,
                        m.status,
                        u.username,
                        o.name as org_name,
                        o.plan
                    FROM missions m
                    JOIN users u ON m.created_by = u.id
                    JOIN organizations o ON m.organization_id = o.id
                    WHERE m.id = :mission_id
                """),
                {'mission_id': mission_id}
            ).fetchone()

            assert result is not None
            assert result.mission_id == mission_id
            assert result.mission_name == 'Test Mission'
            assert result.status == 'created'
            assert result.username is not None
            assert result.org_name is not None
            assert result.plan == 'free'

    @pytest.mark.integration
    def test_database_constraints_enforcement(self, real_database):
        """Test 6: Database constraints enforcement"""
        # Test NOT NULL constraint
        with pytest.raises(Exception):
            with real_database.session_scope() as session:
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username)
                        VALUES (:id, :email, NULL)
                    """),
                    {
                        'id': str(uuid.uuid4()),
                        'email': f'test_{uuid.uuid4().hex[:8]}@example.com'
                    }
                )
                session.commit()

        # Test UNIQUE constraint
        email = f'unique_{uuid.uuid4().hex[:8]}@example.com'
        with real_database.session_scope() as session:
            # First insert should succeed
            session.execute(
                text("""
                    INSERT INTO users (id, email, username, hashed_password)
                    VALUES (:id, :email, :username, :password)
                """),
                {
                    'id': str(uuid.uuid4()),
                    'email': email,
                    'username': f'user_{uuid.uuid4().hex[:8]}',
                    'password': 'test_hash'
                }
            )
            session.commit()

        # Duplicate email should fail
        with pytest.raises(Exception):
            with real_database.session_scope() as session:
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username, hashed_password)
                        VALUES (:id, :email, :username, :password)
                    """),
                    {
                        'id': str(uuid.uuid4()),
                        'email': email,  # Duplicate
                        'username': f'user_{uuid.uuid4().hex[:8]}',
                        'password': 'test_hash'
                    }
                )
                session.commit()

    @pytest.mark.integration
    def test_database_performance_bulk_insert(self, real_database):
        """Test 7: Database performance with bulk insert"""
        import time

        org_id = str(uuid.uuid4())
        
        # Create organization first
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': f'bulk_org_{uuid.uuid4().hex[:8]}',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()

        # Bulk insert 100 users
        start_time = time.time()
        user_ids = []

        with real_database.session_scope() as session:
            for i in range(100):
                user_id = str(uuid.uuid4())
                user_ids.append(user_id)
                
                session.execute(
                    text("""
                        INSERT INTO users (id, email, username, hashed_password,
                                         organization_id, created_at)
                        VALUES (:id, :email, :username, :password, :org_id, :created_at)
                    """),
                    {
                        'id': user_id,
                        'email': f'bulk_{i}_{uuid.uuid4().hex[:8]}@example.com',
                        'username': f'bulk_user_{i}_{uuid.uuid4().hex[:8]}',
                        'password': 'test_hash',
                        'org_id': org_id,
                        'created_at': datetime.utcnow()
                    }
                )
            session.commit()

        duration = time.time() - start_time

        # Verify all inserted
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT COUNT(*) as count FROM users WHERE organization_id = :org_id"),
                {'org_id': org_id}
            ).fetchone()

            assert result.count == 100

        # Performance check: should complete in < 5 seconds
        assert duration < 5.0, f"Bulk insert took {duration:.2f}s, expected < 5s"

    @pytest.mark.integration
    def test_database_indexing_performance(self, real_database):
        """Test 8: Database indexing performance"""
        import time

        # Create test data
        org_id = str(uuid.uuid4())
        mission_ids = []

        with real_database.session_scope() as session:
            # Create organization
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': f'index_test_org_{uuid.uuid4().hex[:8]}',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )

            # Create user
            user_id = str(uuid.uuid4())
            session.execute(
                text("""
                    INSERT INTO users (id, email, username, hashed_password,
                                     organization_id, created_at)
                    VALUES (:id, :email, :username, :password, :org_id, :created_at)
                """),
                {
                    'id': user_id,
                    'email': f'index_test_{uuid.uuid4().hex[:8]}@example.com',
                    'username': f'index_user_{uuid.uuid4().hex[:8]}',
                    'password': 'test_hash',
                    'org_id': org_id,
                    'created_at': datetime.utcnow()
                }
            )

            # Create 50 missions
            for i in range(50):
                mission_id = str(uuid.uuid4())
                mission_ids.append(mission_id)
                
                session.execute(
                    text("""
                        INSERT INTO missions (id, name, status, organization_id,
                                            created_by, created_at)
                        VALUES (:id, :name, :status, :org_id, :user_id, :created_at)
                    """),
                    {
                        'id': mission_id,
                        'name': f'Mission {i}',
                        'status': 'created',
                        'org_id': org_id,
                        'user_id': user_id,
                        'created_at': datetime.utcnow()
                    }
                )
            session.commit()

        # Query by indexed column (organization_id) - should be fast
        start_time = time.time()
        with real_database.session_scope() as session:
            result = session.execute(
                text("""
                    SELECT COUNT(*) as count 
                    FROM missions 
                    WHERE organization_id = :org_id
                """),
                {'org_id': org_id}
            ).fetchone()
            
            assert result.count == 50

        indexed_duration = time.time() - start_time

        # Indexed query should complete in < 0.1 seconds
        assert indexed_duration < 0.1, \
            f"Indexed query took {indexed_duration:.4f}s, expected < 0.1s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
