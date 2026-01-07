"""
Integration Tests for Service Layer
===================================

Tests service layer integration without mocks.
"""

import pytest
import time
import uuid
from datetime import datetime, timedelta
from sqlalchemy import text


from tests.production.base import ProductionTestBase


class TestServiceIntegration(ProductionTestBase):
    """Test suite for service layer integration"""

    @pytest.mark.integration
    def test_service_layer_caching(self, real_database, real_blackboard):
        """Test 1: Service layer caching behavior"""
        # Create test data in database
        org_id = str(uuid.uuid4())
        org_name = f'cache_test_{uuid.uuid4().hex[:8]}'
        
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
        
        # Cache in Redis
        cache_key = f"org:{org_id}"
        cache_data = {
            'id': org_id,
            'name': org_name,
            'plan': 'free'
        }
        real_blackboard.set(cache_key, cache_data, expire=300)
        
        # Verify cache hit
        cached = real_blackboard.get(cache_key)
        assert cached is not None
        assert cached['name'] == org_name
        
        # Verify database consistency
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT * FROM organizations WHERE id = :id"),
                {'id': org_id}
            ).fetchone()
            
            assert result.name == org_name

    @pytest.mark.integration
    def test_cache_invalidation_on_update(self, real_database, real_blackboard):
        """Test 2: Cache invalidation on data update"""
        # Setup: Create cached data
        org_id = str(uuid.uuid4())
        
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': 'Original Name',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()
        
        cache_key = f"org:{org_id}"
        real_blackboard.set(cache_key, {'name': 'Original Name'}, expire=300)
        
        # Update database
        with real_database.session_scope() as session:
            session.execute(
                text("UPDATE organizations SET name = :name WHERE id = :id"),
                {'name': 'Updated Name', 'id': org_id}
            )
            session.commit()
        
        # Invalidate cache
        real_blackboard.delete(cache_key)
        
        # Verify cache is invalidated
        cached = real_blackboard.get(cache_key)
        assert cached is None

    @pytest.mark.integration
    def test_service_distributed_locking(self, real_blackboard):
        """Test 3: Distributed locking mechanism"""
        lock_key = f"lock:test:{uuid.uuid4().hex}"
        
        # Acquire lock
        acquired = real_blackboard.set(lock_key, "locked", expire=10, nx=True)
        assert acquired is True
        
        # Try to acquire again (should fail)
        acquired_again = real_blackboard.set(lock_key, "locked", expire=10, nx=True)
        assert acquired_again is False
        
        # Release lock
        real_blackboard.delete(lock_key)
        
        # Should be able to acquire now
        acquired_after_release = real_blackboard.set(lock_key, "locked", expire=10, nx=True)
        assert acquired_after_release is True

    @pytest.mark.integration
    def test_service_pub_sub_messaging(self, real_blackboard):
        """Test 4: Pub/Sub messaging"""
        import threading
        
        channel = f"test:channel:{uuid.uuid4().hex}"
        messages_received = []
        
        def subscriber():
            """Subscribe and collect messages"""
            pubsub = real_blackboard.redis_client.pubsub()
            pubsub.subscribe(channel)
            
            # Wait for subscription
            for message in pubsub.listen():
                if message['type'] == 'message':
                    messages_received.append(message['data'].decode('utf-8'))
                    if len(messages_received) >= 3:
                        break
        
        # Start subscriber thread
        sub_thread = threading.Thread(target=subscriber)
        sub_thread.start()
        
        # Give subscriber time to start
        time.sleep(0.5)
        
        # Publish messages
        real_blackboard.redis_client.publish(channel, "Message 1")
        real_blackboard.redis_client.publish(channel, "Message 2")
        real_blackboard.redis_client.publish(channel, "Message 3")
        
        # Wait for subscriber
        sub_thread.join(timeout=5)
        
        # Verify messages received
        assert len(messages_received) == 3
        assert "Message 1" in messages_received
        assert "Message 2" in messages_received
        assert "Message 3" in messages_received

    @pytest.mark.integration
    def test_service_transaction_coordination(self, real_database, real_blackboard):
        """Test 5: Transaction coordination between DB and cache"""
        org_id = str(uuid.uuid4())
        cache_key = f"org:{org_id}"
        
        try:
            # Start transaction
            with real_database.session_scope() as session:
                # Insert to database
                session.execute(
                    text("""
                        INSERT INTO organizations (id, name, plan, created_at)
                        VALUES (:id, :name, :plan, :created_at)
                    """),
                    {
                        'id': org_id,
                        'name': 'Transaction Test',
                        'plan': 'free',
                        'created_at': datetime.utcnow()
                    }
                )
                
                # Cache data (only after DB commit)
                session.commit()
                
                # Now safe to cache
                real_blackboard.set(cache_key, {'name': 'Transaction Test'}, expire=300)
            
            # Verify both are consistent
            with real_database.session_scope() as session:
                db_result = session.execute(
                    text("SELECT * FROM organizations WHERE id = :id"),
                    {'id': org_id}
                ).fetchone()
                
                assert db_result is not None
            
            cache_result = real_blackboard.get(cache_key)
            assert cache_result is not None
            
        except Exception as e:
            # Rollback: clean up cache if DB failed
            real_blackboard.delete(cache_key)
            raise e


class TestServicePerformance(ProductionTestBase):
    """Test suite for service performance"""

    @pytest.mark.integration
    def test_cache_vs_database_performance(self, real_database, real_blackboard):
        """Test 6: Cache vs Database performance comparison"""
        # Setup: Create test data
        org_id = str(uuid.uuid4())
        
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': 'Performance Test',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()
        
        # Cache data
        cache_key = f"org:{org_id}"
        real_blackboard.set(cache_key, {'name': 'Performance Test'}, expire=300)
        
        # Measure database read time
        db_times = []
        for _ in range(100):
            start = time.time()
            with real_database.session_scope() as session:
                session.execute(
                    text("SELECT * FROM organizations WHERE id = :id"),
                    {'id': org_id}
                ).fetchone()
            db_times.append(time.time() - start)
        
        # Measure cache read time
        cache_times = []
        for _ in range(100):
            start = time.time()
            real_blackboard.get(cache_key)
            cache_times.append(time.time() - start)
        
        avg_db_time = sum(db_times) / len(db_times)
        avg_cache_time = sum(cache_times) / len(cache_times)
        
        print(f"\nPerformance comparison (100 reads):")
        print(f"  Database avg: {avg_db_time*1000:.2f}ms")
        print(f"  Cache avg: {avg_cache_time*1000:.2f}ms")
        print(f"  Speedup: {avg_db_time/avg_cache_time:.1f}x")
        
        # Cache should be significantly faster
        assert avg_cache_time < avg_db_time

    @pytest.mark.integration
    def test_concurrent_service_operations(self, real_database, real_blackboard):
        """Test 7: Concurrent service operations"""
        import concurrent.futures
        
        org_id = str(uuid.uuid4())
        
        # Create organization
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at, 
                                             missions_this_month)
                    VALUES (:id, :name, :plan, :created_at, :count)
                """),
                {
                    'id': org_id,
                    'name': 'Concurrent Test',
                    'plan': 'free',
                    'created_at': datetime.utcnow(),
                    'count': 0
                }
            )
            session.commit()
        
        def increment_mission_count():
            """Simulate incrementing mission count"""
            with real_database.session_scope() as session:
                # Use atomic increment
                session.execute(
                    text("""
                        UPDATE organizations 
                        SET missions_this_month = missions_this_month + 1 
                        WHERE id = :id
                    """),
                    {'id': org_id}
                )
                session.commit()
        
        # Run 50 concurrent increments
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(increment_mission_count) for _ in range(50)]
            for future in concurrent.futures.as_completed(futures):
                future.result()  # Wait for completion
        
        # Verify final count
        with real_database.session_scope() as session:
            result = session.execute(
                text("SELECT missions_this_month FROM organizations WHERE id = :id"),
                {'id': org_id}
            ).fetchone()
            
            # Should be exactly 50 (atomic operations)
            assert result.missions_this_month == 50

    @pytest.mark.integration
    def test_service_rate_limiting_implementation(self, real_blackboard):
        """Test 8: Service-level rate limiting"""
        user_id = str(uuid.uuid4())
        rate_limit_key = f"rate_limit:{user_id}"
        
        # Simulate rate limiting: 10 requests per minute
        max_requests = 10
        window_seconds = 60
        
        def check_rate_limit():
            """Check if request is within rate limit"""
            current_count = real_blackboard.get(rate_limit_key)
            
            if current_count is None:
                # First request
                real_blackboard.set(rate_limit_key, 1, expire=window_seconds)
                return True
            
            if int(current_count) >= max_requests:
                return False
            
            # Increment counter
            real_blackboard.redis_client.incr(rate_limit_key)
            return True
        
        # Make 10 requests (should all pass)
        for i in range(10):
            assert check_rate_limit() is True, f"Request {i+1} should pass"
        
        # 11th request should be rate limited
        assert check_rate_limit() is False, "Request 11 should be rate limited"


class TestServiceResilience(ProductionTestBase):
    """Test suite for service resilience"""

    @pytest.mark.integration
    def test_service_graceful_cache_failure(self, real_database, real_blackboard):
        """Test 9: Graceful handling of cache failures"""
        org_id = str(uuid.uuid4())
        
        # Create data in database
        with real_database.session_scope() as session:
            session.execute(
                text("""
                    INSERT INTO organizations (id, name, plan, created_at)
                    VALUES (:id, :name, :plan, :created_at)
                """),
                {
                    'id': org_id,
                    'name': 'Resilience Test',
                    'plan': 'free',
                    'created_at': datetime.utcnow()
                }
            )
            session.commit()
        
        # Simulate cache failure by using invalid key
        try:
            # This should not crash the service
            cache_result = real_blackboard.get(f"invalid:{org_id}")
            assert cache_result is None
            
            # Service should fall back to database
            with real_database.session_scope() as session:
                result = session.execute(
                    text("SELECT * FROM organizations WHERE id = :id"),
                    {'id': org_id}
                ).fetchone()
                
                assert result is not None
                assert result.name == 'Resilience Test'
        
        except Exception as e:
            pytest.fail(f"Service should handle cache failures gracefully: {e}")

    @pytest.mark.integration
    def test_service_retry_logic(self, real_blackboard):
        """Test 10: Service retry logic"""
        test_key = f"retry:test:{uuid.uuid4().hex}"
        max_retries = 3
        retry_count = 0
        
        def operation_with_retry():
            """Simulate operation with retry"""
            nonlocal retry_count
            
            for attempt in range(max_retries):
                try:
                    retry_count += 1
                    
                    # Simulate failure on first 2 attempts
                    if attempt < 2:
                        raise Exception("Simulated failure")
                    
                    # Success on 3rd attempt
                    real_blackboard.set(test_key, "success", expire=60)
                    return True
                
                except Exception:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(0.1)  # Brief delay before retry
            
            return False
        
        # Execute with retry
        result = operation_with_retry()
        
        assert result is True
        assert retry_count == 3  # Should have tried 3 times
        
        # Verify final success
        value = real_blackboard.get(test_key)
        assert value == "success"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
