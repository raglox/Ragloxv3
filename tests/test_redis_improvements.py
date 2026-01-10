"""
RAGLOX v3.0 - Redis Improvements Testing
Tests for connection pooling, circuit breaker, and retry logic
"""

import pytest
import asyncio
import logging
from datetime import datetime

from src.core.config import Settings
from src.core.redis_manager import (
    RedisManager,
    CircuitBreaker,
    RetryPolicy,
    RedisConnectionPool,
    CircuitState
)
from src.core.blackboard_v2 import BlackboardV2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_circuit_breaker_basic():
    """Test basic circuit breaker functionality."""
    circuit = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout=2.0,
        expected_exception=Exception
    )
    
    # Initially closed
    assert circuit.state == CircuitState.CLOSED
    assert circuit.can_execute()
    
    # Record failures
    for i in range(2):
        circuit.record_failure()
        assert circuit.state == CircuitState.CLOSED  # Still below threshold
    
    # Third failure should open circuit
    circuit.record_failure()
    assert circuit.state == CircuitState.OPEN
    assert not circuit.can_execute()
    
    # Wait for recovery timeout
    await asyncio.sleep(2.1)
    assert circuit.can_execute()  # Should transition to HALF_OPEN
    assert circuit.state == CircuitState.HALF_OPEN
    
    # Success should close circuit
    circuit.record_success()
    assert circuit.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_retry_policy_delays():
    """Test retry policy delay calculation."""
    policy = RetryPolicy(
        max_attempts=5,
        base_delay=1.0,
        max_delay=10.0,
        exponential_base=2.0,
        jitter=False  # Disable jitter for predictable testing
    )
    
    # Test delay progression
    delays = [policy.get_delay(i) for i in range(5)]
    
    # Should follow: 1, 2, 4, 8, 10 (capped at max_delay)
    assert delays[0] == pytest.approx(1.0, rel=0.01)
    assert delays[1] == pytest.approx(2.0, rel=0.01)
    assert delays[2] == pytest.approx(4.0, rel=0.01)
    assert delays[3] == pytest.approx(8.0, rel=0.01)
    assert delays[4] == pytest.approx(10.0, rel=0.01)  # Capped


@pytest.mark.asyncio
async def test_retry_policy_execution():
    """Test retry policy with failing function."""
    policy = RetryPolicy(max_attempts=3, base_delay=0.1)
    
    call_count = 0
    
    async def failing_func():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception(f"Attempt {call_count} failed")
        return "success"
    
    # Should succeed on third attempt
    result = await policy.execute(failing_func)
    assert result == "success"
    assert call_count == 3


@pytest.mark.asyncio
async def test_redis_connection_pool():
    """Test Redis connection pool basic functionality."""
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"  # Test database
    
    pool = RedisConnectionPool(
        url=settings.redis_url,
        max_connections=10,
        health_check_interval=5
    )
    
    await pool.connect()
    
    # Test health check
    is_healthy = await pool.health_check()
    assert is_healthy
    
    # Test basic operations
    await pool.redis.set("test_key", "test_value")
    value = await pool.redis.get("test_key")
    assert value == "test_value"
    
    await pool.disconnect()


@pytest.mark.asyncio
async def test_redis_manager_standalone():
    """Test RedisManager in standalone mode."""
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"
    settings.redis_mode = "standalone"
    
    manager = RedisManager(settings)
    
    await manager.connect()
    assert manager.is_connected()
    assert manager.circuit_state == CircuitState.CLOSED
    
    # Test basic operations
    await manager.redis.set("test_manager", "value")
    value = await manager.redis.get("test_manager")
    assert value == "value"
    
    # Test health check
    is_healthy = await manager.health_check()
    assert is_healthy
    
    await manager.disconnect()


@pytest.mark.asyncio
async def test_redis_manager_with_retry():
    """Test RedisManager retry logic."""
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"
    settings.redis_reconnect_max_attempts = 3
    
    manager = RedisManager(settings)
    await manager.connect()
    
    # Test successful operation with retry wrapper
    async def redis_operation():
        await manager.redis.set("retry_test", "value")
        return await manager.redis.get("retry_test")
    
    result = await manager.execute_with_retry(redis_operation)
    assert result == "value"
    
    await manager.disconnect()


@pytest.mark.asyncio
async def test_blackboard_v2_basic():
    """Test enhanced Blackboard basic operations."""
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"
    
    blackboard = BlackboardV2(settings=settings)
    
    await blackboard.connect()
    assert blackboard.is_connected()
    
    # Test hash operations
    test_data = {
        "name": "Test Mission",
        "status": "active",
        "count": 42
    }
    
    await blackboard.hset("test:mission:1", test_data)
    retrieved = await blackboard.hgetall("test:mission:1")
    
    assert retrieved is not None
    assert retrieved["name"] == "Test Mission"
    assert retrieved["status"] == "active"
    
    # Test health check
    is_healthy = await blackboard.health_check()
    assert is_healthy
    
    # Check circuit state
    assert blackboard.circuit_state == CircuitState.CLOSED
    
    await blackboard.disconnect()


@pytest.mark.asyncio
async def test_blackboard_v2_with_mission():
    """Test Blackboard with Mission model."""
    from src.core.models import Mission, MissionStatus, GoalStatus
    from uuid import uuid4
    
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"
    
    blackboard = BlackboardV2(settings=settings)
    await blackboard.connect()
    
    # Create mission
    mission_id = str(uuid4())
    mission = Mission(
        id=mission_id,
        name="Test Mission",
        description="Testing Redis improvements",
        scope=["192.168.1.0/24"],
        status=MissionStatus.CREATED,
        goals={"Goal 1": GoalStatus.PENDING},
        constraints={"time_limit": 3600},
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    # Store mission
    await blackboard.create_mission(mission)
    
    # Retrieve mission
    retrieved = await blackboard.get_mission(mission_id)
    assert retrieved is not None
    assert retrieved["name"] == "Test Mission"
    assert retrieved["status"] == MissionStatus.CREATED.value
    
    # Update mission status
    await blackboard.update_mission_status(
        mission_id,
        MissionStatus.RUNNING,
        "Mission started"
    )
    
    # Verify update
    updated = await blackboard.get_mission(mission_id)
    assert updated["status"] == MissionStatus.RUNNING.value
    
    await blackboard.disconnect()


@pytest.mark.asyncio
async def test_circuit_breaker_with_redis():
    """Test circuit breaker behavior with Redis operations."""
    settings = Settings()
    settings.redis_url = "redis://localhost:6379/15"
    
    manager = RedisManager(settings)
    await manager.connect()
    
    # Simulate failures by connecting to invalid URL temporarily
    # (This test is conceptual - actual implementation would need mock)
    
    # Verify circuit starts closed
    assert manager.circuit_state == CircuitState.CLOSED
    
    # Normal operation should work
    await manager.redis.set("circuit_test", "value")
    value = await manager.redis.get("circuit_test")
    assert value == "value"
    
    await manager.disconnect()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
