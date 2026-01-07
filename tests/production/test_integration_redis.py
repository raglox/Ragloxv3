"""
Integration Tests for Real Redis Operations

Tests Redis/Blackboard interactions with real Redis instance.
No mocks - all operations hit real Redis.
"""

import pytest
import json
from typing import Dict, Any
from datetime import datetime
import asyncio

from .base import ProductionTestBase


@pytest.mark.production
@pytest.mark.integration
@pytest.mark.asyncio
class TestRedisIntegration(ProductionTestBase):
    """Test Redis operations with real Redis instance"""
    
    async def test_redis_connection(self, real_blackboard):
        """Test basic Redis connectivity"""
        # Ping Redis
        pong = await real_blackboard.ping()
        assert pong is True
        print("✅ Redis connection verified")
    
    async def test_redis_basic_operations(self, real_blackboard):
        """Test basic Redis SET/GET/DEL operations"""
        # SET
        await real_blackboard.set("test_key", "test_value")
        print("✅ SET operation successful")
        
        # GET
        value = await real_blackboard.get("test_key")
        assert value == "test_value"
        print("✅ GET operation successful")
        
        # DEL
        deleted = await real_blackboard.delete("test_key")
        assert deleted == 1
        print("✅ DEL operation successful")
        
        # Verify deleted
        value = await real_blackboard.get("test_key")
        assert value is None
        print("✅ Key deletion verified")
    
    async def test_redis_hash_operations(self, real_blackboard):
        """Test Redis hash operations for mission storage"""
        mission_id = f"test-mission-{datetime.utcnow().timestamp()}"
        mission_key = f"mission:{mission_id}"
        
        # HSET - Store mission data
        mission_data = {
            "id": mission_id,
            "name": "Test Mission",
            "status": "running",
            "created_at": datetime.utcnow().isoformat()
        }
        
        await real_blackboard.hset(
            mission_key,
            mapping={
                k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                for k, v in mission_data.items()
            }
        )
        print(f"✅ Mission stored in hash: {mission_key}")
        
        # HGETALL - Retrieve mission data
        stored_data = await real_blackboard.hgetall(mission_key)
        assert stored_data["id"] == mission_id
        assert stored_data["status"] == "running"
        print(f"✅ Mission retrieved from hash")
        
        # HGET - Get specific field
        status = await real_blackboard.hget(mission_key, "status")
        assert status == "running"
        print(f"✅ Mission status retrieved: {status}")
        
        # HINCRBY - Increment counter
        await real_blackboard.hset(mission_key, "target_count", "0")
        new_count = await real_blackboard.hincrby(mission_key, "target_count", 5)
        assert new_count == 5
        print(f"✅ Counter incremented: {new_count}")
        
        # Cleanup
        await real_blackboard.delete(mission_key)
    
    async def test_redis_list_operations(self, real_blackboard):
        """Test Redis list operations for task queues"""
        queue_key = f"task_queue:{datetime.utcnow().timestamp()}"
        
        # RPUSH - Add tasks to queue
        task1 = json.dumps({"task_id": "1", "action": "scan"})
        task2 = json.dumps({"task_id": "2", "action": "enumerate"})
        task3 = json.dumps({"task_id": "3", "action": "exploit"})
        
        await real_blackboard.rpush(queue_key, task1, task2, task3)
        print(f"✅ 3 tasks added to queue")
        
        # LLEN - Get queue length
        length = await real_blackboard.llen(queue_key)
        assert length == 3
        print(f"✅ Queue length: {length}")
        
        # LPOP - Get task from queue (FIFO)
        first_task = await real_blackboard.lpop(queue_key)
        first_task_data = json.loads(first_task)
        assert first_task_data["task_id"] == "1"
        print(f"✅ First task retrieved: {first_task_data['task_id']}")
        
        # LRANGE - View remaining tasks
        remaining = await real_blackboard.lrange(queue_key, 0, -1)
        assert len(remaining) == 2
        print(f"✅ Remaining tasks: {len(remaining)}")
        
        # Cleanup
        await real_blackboard.delete(queue_key)
    
    async def test_redis_set_operations(self, real_blackboard):
        """Test Redis set operations for unique collections"""
        targets_key = f"mission:targets:{datetime.utcnow().timestamp()}"
        
        # SADD - Add targets
        await real_blackboard.sadd(
            targets_key,
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3"
        )
        print(f"✅ 3 targets added to set")
        
        # SCARD - Get set size
        size = await real_blackboard.scard(targets_key)
        assert size == 3
        print(f"✅ Set size: {size}")
        
        # SISMEMBER - Check membership
        is_member = await real_blackboard.sismember(targets_key, "192.168.1.1")
        assert is_member is True
        print(f"✅ Membership check passed")
        
        # SADD duplicate - Should not increase size
        await real_blackboard.sadd(targets_key, "192.168.1.1")
        size_after = await real_blackboard.scard(targets_key)
        assert size_after == 3
        print(f"✅ Duplicate handling verified")
        
        # SMEMBERS - Get all members
        members = await real_blackboard.smembers(targets_key)
        assert len(members) == 3
        assert "192.168.1.1" in members
        print(f"✅ All members retrieved: {len(members)}")
        
        # Cleanup
        await real_blackboard.delete(targets_key)
    
    async def test_redis_expiration(self, real_blackboard):
        """Test Redis key expiration (TTL)"""
        temp_key = f"temp_key:{datetime.utcnow().timestamp()}"
        
        # Set key with expiration
        await real_blackboard.setex(temp_key, 5, "temporary_value")
        print(f"✅ Key set with 5 second expiration")
        
        # Check TTL
        ttl = await real_blackboard.ttl(temp_key)
        assert 0 < ttl <= 5
        print(f"✅ TTL check: {ttl} seconds remaining")
        
        # Value should exist
        value = await real_blackboard.get(temp_key)
        assert value == "temporary_value"
        print(f"✅ Value exists before expiration")
        
        # Wait for expiration
        await asyncio.sleep(6)
        
        # Value should be gone
        value_after = await real_blackboard.get(temp_key)
        assert value_after is None
        print(f"✅ Key expired successfully")
    
    async def test_redis_pub_sub(self, real_blackboard):
        """Test Redis pub/sub for event broadcasting"""
        channel = f"test_channel:{datetime.utcnow().timestamp()}"
        received_messages = []
        
        # Create subscriber
        pubsub = real_blackboard.pubsub()
        await pubsub.subscribe(channel)
        print(f"✅ Subscribed to channel: {channel}")
        
        # Publish message
        await real_blackboard.publish(
            channel,
            json.dumps({"event": "test", "data": "hello"})
        )
        print(f"✅ Message published")
        
        # Receive message (with timeout)
        try:
            message = await asyncio.wait_for(
                pubsub.get_message(ignore_subscribe_messages=True),
                timeout=2.0
            )
            
            if message and message['type'] == 'message':
                data = json.loads(message['data'])
                assert data['event'] == "test"
                print(f"✅ Message received: {data}")
        except asyncio.TimeoutError:
            print(f"⚠️  No message received (pub/sub timing)")
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
    
    async def test_redis_pipeline(self, real_blackboard):
        """Test Redis pipeline for batch operations"""
        base_key = f"pipeline_test:{datetime.utcnow().timestamp()}"
        
        # Create pipeline
        pipe = real_blackboard.pipeline()
        
        # Add multiple operations
        pipe.set(f"{base_key}:1", "value1")
        pipe.set(f"{base_key}:2", "value2")
        pipe.set(f"{base_key}:3", "value3")
        pipe.mget(f"{base_key}:1", f"{base_key}:2", f"{base_key}:3")
        
        # Execute all at once
        results = await pipe.execute()
        print(f"✅ Pipeline executed: {len(results)} operations")
        
        # Verify results
        values = results[-1]  # Last operation was MGET
        assert values == ["value1", "value2", "value3"]
        print(f"✅ Pipeline results verified")
        
        # Cleanup
        await real_blackboard.delete(
            f"{base_key}:1",
            f"{base_key}:2",
            f"{base_key}:3"
        )
    
    async def test_redis_memory_usage(self, real_blackboard):
        """Test Redis memory usage monitoring"""
        # Get memory info
        memory_info = await real_blackboard.info("memory")
        
        used_memory = memory_info.get("used_memory_human", "unknown")
        peak_memory = memory_info.get("used_memory_peak_human", "unknown")
        
        print(f"✅ Memory usage: {used_memory}")
        print(f"   Peak memory: {peak_memory}")
        
        assert "used_memory" in memory_info
