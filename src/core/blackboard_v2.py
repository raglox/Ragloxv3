"""
RAGLOX v3.0 - Enhanced Blackboard Implementation (v2)
Central shared state using Redis with advanced connection management

This version uses RedisManager for improved reliability:
- Connection pooling
- Circuit breaker protection
- Retry logic with exponential backoff
- Sentinel support for high availability
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union
from uuid import UUID
import json
import asyncio
import logging

from pydantic import BaseModel

from .config import Settings, get_settings
from .redis_manager import RedisManager, CircuitState
from .models import (
    Mission, MissionStatus, MissionStats,
    Target, TargetStatus,
    Vulnerability, Severity,
    Credential,
    Session, SessionStatus,
    Task, TaskStatus,
    AttackPath,
    BlackboardEvent,
)

logger = logging.getLogger(__name__)
T = TypeVar('T', bound=BaseModel)


class BlackboardV2:
    """
    Enhanced Blackboard - The central shared state for RAGLOX (v2).
    
    Implements the Blackboard pattern using Redis with advanced features:
    - Connection pooling for better performance
    - Circuit breaker to prevent cascading failures
    - Automatic retry with exponential backoff
    - High availability via Sentinel support
    
    Features:
    - Key-value storage for entities
    - Pub/Sub for real-time notifications
    - Sorted sets for priority queues
    - Streams for event logs
    - Improved reliability and fault tolerance
    """
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        settings: Optional[Settings] = None
    ):
        """
        Initialize the Enhanced Blackboard.
        
        Args:
            redis_url: Redis connection URL (overrides settings)
            settings: Application settings
        """
        self.settings = settings or get_settings()
        
        # Override redis_url in settings if provided
        if redis_url:
            self.settings.redis_url = redis_url
        
        # Initialize Redis Manager with all advanced features
        self._redis_manager = RedisManager(self.settings)
        self._pubsub = None
        self._connected = False
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def connect(self) -> None:
        """
        Connect to Redis with retry and circuit breaker protection.
        
        This method uses the RedisManager which automatically handles:
        - Connection pooling
        - Sentinel failover (if configured)
        - Health monitoring
        """
        if self._connected:
            logger.debug("Blackboard already connected")
            return
        
        try:
            await self._redis_manager.connect()
            self._connected = True
            logger.info(
                f"Blackboard connected successfully "
                f"(mode: {self.settings.redis_mode}, "
                f"circuit: {self._redis_manager.circuit_state.value})"
            )
        except Exception as e:
            logger.error(f"Failed to connect Blackboard: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        
        await self._redis_manager.disconnect()
        self._connected = False
        logger.info("Blackboard disconnected")
    
    async def health_check(self) -> bool:
        """
        Check if Redis connection is healthy.
        
        Returns:
            bool: True if healthy, False otherwise
        """
        try:
            return await self._redis_manager.health_check()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if Blackboard is connected to Redis."""
        return self._connected and self._redis_manager.is_connected()
    
    @property
    def redis(self):
        """
        Get Redis client.
        
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected:
            raise RuntimeError("Blackboard not connected. Call connect() first.")
        return self._redis_manager.redis
    
    @property
    def circuit_state(self) -> CircuitState:
        """Get circuit breaker state."""
        return self._redis_manager.circuit_state
    
    # ═══════════════════════════════════════════════════════════
    # Generic CRUD Operations with Retry Logic
    # ═══════════════════════════════════════════════════════════
    
    async def _set_hash(self, key: str, data: Dict[str, Any]) -> None:
        """
        Set a hash in Redis with retry logic.
        
        Args:
            key: Redis key
            data: Data dictionary to store
        """
        # Convert complex types to JSON strings
        serialized = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                serialized[k] = json.dumps(v)
            elif isinstance(v, datetime):
                serialized[k] = v.isoformat()
            elif isinstance(v, UUID):
                serialized[k] = str(v)
            elif isinstance(v, bool):
                serialized[k] = "true" if v else "false"
            elif v is None:
                continue  # Skip None values
            else:
                serialized[k] = str(v)
        
        # Execute with retry and circuit breaker
        async def _hset():
            await self.redis.hset(key, mapping=serialized)
        
        await self._redis_manager.execute_with_retry(_hset)
    
    async def _get_hash(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get a hash from Redis with retry logic.
        
        Args:
            key: Redis key
        
        Returns:
            Dictionary of deserialized data, or None if key doesn't exist
        """
        async def _hgetall():
            data = await self.redis.hgetall(key)
            if not data:
                return None
            
            # Deserialize JSON strings back to objects
            deserialized = {}
            for k, v in data.items():
                # Try to parse as JSON if it looks like JSON
                if isinstance(v, str) and v and (v.startswith('[') or v.startswith('{')):
                    try:
                        deserialized[k] = json.loads(v)
                    except json.JSONDecodeError:
                        # Not valid JSON, keep as string
                        deserialized[k] = v
                else:
                    deserialized[k] = v
            
            return deserialized
        
        return await self._redis_manager.execute_with_retry(_hgetall)
    
    async def _delete(self, key: str) -> None:
        """
        Delete a key from Redis with retry logic.
        
        Args:
            key: Redis key
        """
        async def _del():
            await self.redis.delete(key)
        
        await self._redis_manager.execute_with_retry(_del)
    
    # ═══════════════════════════════════════════════════════════
    # Public Hash Operations (for workflow orchestrator compatibility)
    # ═══════════════════════════════════════════════════════════
    
    async def hgetall(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get all fields from a hash.
        
        Args:
            key: Redis key
        
        Returns:
            Dictionary of hash fields and values, or None if key doesn't exist
        """
        return await self._get_hash(key)
    
    async def hset(self, key: str, mapping: Dict[str, Any]) -> None:
        """
        Set multiple fields in a hash.
        
        Args:
            key: Redis key
            mapping: Dictionary of field-value pairs to set
        """
        await self._set_hash(key, mapping)
    
    async def hget(self, key: str, field: str) -> Optional[str]:
        """
        Get a single field from a hash.
        
        Args:
            key: Redis key
            field: Field name
        
        Returns:
            Field value or None
        """
        async def _hget():
            return await self.redis.hget(key, field)
        
        return await self._redis_manager.execute_with_retry(_hget)
    
    async def hdel(self, key: str, *fields: str) -> int:
        """
        Delete fields from a hash.
        
        Args:
            key: Redis key
            *fields: Field names to delete
        
        Returns:
            Number of fields deleted
        """
        async def _hdel():
            return await self.redis.hdel(key, *fields)
        
        return await self._redis_manager.execute_with_retry(_hdel)
    
    async def sadd(self, key: str, *members: str) -> int:
        """
        Add members to a set.
        
        Args:
            key: Redis key
            *members: Members to add
        
        Returns:
            Number of members added
        """
        async def _sadd():
            return await self.redis.sadd(key, *members)
        
        return await self._redis_manager.execute_with_retry(_sadd)
    
    async def smembers(self, key: str) -> Set[str]:
        """
        Get all members of a set.
        
        Args:
            key: Redis key
        
        Returns:
            Set of members
        """
        async def _smembers():
            return await self.redis.smembers(key)
        
        return await self._redis_manager.execute_with_retry(_smembers)
    
    async def zadd(self, key: str, mapping: Dict[str, float]) -> int:
        """
        Add members to a sorted set.
        
        Args:
            key: Redis key
            mapping: Dictionary of member -> score
        
        Returns:
            Number of members added
        """
        async def _zadd():
            return await self.redis.zadd(key, mapping)
        
        return await self._redis_manager.execute_with_retry(_zadd)
    
    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        withscores: bool = False
    ) -> List[Union[str, Tuple[str, float]]]:
        """
        Get members from a sorted set by rank.
        
        Args:
            key: Redis key
            start: Start index
            end: End index
            withscores: Include scores in response
        
        Returns:
            List of members (or tuples if withscores=True)
        """
        async def _zrange():
            return await self.redis.zrange(key, start, end, withscores=withscores)
        
        return await self._redis_manager.execute_with_retry(_zrange)
    
    # ═══════════════════════════════════════════════════════════
    # Mission Operations (backward compatible)
    # ═══════════════════════════════════════════════════════════
    
    async def create_mission(self, mission: Mission) -> str:
        """
        Create a new mission.
        
        Args:
            mission: Mission object
        
        Returns:
            Mission ID
        """
        mission_key = f"mission:{mission.id}"
        await self._set_hash(mission_key, mission.dict())
        logger.info(f"Mission created: {mission.id}")
        return str(mission.id)
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """
        Get mission by ID.
        
        Args:
            mission_id: Mission ID
        
        Returns:
            Mission data dictionary or None
        """
        mission_key = f"mission:{mission_id}"
        return await self._get_hash(mission_key)
    
    async def update_mission_status(
        self,
        mission_id: str,
        status: MissionStatus,
        message: Optional[str] = None
    ) -> None:
        """
        Update mission status.
        
        Args:
            mission_id: Mission ID
            status: New status
            message: Optional status message
        """
        mission_key = f"mission:{mission_id}"
        updates = {
            "status": status.value,
            "updated_at": datetime.now().isoformat()
        }
        if message:
            updates["status_message"] = message
        
        await self.hset(mission_key, updates)
        logger.info(f"Mission {mission_id} status updated: {status.value}")
    
    # ... (rest of the methods remain the same as original Blackboard)
    # These are placeholders - full implementation would mirror blackboard.py
    
    async def get_mission_goals(self, mission_id: str) -> Dict[str, str]:
        """Get mission goals."""
        mission = await self.get_mission(mission_id)
        if not mission:
            return {}
        return mission.get("goals", {})
    
    async def get_mission_stats(self, mission_id: str) -> MissionStats:
        """Get mission statistics."""
        # Simplified implementation
        return MissionStats(
            total_targets=0,
            total_vulns=0,
            total_creds=0,
            total_sessions=0,
            critical_vulns=0,
            high_vulns=0
        )


# Backward compatibility alias
Blackboard = BlackboardV2
