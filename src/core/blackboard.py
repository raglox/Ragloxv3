# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Blackboard Implementation (Enhanced with RedisManager)
# Central shared state using Redis with production-grade reliability
# ═══════════════════════════════════════════════════════════════

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type, TypeVar, Union
from uuid import UUID
import json
import asyncio
import logging

import redis.asyncio as aioredis
from pydantic import BaseModel

from .config import Settings, get_settings
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

# Import RedisManager for production reliability
try:
    from .redis_manager import RedisManager
    REDIS_MANAGER_AVAILABLE = True
except ImportError:
    REDIS_MANAGER_AVAILABLE = False
    logging.warning("RedisManager not available, using basic Redis connection")

T = TypeVar('T', bound=BaseModel)
logger = logging.getLogger(__name__)


class Blackboard:
    """
    Blackboard - The central shared state for RAGLOX.
    
    Implements the Blackboard pattern using Redis as the backing store.
    All specialists read from and write to this shared state.
    
    Enhanced with RedisManager for production reliability:
    - Connection pooling for better performance
    - Circuit breaker to prevent cascading failures
    - Automatic retry with exponential backoff
    - High availability via Sentinel support
    
    Features:
    - Key-value storage for entities
    - Pub/Sub for real-time notifications
    - Sorted sets for priority queues
    - Streams for event logs
    """
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        settings: Optional[Settings] = None,
        use_redis_manager: bool = True  # Use enhanced RedisManager by default
    ):
        """
        Initialize the Blackboard.
        
        Args:
            redis_url: Redis connection URL (overrides settings)
            settings: Application settings
            use_redis_manager: Use RedisManager for enhanced reliability (default: True)
        """
        self.settings = settings or get_settings()
        self.redis_url = redis_url or self.settings.redis_url
        self._redis: Optional[aioredis.Redis] = None
        self._redis_manager: Optional[RedisManager] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None
        self._connected = False
        self._use_redis_manager = use_redis_manager and REDIS_MANAGER_AVAILABLE
        
        if self._use_redis_manager:
            logger.info("Blackboard initialized with RedisManager (production mode)")
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def connect(self) -> None:
        """Connect to Redis (with RedisManager if available)."""
        if self._connected:
            return
        
        if self._use_redis_manager:
            # Use RedisManager for production reliability
            self._redis_manager = RedisManager(settings=self.settings)
            await self._redis_manager.connect()
            self._redis = self._redis_manager.redis  # Use property, not method
            logger.info("Blackboard connected via RedisManager (pooled connection)")
        else:
            # Fallback to basic Redis connection
            self._redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=self.settings.redis_max_connections,
            )
            logger.info("Blackboard connected via basic Redis")
        
        self._connected = True
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._pubsub:
            await self._pubsub.close()
            self._pubsub = None
        
        if self._use_redis_manager and self._redis_manager:
            await self._redis_manager.disconnect()
            self._redis_manager = None
            logger.info("Blackboard disconnected from RedisManager")
        elif self._redis:
            await self._redis.close()
            logger.info("Blackboard disconnected from Redis")
        
        self._redis = None
        self._connected = False
    
    async def health_check(self) -> bool:
        """Check if Redis connection is healthy."""
        if not self._redis:
            return False
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False
    
    def is_connected(self) -> bool:
        """Check if Blackboard is connected to Redis."""
        return self._connected
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis client (raises if not connected)."""
        if not self._redis:
            raise RuntimeError("Blackboard not connected. Call connect() first.")
        return self._redis
    
    # ═══════════════════════════════════════════════════════════
    # Generic CRUD Operations
    # ═══════════════════════════════════════════════════════════
    
    async def _set_hash(self, key: str, data: Dict[str, Any]) -> None:
        """Set a hash in Redis."""
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
        
        await self.redis.hset(key, mapping=serialized)
    
    async def _get_hash(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get a hash from Redis and deserialize JSON fields.
        
        This method properly deserializes complex fields (lists, dicts) that were
        JSON-serialized during _set_hash(). This ensures that when AttackSpecialist
        retrieves a Vulnerability, fields like rx_modules and metadata are proper
        Python objects, not JSON strings.
        """
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
    
    async def _delete(self, key: str) -> None:
        """Delete a key from Redis."""
        await self.redis.delete(key)
    
    # ═══════════════════════════════════════════════════════════
    # Public Hash Operations (for workflow orchestrator compatibility)
    # ═══════════════════════════════════════════════════════════
    
    async def hgetall(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get all fields from a hash (public wrapper for _get_hash).
        
        This method is used by WorkflowOrchestrator and other components
        that need direct hash access.
        
        Args:
            key: Redis key
            
        Returns:
            Dictionary of hash fields and values, or None if key doesn't exist
        """
        return await self._get_hash(key)
    
    async def hset(self, key: str, mapping: Dict[str, Any]) -> None:
        """
        Set multiple fields in a hash (public wrapper for _set_hash).
        
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
        return await self.redis.hget(key, field)
    
    # ═══════════════════════════════════════════════════════════
    # Mission Operations
    # ═══════════════════════════════════════════════════════════
    
    async def create_mission(self, mission: Mission) -> str:
        """
        Create a new mission.
        
        Args:
            mission: Mission object to create
            
        Returns:
            Mission ID
        """
        mission_id = str(mission.id)
        
        # Store mission info
        await self._set_hash(f"mission:{mission_id}:info", mission.model_dump())
        
        # Initialize goals
        goals = {goal: "pending" for goal in mission.goals.keys()}
        if goals:
            await self.redis.hset(f"mission:{mission_id}:goals", mapping=goals)
        
        # Initialize stats
        await self.redis.hset(f"mission:{mission_id}:stats", mapping={
            "targets_discovered": 0,
            "vulns_found": 0,
            "creds_harvested": 0,
            "sessions_established": 0,
            "goals_achieved": 0,
        })
        
        return mission_id
    
    async def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get mission by ID."""
        return await self._get_hash(f"mission:{mission_id}:info")
    
    async def update_mission_status(
        self,
        mission_id: str,
        status: MissionStatus
    ) -> None:
        """Update mission status."""
        await self.redis.hset(f"mission:{mission_id}:info", "status", status.value)
        
        if status == MissionStatus.RUNNING:
            await self.redis.hset(
                f"mission:{mission_id}:info",
                "started_at",
                datetime.utcnow().isoformat()
            )
        elif status in (MissionStatus.COMPLETED, MissionStatus.FAILED):
            await self.redis.hset(
                f"mission:{mission_id}:info",
                "completed_at",
                datetime.utcnow().isoformat()
            )
    
    async def get_mission_goals(self, mission_id: str) -> Dict[str, str]:
        """Get mission goals and their status."""
        return await self.redis.hgetall(f"mission:{mission_id}:goals") or {}
    
    async def update_goal_status(
        self,
        mission_id: str,
        goal: str,
        status: str
    ) -> None:
        """Update a goal's status."""
        await self.redis.hset(f"mission:{mission_id}:goals", goal, status)
        
        if status == "achieved":
            await self.redis.hincrby(f"mission:{mission_id}:stats", "goals_achieved", 1)
    
    async def get_mission_stats(self, mission_id: str) -> MissionStats:
        """Get mission statistics."""
        stats = await self.redis.hgetall(f"mission:{mission_id}:stats")
        if not stats:
            return MissionStats()
        
        return MissionStats(
            targets_discovered=int(stats.get("targets_discovered", 0)),
            vulns_found=int(stats.get("vulns_found", 0)),
            creds_harvested=int(stats.get("creds_harvested", 0)),
            sessions_established=int(stats.get("sessions_established", 0)),
            goals_achieved=int(stats.get("goals_achieved", 0)),
        )
    
    # ═══════════════════════════════════════════════════════════
    # Metadata Operations
    # ═══════════════════════════════════════════════════════════
    
    async def store_metadata(
        self,
        mission_id: str,
        key: str,
        value: Union[Dict[str, Any], str, int, float, bool]
    ) -> None:
        """
        Store mission metadata in Redis.
        
        Args:
            mission_id: Mission identifier
            key: Metadata key (e.g., 'intelligence', 'config', 'state')
            value: Metadata value (dict, string, number, or boolean)
            
        Usage:
            # Store intelligence data
            await blackboard.store_metadata(
                mission_id="mission-123",
                key="intelligence",
                value=intel.to_dict()
            )
            
            # Store simple config
            await blackboard.store_metadata(
                mission_id="mission-123",
                key="stealth_mode",
                value=True
            )
        """
        # Serialize value if it's a dict or complex type
        if isinstance(value, dict):
            serialized = json.dumps(value)
        elif isinstance(value, (list, tuple)):
            serialized = json.dumps(value)
        else:
            serialized = str(value)
        
        await self.redis.hset(
            f"mission:{mission_id}:metadata",
            key,
            serialized
        )
    
    async def get_metadata(
        self,
        mission_id: str,
        key: str,
        default: Optional[Any] = None
    ) -> Optional[Any]:
        """
        Retrieve mission metadata from Redis.
        
        Args:
            mission_id: Mission identifier
            key: Metadata key
            default: Default value if key not found
            
        Returns:
            Metadata value (parsed from JSON if applicable) or default
            
        Usage:
            # Get intelligence data
            intel_dict = await blackboard.get_metadata(
                mission_id="mission-123",
                key="intelligence"
            )
            
            # Get with default
            stealth = await blackboard.get_metadata(
                mission_id="mission-123",
                key="stealth_mode",
                default=False
            )
        """
        data = await self.redis.hget(
            f"mission:{mission_id}:metadata",
            key
        )
        
        if data is None:
            return default
        
        # Try to parse as JSON
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            # Return as string if not JSON
            return data
    
    async def get_all_metadata(
        self,
        mission_id: str
    ) -> Dict[str, Any]:
        """
        Get all metadata for a mission.
        
        Args:
            mission_id: Mission identifier
            
        Returns:
            Dictionary of all metadata key-value pairs
            
        Usage:
            all_meta = await blackboard.get_all_metadata("mission-123")
        """
        data = await self.redis.hgetall(f"mission:{mission_id}:metadata")
        
        if not data:
            return {}
        
        # Parse JSON values where possible
        result = {}
        for key, value in data.items():
            try:
                result[key] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                result[key] = value
        
        return result
    
    async def delete_metadata(
        self,
        mission_id: str,
        key: str
    ) -> bool:
        """
        Delete a specific metadata key.
        
        Args:
            mission_id: Mission identifier
            key: Metadata key to delete
            
        Returns:
            True if key was deleted, False if it didn't exist
        """
        result = await self.redis.hdel(
            f"mission:{mission_id}:metadata",
            key
        )
        return result > 0
    
    # ═══════════════════════════════════════════════════════════
    # Target Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_target(self, target: Target) -> str:
        """Add a new target."""
        target_id = str(target.id)
        mission_id = str(target.mission_id)
        
        # Store target
        await self._set_hash(f"target:{target_id}", target.model_dump())
        
        # Add to mission's target set
        await self.redis.sadd(f"mission:{mission_id}:targets", f"target:{target_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "targets_discovered", 1)
        
        return target_id
    
    async def create_target(
        self,
        mission_id: str,
        target_id: str,
        ip: str,
        hostname: Optional[str] = None,
        os: Optional[str] = None,
        status: str = "discovered",
        ports: Optional[List[int]] = None,
        services: Optional[List[str]] = None,
        **kwargs
    ) -> str:
        """
        Create and add a target using named parameters (convenience method).
        
        This is a helper method for tests and dynamic target creation
        that don't have a full Target object ready.
        
        Args:
            mission_id: Mission ID
            target_id: Target identifier
            ip: IP address
            hostname: Optional hostname
            os: Optional OS information
            status: Target status (default: "discovered")
            ports: Optional list of ports
            services: Optional list of services
            **kwargs: Additional target fields
            
        Returns:
            Target ID
            
        Example:
            target_id = await bb.create_target(
                mission_id="mission_123",
                target_id="target_1",
                ip="192.168.1.10",
                hostname="web-server",
                status="scanned",
                ports=[22, 80, 443]
            )
        """
        from uuid import UUID
        from .models import Target, TargetStatus
        
        # Convert status string to enum if needed
        if isinstance(status, str):
            status_enum = TargetStatus[status.upper()] if hasattr(TargetStatus, status.upper()) else TargetStatus.DISCOVERED
        else:
            status_enum = status
        
        # Create Target object
        target = Target(
            id=UUID(target_id) if len(target_id) == 36 else UUID(int=hash(target_id) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
            mission_id=UUID(mission_id) if len(mission_id) == 36 else UUID(int=hash(mission_id) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
            ip=ip,
            hostname=hostname,
            os=os,
            status=status_enum,
            ports={port: "" for port in (ports or [])},
            **kwargs
        )
        
        return await self.add_target(target)
    
    async def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get target by ID."""
        return await self._get_hash(f"target:{target_id}")
    
    async def get_mission_targets(self, mission_id: str) -> List[str]:
        """Get all target IDs for a mission."""
        targets = await self.redis.smembers(f"mission:{mission_id}:targets")
        return list(targets) if targets else []
    
    async def update_target_status(
        self,
        target_id: str,
        status: TargetStatus
    ) -> None:
        """Update target status."""
        await self.redis.hset(f"target:{target_id}", "status", status.value)
    
    async def add_target_ports(
        self,
        target_id: str,
        ports: Dict[int, str]
    ) -> None:
        """Add ports to a target."""
        if ports:
            mapping = {str(port): info for port, info in ports.items()}
            await self.redis.hset(f"target:{target_id}:ports", mapping=mapping)
    
    async def get_target_ports(self, target_id: str) -> Dict[str, str]:
        """Get target ports."""
        return await self.redis.hgetall(f"target:{target_id}:ports") or {}
    
    # ═══════════════════════════════════════════════════════════
    # Vulnerability Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_vulnerability(self, vuln: Vulnerability) -> str:
        """Add a new vulnerability."""
        vuln_id = str(vuln.id)
        mission_id = str(vuln.mission_id)
        
        # Store vulnerability
        await self._set_hash(f"vuln:{vuln_id}", vuln.model_dump())
        
        # Add to sorted set by CVSS score
        score = vuln.cvss if vuln.cvss else self._severity_to_score(vuln.severity)
        await self.redis.zadd(f"mission:{mission_id}:vulns", {f"vuln:{vuln_id}": score})
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "vulns_found", 1)
        
        return vuln_id
    
    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to numeric score."""
        mapping = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }
        return mapping.get(severity, 5.0)
    
    async def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerability by ID."""
        return await self._get_hash(f"vuln:{vuln_id}")
    
    async def get_mission_vulns(
        self,
        mission_id: str,
        limit: int = 100
    ) -> List[str]:
        """Get vulnerability IDs for a mission, sorted by severity."""
        vulns = await self.redis.zrevrange(
            f"mission:{mission_id}:vulns",
            0,
            limit - 1
        )
        return list(vulns) if vulns else []
    
    async def update_vuln_status(self, vuln_id: str, status: str) -> None:
        """Update vulnerability status."""
        await self.redis.hset(f"vuln:{vuln_id}", "status", status)
    
    # ═══════════════════════════════════════════════════════════
    # Credential Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_credential(self, cred: Credential) -> str:
        """Add a new credential."""
        cred_id = str(cred.id)
        mission_id = str(cred.mission_id)
        
        # Store credential
        await self._set_hash(f"cred:{cred_id}", cred.model_dump())
        
        # Add to mission's credential set
        await self.redis.sadd(f"mission:{mission_id}:creds", f"cred:{cred_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "creds_harvested", 1)
        
        return cred_id
    
    async def get_credential(self, cred_id: str) -> Optional[Dict[str, Any]]:
        """Get credential by ID."""
        return await self._get_hash(f"cred:{cred_id}")
    
    async def get_mission_creds(self, mission_id: str) -> List[str]:
        """Get all credential IDs for a mission."""
        creds = await self.redis.smembers(f"mission:{mission_id}:creds")
        return list(creds) if creds else []
    
    # ═══════════════════════════════════════════════════════════
    # Session Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_session(self, session: Session) -> str:
        """Add a new session."""
        session_id = str(session.id)
        mission_id = str(session.mission_id)
        
        # Store session
        await self._set_hash(f"session:{session_id}", session.model_dump())
        
        # Add to mission's session set
        await self.redis.sadd(f"mission:{mission_id}:sessions", f"session:{session_id}")
        
        # Update stats
        await self.redis.hincrby(f"mission:{mission_id}:stats", "sessions_established", 1)
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by ID."""
        return await self._get_hash(f"session:{session_id}")
    
    async def get_mission_sessions(self, mission_id: str) -> List[str]:
        """Get all session IDs for a mission."""
        sessions = await self.redis.smembers(f"mission:{mission_id}:sessions")
        return list(sessions) if sessions else []
    
    async def update_session_status(
        self,
        session_id: str,
        status: SessionStatus
    ) -> None:
        """Update session status."""
        await self.redis.hset(f"session:{session_id}", "status", status.value)
        await self.redis.hset(
            f"session:{session_id}",
            "last_activity",
            datetime.utcnow().isoformat()
        )
    
    # ═══════════════════════════════════════════════════════════
    # Task Operations
    # ═══════════════════════════════════════════════════════════
    
    async def add_task(self, task: Task) -> str:
        """Add a new task to the pending queue."""
        task_id = str(task.id)
        mission_id = str(task.mission_id)
        
        # Store task
        await self._set_hash(f"task:{task_id}", task.model_dump())
        
        # Add to pending queue (sorted by priority)
        await self.redis.zadd(
            f"mission:{mission_id}:tasks:pending",
            {f"task:{task_id}": task.priority}
        )
        
        return task_id
    
    async def create_task(
        self,
        mission_id: str,
        task_type: str,
        assigned_to: str,
        priority: Union[int, str] = 5,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> str:
        """
        Create and add a task using named parameters (convenience method).
        
        Helper method for tests and dynamic task creation.
        
        Args:
            mission_id: Mission ID
            task_type: Type of task (from TaskType enum or string)
            assigned_to: Specialist type assigned to this task (string or SpecialistType)
            priority: Task priority (1-10 int, or string like "high")
            params: Task parameters
            **kwargs: Additional task fields
            
        Returns:
            Task ID
            
        Example:
            task_id = await bb.create_task(
                mission_id="mission_123",
                task_type="network_scan",
                assigned_to="recon",
                priority=8,
                params={"target": "192.168.1.0/24"}
            )
        """
        from uuid import uuid4
        from .models import Task, TaskStatus, TaskType, SpecialistType
        
        # Convert priority string to int if needed
        if isinstance(priority, str):
            priority_map = {"critical": 10, "high": 8, "medium": 5, "low": 3}
            priority = priority_map.get(priority.lower(), 5)
        
        # Convert task_type string to TaskType if needed
        if isinstance(task_type, str):
            try:
                task_type = TaskType[task_type.upper()] if hasattr(TaskType, task_type.upper()) else TaskType(task_type)
            except:
                pass  # Keep as string if conversion fails
        
        # Convert assigned_to string to SpecialistType
        if isinstance(assigned_to, str):
            try:
                specialist_type = SpecialistType[assigned_to.upper()] if hasattr(SpecialistType, assigned_to.upper()) else SpecialistType(assigned_to)
            except:
                specialist_type = SpecialistType.RECON  # Fallback
        else:
            specialist_type = assigned_to
        
        # Create Task object
        task = Task(
            id=uuid4(),
            mission_id=UUID(mission_id) if len(mission_id) == 36 else UUID(int=hash(mission_id) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
            type=task_type,
            specialist=specialist_type,
            assigned_to=str(specialist_type.value) if hasattr(specialist_type, 'value') else assigned_to,
            priority=priority,
            status=TaskStatus.PENDING,
            params=params or {},
            **kwargs
        )
        
        return await self.add_task(task)
    
    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID."""
        return await self._get_hash(f"task:{task_id}")
    
    async def update_task(
        self,
        mission_id: str,
        task_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        result: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        """
        Update task fields (convenience method for tests).
        
        Automatically handles task lifecycle transitions:
        - PENDING → RUNNING: moves to running queue
        - RUNNING → COMPLETED: moves to completed queue
        - RUNNING → FAILED: moves to failed tracking
        
        Args:
            mission_id: Mission ID
            task_id: Task ID
            status: Optional task status
            progress: Optional progress (0-100)
            result: Optional result data
            **kwargs: Additional fields to update
        """
        from .models import TaskStatus as TS
        
        task_key = f"task:{task_id}"
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        updates = {}
        if status is not None:
            updates["status"] = status
        if progress is not None:
            updates["progress"] = progress
        if result is not None:
            updates["result"] = json.dumps(result)
        updates.update(kwargs)
        
        # Apply updates
        if updates:
            await self.redis.hset(task_key, mapping=updates)
        
        # Handle queue transitions if status changed
        if status:
            status_upper = status.upper() if isinstance(status, str) else status
            
            # PENDING → RUNNING
            if status_upper in ["RUNNING", TS.RUNNING.value.upper()]:
                await self.redis.zrem(pending_key, task_key)
                await self.redis.sadd(running_key, task_key)
                if "started_at" not in updates:
                    await self.redis.hset(task_key, "started_at", datetime.utcnow().isoformat())
            
            # RUNNING → COMPLETED
            elif status_upper in ["COMPLETED", TS.COMPLETED.value.upper()]:
                await self.redis.srem(running_key, task_key)
                await self.redis.lpush(completed_key, task_key)
                if "completed_at" not in updates:
                    await self.redis.hset(task_key, "completed_at", datetime.utcnow().isoformat())
            
            # RUNNING → FAILED
            elif status_upper in ["FAILED", TS.FAILED.value.upper()]:
                await self.redis.srem(running_key, task_key)
                # Could add to failed queue if needed
                if "completed_at" not in updates:
                    await self.redis.hset(task_key, "completed_at", datetime.utcnow().isoformat())
    
    # ═══════════════════════════════════════════════════════════
    # Lua Scripts for Atomic Operations
    # ═══════════════════════════════════════════════════════════
    
    # Lua script for atomic task claiming
    # This ensures that read + check + move + update is done atomically
    CLAIM_TASK_LUA = """
    local pending_key = KEYS[1]
    local running_key = KEYS[2]
    local specialist = ARGV[1]
    local worker_id = ARGV[2]
    local started_at = ARGV[3]
    local running_status = ARGV[4]
    
    -- Get all pending tasks sorted by priority (highest first)
    local tasks = redis.call('ZREVRANGE', pending_key, 0, -1)
    
    for i, task_key in ipairs(tasks) do
        -- Get task specialist type
        local task_specialist = redis.call('HGET', task_key, 'specialist')
        
        if task_specialist == specialist then
            -- Atomically move from pending to running
            redis.call('ZREM', pending_key, task_key)
            redis.call('SADD', running_key, task_key)
            
            -- Update task status, assignment, and timestamp
            redis.call('HSET', task_key, 
                'status', running_status,
                'assigned_to', worker_id,
                'started_at', started_at,
                'updated_at', started_at
            )
            
            -- Return task key (e.g., "task:uuid")
            return task_key
        end
    end
    
    -- No matching task found
    return nil
    """
    
    async def claim_task(
        self,
        mission_id: str,
        worker_id: str,
        specialist: str
    ) -> Optional[str]:
        """
        Claim a pending task for a worker atomically.
        
        Uses a Lua script to ensure the entire operation is atomic:
        - Read task from pending queue
        - Check if task matches specialist type
        - Move task from pending to running
        - Update task status and assignment
        
        This prevents race conditions where multiple workers
        could claim the same task.
        
        Args:
            mission_id: Mission ID
            worker_id: Worker ID claiming the task
            specialist: Specialist type
            
        Returns:
            Task ID if claimed, None if no tasks available
        """
        pending_key = f"mission:{mission_id}:tasks:pending"
        running_key = f"mission:{mission_id}:tasks:running"
        started_at = datetime.utcnow().isoformat()
        
        # Execute atomic Lua script
        result = await self.redis.eval(
            self.CLAIM_TASK_LUA,
            2,  # Number of keys
            pending_key,
            running_key,
            specialist,
            worker_id,
            started_at,
            TaskStatus.RUNNING.value
        )
        
        if result:
            # Result is the task key (e.g., "task:uuid")
            task_id = self._extract_task_id(result)
            return task_id
        
        return None
    
    def _extract_task_id(self, task_key: Any) -> str:
        """
        Extract task ID from task key.
        
        Handles both string and bytes types returned by Redis.
        
        Args:
            task_key: Task key from Redis (str or bytes)
            
        Returns:
            Clean task ID without prefix
        """
        if isinstance(task_key, bytes):
            task_key = task_key.decode()
        return task_key.replace("task:", "") if isinstance(task_key, str) else str(task_key)
    
    async def complete_task(
        self,
        mission_id: str,
        task_id: str,
        result: str,
        result_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Mark a task as completed."""
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        # Move from running to completed
        await self.redis.srem(running_key, task_key)
        await self.redis.lpush(completed_key, task_key)
        
        # Update task
        update = {
            "status": TaskStatus.COMPLETED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "result": result,
        }
        if result_data:
            update["result_data"] = json.dumps(result_data)
        
        await self.redis.hset(task_key, mapping=update)
    
    async def fail_task(
        self,
        mission_id: str,
        task_id: str,
        error_message: str
    ) -> None:
        """Mark a task as failed."""
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        # Move from running to completed
        await self.redis.srem(running_key, task_key)
        await self.redis.lpush(completed_key, task_key)
        
        # Update task
        await self.redis.hset(task_key, mapping={
            "status": TaskStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "result": "failure",
            "error_message": error_message,
        })
    
    async def get_pending_tasks(
        self,
        mission_id: str,
        specialist: Optional[str] = None,
        limit: int = 100
    ) -> List[str]:
        """Get pending task IDs."""
        tasks = await self.redis.zrevrange(
            f"mission:{mission_id}:tasks:pending",
            0,
            limit - 1
        )
        
        if not specialist:
            return list(tasks) if tasks else []
        
        # Filter by specialist
        result = []
        for task_key in tasks:
            task = await self._get_hash(task_key)
            if task and task.get("specialist") == specialist:
                result.append(task_key.replace("task:", ""))
        
        return result
    
    async def get_running_tasks(self, mission_id: str) -> List[str]:
        """Get all running task IDs for a mission."""
        running_key = f"mission:{mission_id}:tasks:running"
        tasks = await self.redis.smembers(running_key)
        return list(tasks) if tasks else []
    
    async def get_completed_tasks(self, mission_id: str) -> List[Dict[str, Any]]:
        """
        Get all completed tasks for a mission with their data.
        
        Args:
            mission_id: Mission ID
            
        Returns:
            List of completed task dictionaries
        """
        completed_key = f"mission:{mission_id}:tasks:completed"
        # Use lrange since complete_task uses lpush (list, not set)
        task_keys = await self.redis.lrange(completed_key, 0, -1)
        
        if not task_keys:
            return []
        
        tasks = []
        for task_key in task_keys:
            # task_key is bytes or str like "task:UUID"
            if isinstance(task_key, bytes):
                task_key = task_key.decode('utf-8')
            
            # Extract task_id from "task:UUID" format
            task_id = task_key.replace("task:", "") if task_key.startswith("task:") else task_key
            task_data = await self.get_task(task_id)
            if task_data:
                tasks.append(task_data)
        
        return tasks
    
    async def requeue_task(
        self,
        mission_id: str,
        task_id: str,
        reason: str = "watchdog_timeout"
    ) -> None:
        """
        Re-queue a stale/zombie task back to pending.
        
        Used by the Task Watchdog to recover from stuck tasks.
        
        Args:
            mission_id: Mission ID
            task_id: Task ID to requeue
            reason: Reason for requeuing
        """
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        pending_key = f"mission:{mission_id}:tasks:pending"
        
        # Get current task data
        task = await self._get_hash(task_key)
        if not task:
            return
        
        # Get current retry count
        retry_count = int(task.get("retry_count", 0))
        priority = int(task.get("priority", 5))
        
        # Move from running back to pending
        await self.redis.srem(running_key, task_key)
        await self.redis.zadd(pending_key, {task_key: priority})
        
        # Update task status
        await self.redis.hset(task_key, mapping={
            "status": TaskStatus.PENDING.value,
            "assigned_to": "",
            "retry_count": str(retry_count + 1),
            "last_requeue_reason": reason,
            "updated_at": datetime.utcnow().isoformat(),
        })
    
    async def mark_task_failed_permanently(
        self,
        mission_id: str,
        task_id: str,
        reason: str = "max_retries_exceeded"
    ) -> None:
        """
        Mark a task as permanently failed (no more retries).
        
        Args:
            mission_id: Mission ID
            task_id: Task ID
            reason: Failure reason
        """
        task_key = f"task:{task_id}"
        running_key = f"mission:{mission_id}:tasks:running"
        completed_key = f"mission:{mission_id}:tasks:completed"
        
        # Move from running to completed
        await self.redis.srem(running_key, task_key)
        await self.redis.lpush(completed_key, task_key)
        
        # Update task status
        await self.redis.hset(task_key, mapping={
            "status": TaskStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "result": "failure",
            "error_message": reason,
        })
    
    # ═══════════════════════════════════════════════════════════
    # Pub/Sub Operations
    # ═══════════════════════════════════════════════════════════
    
    async def publish(self, channel: str, event: BlackboardEvent) -> None:
        """Publish an event to a channel."""
        await self.redis.publish(channel, event.model_dump_json())
    
    async def publish_dict(self, channel: str, data: Dict[str, Any]) -> None:
        """Publish a dictionary to a channel."""
        await self.redis.publish(channel, json.dumps(data))
    
    async def subscribe(self, *channels: str) -> aioredis.client.PubSub:
        """Subscribe to channels."""
        if not self._pubsub:
            self._pubsub = self.redis.pubsub()
        
        await self._pubsub.subscribe(*channels)
        return self._pubsub
    
    async def get_message(
        self,
        timeout: float = 1.0
    ) -> Optional[Dict[str, Any]]:
        """Get next message from subscribed channels."""
        if not self._pubsub:
            return None
        
        message = await self._pubsub.get_message(
            ignore_subscribe_messages=True,
            timeout=timeout
        )
        
        if message and message["type"] == "message":
            try:
                return json.loads(message["data"])
            except json.JSONDecodeError:
                return {"raw": message["data"]}
        
        return None
    
    def get_channel(self, mission_id: str, entity: str) -> str:
        """Get the channel name for a mission entity."""
        return f"channel:mission:{mission_id}:{entity}"
    
    # ═══════════════════════════════════════════════════════════
    # Heartbeat Operations
    # ═══════════════════════════════════════════════════════════
    
    async def send_heartbeat(
        self,
        mission_id: str,
        specialist_id: str
    ) -> None:
        """Send a heartbeat from a specialist."""
        await self.redis.hset(
            f"mission:{mission_id}:heartbeats",
            specialist_id,
            datetime.utcnow().isoformat()
        )
    
    async def get_heartbeats(self, mission_id: str) -> Dict[str, str]:
        """Get all heartbeats for a mission."""
        return await self.redis.hgetall(f"mission:{mission_id}:heartbeats") or {}
    
    # ═══════════════════════════════════════════════════════════
    # Results Stream
    # ═══════════════════════════════════════════════════════════
    
    async def log_result(
        self,
        mission_id: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> None:
        """Log a result to the mission's result stream."""
        await self.redis.xadd(
            f"mission:{mission_id}:results",
            {
                "type": event_type,
                "data": json.dumps(data),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    async def get_results(
        self,
        mission_id: str,
        count: int = 100,
        start: str = "-",
        end: str = "+"
    ) -> List[Dict[str, Any]]:
        """Get results from the mission's result stream."""
        results = await self.redis.xrange(
            f"mission:{mission_id}:results",
            min=start,
            max=end,
            count=count
        )
        
        parsed = []
        for entry_id, fields in results:
            parsed.append({
                "id": entry_id,
                "type": fields.get("type"),
                "data": json.loads(fields.get("data", "{}")),
                "timestamp": fields.get("timestamp"),
            })
        
        return parsed
    
    # ═══════════════════════════════════════════════════════════════
    # Event Management (for Phase 5 Adaptation & Monitoring)
    # ═══════════════════════════════════════════════════════════════
    
    async def add_event(
        self,
        mission_id: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> str:
        """
        Add a mission event for real-time monitoring and adaptation.
        
        Events are used by Phase 5 advanced features for:
        - Real-time risk monitoring
        - Adaptive strategy adjustment
        - Detection alerts and response
        - Mission timeline tracking
        
        Args:
            mission_id: Mission ID
            event_type: Type of event (detection_alert, target_discovered, etc.)
            data: Event data payload
            
        Returns:
            Event ID (Redis stream entry ID)
            
        Example:
            event_id = await bb.add_event(
                mission_id="mission_123",
                event_type="detection_alert",
                data={
                    "severity": "high",
                    "source": "ids",
                    "message": "Suspicious activity detected"
                }
            )
        """
        event_id = await self.redis.xadd(
            f"mission:{mission_id}:events",
            {
                "type": event_type,
                "data": json.dumps(data),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        
        # Also publish to pub/sub for real-time subscribers
        await self.publish_dict(
            f"mission:{mission_id}:events",
            {
                "event_id": event_id,
                "type": event_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        return event_id
    
    async def get_events(
        self,
        mission_id: str,
        event_type: Optional[str] = None,
        count: int = 100,
        start: str = "-",
        end: str = "+"
    ) -> List[Dict[str, Any]]:
        """
        Get events from mission event stream.
        
        Args:
            mission_id: Mission ID
            event_type: Optional filter by event type
            count: Maximum number of events to return
            start: Start ID for range query
            end: End ID for range query
            
        Returns:
            List of events with metadata
        """
        events = await self.redis.xrange(
            f"mission:{mission_id}:events",
            min=start,
            max=end,
            count=count
        )
        
        parsed = []
        for entry_id, fields in events:
            event = {
                "id": entry_id,
                "type": fields.get("type"),
                "data": json.loads(fields.get("data", "{}")),
                "timestamp": fields.get("timestamp"),
            }
            
            # Filter by event type if specified
            if event_type is None or event["type"] == event_type:
                parsed.append(event)
        
        return parsed
    
    async def get_event_count(
        self,
        mission_id: str,
        event_type: Optional[str] = None
    ) -> int:
        """
        Get count of events for a mission.
        
        Args:
            mission_id: Mission ID
            event_type: Optional filter by event type
            
        Returns:
            Event count
        """
        events = await self.get_events(mission_id, event_type=event_type)
        return len(events)
