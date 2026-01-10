"""
RAGLOX v3.0 - Advanced Redis Connection Manager
Implements connection pooling, circuit breaker, retry logic, and Sentinel support
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import random

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel

from .config import Settings

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation for Redis connections.
    
    Prevents cascading failures by detecting failures and temporarily
    blocking requests to allow the system to recover.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type to catch
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = CircuitState.CLOSED
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        if self._last_failure_time is None:
            return False
        
        elapsed = (datetime.now() - self._last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout
    
    def record_success(self) -> None:
        """Record a successful operation."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        logger.debug("Circuit breaker: Success recorded, circuit CLOSED")
    
    def record_failure(self) -> None:
        """Record a failed operation."""
        self._failure_count += 1
        self._last_failure_time = datetime.now()
        
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                f"Circuit breaker: Threshold reached ({self._failure_count} failures), "
                f"circuit OPEN for {self.recovery_timeout}s"
            )
    
    def can_execute(self) -> bool:
        """Check if operation can be executed."""
        if self._state == CircuitState.CLOSED:
            return True
        
        if self._state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker: Attempting recovery, circuit HALF_OPEN")
                return True
            return False
        
        # HALF_OPEN state
        return True
    
    async def call(self, func, *args, **kwargs):
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Function result
        
        Raises:
            Exception: If circuit is open or function fails
        """
        if not self.can_execute():
            raise Exception(f"Circuit breaker is {self._state.value}, request rejected")
        
        try:
            result = await func(*args, **kwargs)
            self.record_success()
            return result
        except self.expected_exception as e:
            self.record_failure()
            raise


class RetryPolicy:
    """
    Retry policy with exponential backoff.
    """
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True
    ):
        """
        Initialize retry policy.
        
        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            exponential_base: Base for exponential backoff
            jitter: Add random jitter to delays
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt number.
        
        Args:
            attempt: Current attempt number (0-indexed)
        
        Returns:
            Delay in seconds
        """
        delay = min(
            self.base_delay * (self.exponential_base ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            # Add ±25% jitter
            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(0, delay)
    
    async def execute(self, func, *args, **kwargs):
        """
        Execute function with retry logic.
        
        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Function result
        
        Raises:
            Exception: If all retries exhausted
        """
        last_exception = None
        
        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt < self.max_attempts - 1:
                    delay = self.get_delay(attempt)
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_attempts} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"All {self.max_attempts} attempts failed. Last error: {e}"
                    )
        
        raise last_exception


class RedisConnectionPool:
    """
    Advanced Redis connection pool with health checks and failover.
    """
    
    def __init__(
        self,
        url: str,
        max_connections: int = 100,
        min_idle_connections: int = 10,
        socket_timeout: float = 5.0,
        socket_connect_timeout: float = 5.0,
        health_check_interval: int = 30
    ):
        """
        Initialize connection pool.
        
        Args:
            url: Redis connection URL
            max_connections: Maximum number of connections
            min_idle_connections: Minimum idle connections to maintain
            socket_timeout: Socket operation timeout
            socket_connect_timeout: Socket connection timeout
            health_check_interval: Health check interval in seconds
        """
        self.url = url
        self.max_connections = max_connections
        self.min_idle_connections = min_idle_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.health_check_interval = health_check_interval
        
        self._pool: Optional[aioredis.ConnectionPool] = None
        self._redis: Optional[aioredis.Redis] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._is_healthy = False
    
    async def connect(self) -> None:
        """Initialize connection pool."""
        if self._pool is not None:
            return
        
        self._pool = aioredis.ConnectionPool.from_url(
            self.url,
            max_connections=self.max_connections,
            socket_timeout=self.socket_timeout,
            socket_connect_timeout=self.socket_connect_timeout,
            decode_responses=True,
            encoding="utf-8"
        )
        
        self._redis = aioredis.Redis(connection_pool=self._pool)
        
        # Start health check background task
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        logger.info(
            f"Redis connection pool initialized: "
            f"max_connections={self.max_connections}, url={self.url}"
        )
    
    async def disconnect(self) -> None:
        """Close connection pool."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._redis:
            await self._redis.close()
            self._redis = None
        
        if self._pool:
            await self._pool.disconnect()
            self._pool = None
        
        logger.info("Redis connection pool closed")
    
    async def _health_check_loop(self) -> None:
        """Background task for periodic health checks."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                self._is_healthy = await self.health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                self._is_healthy = False
    
    async def health_check(self) -> bool:
        """Perform health check on Redis connection."""
        if not self._redis:
            return False
        
        try:
            await self._redis.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis client."""
        if not self._redis:
            raise RuntimeError("Connection pool not initialized. Call connect() first.")
        return self._redis
    
    @property
    def is_healthy(self) -> bool:
        """Check if connection pool is healthy."""
        return self._is_healthy


class RedisSentinelManager:
    """
    Redis Sentinel manager for high availability.
    
    Automatically discovers and connects to the master Redis instance.
    Handles failover automatically.
    """
    
    def __init__(
        self,
        sentinel_hosts: List[Tuple[str, int]],
        master_name: str = "mymaster",
        password: Optional[str] = None,
        socket_timeout: float = 5.0
    ):
        """
        Initialize Sentinel manager.
        
        Args:
            sentinel_hosts: List of (host, port) tuples for Sentinel nodes
            master_name: Name of the master service
            password: Redis password
            socket_timeout: Socket timeout in seconds
        """
        self.sentinel_hosts = sentinel_hosts
        self.master_name = master_name
        self.password = password
        self.socket_timeout = socket_timeout
        
        self._sentinel: Optional[Sentinel] = None
        self._master: Optional[aioredis.Redis] = None
    
    async def connect(self) -> None:
        """Connect to Redis via Sentinel."""
        if self._sentinel is not None:
            return
        
        self._sentinel = Sentinel(
            self.sentinel_hosts,
            socket_timeout=self.socket_timeout
        )
        
        self._master = self._sentinel.master_for(
            self.master_name,
            password=self.password,
            decode_responses=True,
            encoding="utf-8"
        )
        
        logger.info(
            f"Connected to Redis master '{self.master_name}' via Sentinel "
            f"(hosts: {self.sentinel_hosts})"
        )
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._master:
            await self._master.close()
            self._master = None
        
        self._sentinel = None
        logger.info("Disconnected from Redis Sentinel")
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis master client."""
        if not self._master:
            raise RuntimeError("Sentinel not initialized. Call connect() first.")
        return self._master
    
    async def get_master_address(self) -> Optional[Tuple[str, int]]:
        """Get current master address."""
        if not self._sentinel:
            return None
        
        try:
            master_info = await self._sentinel.discover_master(self.master_name)
            return (master_info[0], master_info[1])
        except Exception as e:
            logger.error(f"Failed to discover master: {e}")
            return None


class RedisManager:
    """
    Unified Redis manager with all advanced features.
    
    Features:
    - Connection pooling
    - Circuit breaker
    - Retry logic with exponential backoff
    - Sentinel support for HA
    - Automatic failover
    - Health monitoring
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize Redis manager.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        
        # Connection pool or Sentinel
        self._connection_pool: Optional[RedisConnectionPool] = None
        self._sentinel_manager: Optional[RedisSentinelManager] = None
        
        # Circuit breaker and retry
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=settings.redis_health_check_interval,
            expected_exception=Exception
        )
        self._retry_policy = RetryPolicy(
            max_attempts=settings.redis_reconnect_max_attempts,
            base_delay=1.0,
            max_delay=30.0,
            exponential_base=2.0,
            jitter=True
        )
        
        self._connected = False
    
    async def connect(self) -> None:
        """Connect to Redis (Sentinel or standalone)."""
        if self._connected:
            return
        
        # Determine mode: Sentinel or Standalone
        if self.settings.redis_mode == "sentinel" and self.settings.redis_sentinel_hosts:
            await self._connect_sentinel()
        elif self.settings.redis_mode == "cluster":
            raise NotImplementedError("Redis Cluster mode not yet implemented")
        else:
            await self._connect_standalone()
        
        self._connected = True
        logger.info(f"Redis manager connected in {self.settings.redis_mode} mode")
    
    async def _connect_standalone(self) -> None:
        """Connect to standalone Redis."""
        self._connection_pool = RedisConnectionPool(
            url=self.settings.redis_url,
            max_connections=self.settings.redis_max_connections,
            socket_timeout=self.settings.redis_socket_timeout,
            health_check_interval=self.settings.redis_health_check_interval
        )
        await self._connection_pool.connect()
    
    async def _connect_sentinel(self) -> None:
        """Connect to Redis via Sentinel."""
        # Parse sentinel hosts (format: "host1:port1,host2:port2")
        sentinel_hosts = []
        for host_port in self.settings.redis_sentinel_hosts.split(","):
            host, port = host_port.strip().split(":")
            sentinel_hosts.append((host, int(port)))
        
        self._sentinel_manager = RedisSentinelManager(
            sentinel_hosts=sentinel_hosts,
            master_name=self.settings.redis_sentinel_master,
            password=self.settings.redis_password,
            socket_timeout=self.settings.redis_socket_timeout
        )
        await self._sentinel_manager.connect()
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._connection_pool:
            await self._connection_pool.disconnect()
            self._connection_pool = None
        
        if self._sentinel_manager:
            await self._sentinel_manager.disconnect()
            self._sentinel_manager = None
        
        self._connected = False
        logger.info("Redis manager disconnected")
    
    @property
    def redis(self) -> aioredis.Redis:
        """Get Redis client."""
        if self._sentinel_manager:
            return self._sentinel_manager.redis
        elif self._connection_pool:
            return self._connection_pool.redis
        else:
            raise RuntimeError("Redis manager not connected")
    
    async def execute_with_retry(self, func, *args, **kwargs):
        """
        Execute Redis operation with retry and circuit breaker.
        
        Args:
            func: Redis operation function
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Operation result
        """
        async def wrapped_func():
            return await func(*args, **kwargs)
        
        # Apply circuit breaker
        result = await self._circuit_breaker.call(
            self._retry_policy.execute,
            wrapped_func
        )
        
        return result
    
    async def health_check(self) -> bool:
        """Perform health check."""
        try:
            await self.redis.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._connected
    
    @property
    def circuit_state(self) -> CircuitState:
        """Get circuit breaker state."""
        return self._circuit_breaker.state
