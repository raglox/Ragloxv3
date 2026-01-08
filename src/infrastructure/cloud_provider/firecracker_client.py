"""
RAGLOX v3.0 - Firecracker API Client
Client for Firecracker Manager API on bare metal server.

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-08
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

import aiohttp


logger = logging.getLogger("raglox.infrastructure.cloud_provider.firecracker")


class FirecrackerError(Exception):
    """Firecracker API error"""
    pass


class VMState(str, Enum):
    """VM states from Firecracker"""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DESTROYED = "destroyed"


class FirecrackerClient:
    """
    Firecracker API Client
    
    Handles all communication with Firecracker Manager API for microVM management.
    Supports:
    - MicroVM creation/deletion
    - VM operations (start, stop)
    - Resource monitoring
    - User isolation
    
    Architecture:
    - Direct HTTP communication (no authentication needed)
    - Async operations using aiohttp
    - Automatic retry logic for resilience
    """
    
    def __init__(
        self,
        api_url: str = "http://208.115.230.194:8080",
        timeout: int = 30,
        max_retries: int = 3
    ):
        """
        Initialize Firecracker client
        
        Args:
            api_url: Firecracker Manager API URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Context manager entry"""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Raglox-Firecracker-Client/3.0"
                },
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
    
    async def close(self):
        """Close the client session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        retry_count: int = 0
    ) -> Dict[str, Any]:
        """
        Make API request with retry logic
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            json: JSON body
            params: Query parameters
            retry_count: Current retry count
        
        Returns:
            API response data
        
        Raises:
            FirecrackerError: If request fails
        """
        await self._ensure_session()
        
        url = f"{self.api_url}{endpoint}"
        
        try:
            logger.debug(f"Firecracker API: {method} {url}")
            
            async with self._session.request(
                method,
                url,
                json=json,
                params=params
            ) as response:
                # Read response text
                text = await response.text()
                
                # Log response
                logger.debug(
                    f"Firecracker response: status={response.status}, "
                    f"body={text[:200]}"
                )
                
                # Check status
                if response.status >= 400:
                    error_msg = f"Firecracker API error: {response.status} - {text}"
                    
                    # Retry on server errors
                    if (
                        response.status >= 500
                        and retry_count < self.max_retries
                    ):
                        logger.warning(
                            f"Retrying request ({retry_count + 1}/{self.max_retries})"
                        )
                        await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                        return await self._request(
                            method,
                            endpoint,
                            json,
                            params,
                            retry_count + 1
                        )
                    
                    raise FirecrackerError(error_msg)
                
                # Parse JSON
                try:
                    data = await response.json()
                    return data
                except Exception as e:
                    # If empty response, return success marker
                    if not text.strip():
                        return {"status": "success"}
                    logger.error(f"Failed to parse JSON response: {str(e)}")
                    return {"raw_response": text}
                
        except aiohttp.ClientError as e:
            error_msg = f"Firecracker request failed: {str(e)}"
            logger.error(error_msg)
            
            # Retry on network errors
            if retry_count < self.max_retries:
                logger.warning(
                    f"Retrying request ({retry_count + 1}/{self.max_retries})"
                )
                await asyncio.sleep(2 ** retry_count)
                return await self._request(
                    method,
                    endpoint,
                    json,
                    params,
                    retry_count + 1
                )
            
            raise FirecrackerError(error_msg) from e
    
    # ========================================================================
    # VM Management
    # ========================================================================
    
    async def list_vms(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all VMs (optionally filter by user)
        
        Args:
            user_id: Filter by user ID (optional)
        
        Returns:
            List of VM details
        """
        params = {"user_id": user_id} if user_id else None
        data = await self._request("GET", "/vms", params=params)
        
        # Handle both list response and object response
        if isinstance(data, list):
            return data
        return data.get("vms", [])
    
    async def get_vm_info(self, vm_id: str) -> Dict[str, Any]:
        """
        Get detailed VM information
        
        Args:
            vm_id: VM ID
        
        Returns:
            VM details including status, IP, resources
        """
        data = await self._request("GET", f"/vms/{vm_id}")
        return data
    
    async def create_vm(
        self,
        user_id: str,
        hostname: Optional[str] = None,
        vcpu_count: int = 2,
        mem_size_mib: int = 2048,
        disk_size_mb: int = 10240,
        **kwargs  # For compatibility with OneProvider signature
    ) -> Dict[str, Any]:
        """
        Create a new microVM using Firecracker
        
        Args:
            user_id: User ID (for isolation)
            hostname: VM hostname (optional, auto-generated if not provided)
            vcpu_count: Number of vCPUs (default: 2)
            mem_size_mib: Memory size in MiB (default: 2048)
            disk_size_mb: Disk size in MB (default: 10240)
            **kwargs: Additional parameters (ignored, for compatibility)
        
        Returns:
            Created VM details with keys:
                - vm_id: VM ID
                - ip_address: Assigned IP address
                - hostname: VM hostname  
                - status: VM status
                - ssh_port: SSH port (22)
                - ssh_password: Default root password
        
        Note:
            Firecracker VMs are created instantly and are ready immediately.
            Default credentials: root/raglox123
        """
        # Generate VM ID if hostname not provided
        if not hostname:
            hostname = f"raglox-{user_id[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        vm_id = hostname
        
        # Build request payload
        payload = {
            "vm_id": vm_id,
            "user_id": user_id,
            "vcpu_count": vcpu_count,
            "mem_size_mib": mem_size_mib,
            "disk_size_mb": disk_size_mb
        }
        
        logger.info(f"Creating Firecracker VM: {vm_id} for user {user_id}")
        
        # Make API request
        response = await self._request("POST", "/vms", json=payload)
        
        # Parse response
        if response.get("status") == "success" or "vm_id" in response:
            vm_data = response
            actual_vm_id = vm_data.get("vm_id", vm_id)
            
            logger.info(f"Created Firecracker VM: {actual_vm_id}")
            
            # Return standardized format (compatible with OneProvider)
            return {
                "vm_id": actual_vm_id,
                "ip_address": vm_data.get("ip_address"),
                "hostname": hostname,
                "password": "raglox123",  # Default Firecracker password
                "status": "running",  # Firecracker VMs are instantly ready
                "ssh_port": 22,
                "ssh_user": "root"
            }
        else:
            error_msg = response.get("error", "Unknown error")
            raise FirecrackerError(f"Failed to create VM: {error_msg}")
    
    async def destroy_vm(
        self,
        vm_id: str,
        confirm_close: bool = False  # For compatibility with OneProvider
    ) -> Dict[str, Any]:
        """
        Destroy a microVM
        
        Args:
            vm_id: VM ID
            confirm_close: Ignored (for compatibility)
        
        Returns:
            Destruction status
        """
        logger.info(f"Destroying Firecracker VM: {vm_id}")
        
        data = await self._request("DELETE", f"/vms/{vm_id}")
        
        logger.info(f"Destroyed Firecracker VM: {vm_id}")
        return data
    
    async def start_vm(self, vm_id: str) -> Dict[str, Any]:
        """
        Start a stopped VM
        
        Note: Firecracker VMs are created in running state,
        but this is here for compatibility.
        """
        logger.info(f"Starting Firecracker VM: {vm_id}")
        # Firecracker VMs don't have explicit start endpoint in current API
        # They start automatically on creation
        return {"status": "success", "vm_id": vm_id}
    
    async def stop_vm(self, vm_id: str, force: bool = False) -> Dict[str, Any]:
        """
        Stop a running VM
        
        Args:
            vm_id: VM ID
            force: Force stop (ignored for now)
        
        Returns:
            Stop status
        """
        logger.info(f"Stopping Firecracker VM: {vm_id}")
        
        data = await self._request("POST", f"/vms/{vm_id}/stop")
        
        logger.info(f"Stopped Firecracker VM: {vm_id}")
        return data
    
    async def reboot_vm(self, vm_id: str, force: bool = False) -> Dict[str, Any]:
        """
        Reboot a VM (not implemented in Firecracker API)
        
        For compatibility with OneProvider interface.
        """
        logger.warning(f"Reboot not supported for Firecracker VM: {vm_id}")
        # Simulate reboot by stop/start (if needed in future)
        return {"status": "not_supported", "vm_id": vm_id}
    
    # ========================================================================
    # Monitoring & Status
    # ========================================================================
    
    async def wait_for_vm_ready(
        self,
        vm_id: str,
        timeout: int = 60,  # Much shorter than OneProvider
        poll_interval: int = 2
    ) -> bool:
        """
        Wait for VM to be ready
        
        Note: Firecracker VMs are ready immediately upon creation,
        but we add a small delay to ensure networking is up.
        
        Args:
            vm_id: VM ID
            timeout: Maximum wait time in seconds
            poll_interval: Seconds between status checks
        
        Returns:
            True if VM is ready, False if timeout
        """
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            try:
                vm_info = await self.get_vm_info(vm_id)
                
                # Check if VM is running and has IP
                if vm_info.get("status") == "running" and vm_info.get("ip_address"):
                    logger.info(f"Firecracker VM {vm_id} is ready")
                    return True
                
                logger.debug(f"Waiting for VM {vm_id} to be ready...")
                
            except Exception as e:
                logger.warning(f"Error checking VM status: {str(e)}")
            
            await asyncio.sleep(poll_interval)
        
        logger.error(f"Firecracker VM {vm_id} not ready after {timeout}s")
        return False
    
    # ========================================================================
    # Compatibility Methods (for OneProvider interface parity)
    # ========================================================================
    
    async def list_projects(self) -> List[Dict[str, Any]]:
        """
        Compatibility method: Firecracker doesn't have projects
        Returns empty list.
        """
        return []
    
    async def get_project(self, project_uuid: str) -> Dict[str, Any]:
        """
        Compatibility method: Firecracker doesn't have projects
        Returns dummy project.
        """
        return {
            "uuid": project_uuid,
            "name": "Default Firecracker Project",
            "status": "active"
        }
    
    async def search_vms(
        self,
        query: Optional[str] = None,
        project_uuid: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search VMs by user_id
        
        Args:
            query: Ignored (for compatibility)
            project_uuid: Ignored (for compatibility)
            user_id: Filter by user ID
        
        Returns:
            List of matching VMs
        """
        return await self.list_vms(user_id=user_id)
