"""
RAGLOX v3.0 - Cloud Provider Integration
Support for both OneProvider and Firecracker VM management.

Author: RAGLOX Team
Version: 3.0.0
"""

from contextlib import asynccontextmanager
from .oneprovider_client import OneProviderClient, OneProviderError
from .firecracker_client import FirecrackerClient, FirecrackerError
from .vm_manager import VMManager, VMStatus, VMConfiguration
from .resource_monitor import ResourceMonitor
from .billing_tracker import BillingTracker


@asynccontextmanager
async def get_cloud_provider_client():
    """
    Get cloud provider client (Firecracker) as async context manager.
    
    Usage:
        async with get_cloud_provider_client() as client:
            vm = await client.create_vm(...)
    
    Yields:
        FirecrackerClient: Initialized Firecracker client
    """
    client = FirecrackerClient()
    try:
        yield client
    finally:
        await client.close()


__all__ = [
    "OneProviderClient",
    "OneProviderError",
    "FirecrackerClient",
    "FirecrackerError",
    "VMManager",
    "VMStatus",
    "VMConfiguration",
    "ResourceMonitor",
    "BillingTracker",
    "get_cloud_provider_client",
]
