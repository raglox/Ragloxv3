#!/usr/bin/env python3
"""
Script to manually add VM credentials for testing user
"""
import asyncio
import sys
sys.path.insert(0, '/root/RAGLOX_V3/webapp')

from src.core.database.user_repository import UserRepository
from src.core.config import get_settings
from redis import asyncio as aioredis
from uuid import UUID

async def add_vm_for_test_user():
    """Add VM credentials for test user"""
    settings = get_settings()
    
    # Connect to Redis
    redis = await aioredis.from_url(
        f"redis://{settings.redis_host}:{settings.redis_port}",
        encoding="utf-8",
        decode_responses=True
    )
    
    user_repo = UserRepository(redis)
    
    # Email of test user
    test_email = "qate@raglox.com"
    
    print(f"🔍 Searching for user: {test_email}")
    
    # Get all users to find the one with this email
    # Note: This is a workaround since we don't have get_by_email method
    # In production, you'd query PostgreSQL directly
    
    # For now, let's use a known user_id if you have it
    # Or we can add a method to search by email
    
    print("❌ We need the user_id (UUID) to update the VM info")
    print("Please provide the user_id for qate@raglox.com")
    print("\nAlternatively, please provide:")
    print("1. A working VM IP address")
    print("2. SSH username (usually 'root')")
    print("3. SSH password")
    print("4. SSH port (usually 22)")
    
    await redis.close()

if __name__ == "__main__":
    asyncio.run(add_vm_for_test_user())
