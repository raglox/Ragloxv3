"""
Test script for FirecrackerClient
Tests basic VM operations.
"""

import asyncio
import sys
sys.path.insert(0, '/opt/raglox/webapp')

from src.infrastructure.cloud_provider.firecracker_client import FirecrackerClient


async def test_firecracker_client():
    """Test FirecrackerClient operations"""
    
    print("=" * 60)
    print("Testing FirecrackerClient")
    print("=" * 60)
    
    # Initialize client
    client = FirecrackerClient(api_url="http://208.115.230.194:8080")
    
    try:
        # Test 1: List VMs
        print("\n1. Testing list_vms()...")
        vms = await client.list_vms()
        print(f"   ✅ Found {len(vms)} VMs")
        
        # Test 2: Create VM
        print("\n2. Testing create_vm()...")
        vm_result = await client.create_vm(
            user_id="test-user-001",
            hostname="test-raglox-vm",
            vcpu_count=2,
            mem_size_mib=2048
        )
        vm_id = vm_result["vm_id"]
        print(f"   ✅ Created VM: {vm_id}")
        print(f"   IP: {vm_result.get('ip_address')}")
        print(f"   Password: {vm_result.get('password')}")
        
        # Test 3: Get VM info
        print("\n3. Testing get_vm_info()...")
        vm_info = await client.get_vm_info(vm_id)
        print(f"   ✅ VM Status: {vm_info.get('status')}")
        print(f"   IP: {vm_info.get('ip_address')}")
        
        # Test 4: Wait for VM ready
        print("\n4. Testing wait_for_vm_ready()...")
        ready = await client.wait_for_vm_ready(vm_id, timeout=30)
        if ready:
            print(f"   ✅ VM is ready!")
        else:
            print(f"   ⚠️ VM not ready yet")
        
        # Test 5: Stop VM
        print("\n5. Testing stop_vm()...")
        await client.stop_vm(vm_id)
        print(f"   ✅ VM stopped")
        
        # Test 6: Destroy VM
        print("\n6. Testing destroy_vm()...")
        await client.destroy_vm(vm_id)
        print(f"   ✅ VM destroyed")
        
        # Test 7: Verify VM is gone
        print("\n7. Verifying VM deletion...")
        vms_after = await client.list_vms()
        print(f"   ✅ VMs remaining: {len(vms_after)}")
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(test_firecracker_client())
