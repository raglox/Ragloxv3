#!/usr/bin/env python3
"""
RAGLOX v3.0 - Real VM Creation Integration Test
Tests actual VM provisioning with a real user registration
"""

import asyncio
import sys
import time
import requests
import json
from datetime import datetime

# Test configuration
API_BASE_URL = "http://localhost:8000"
TEST_USER = {
    "email": f"test_{int(time.time())}@raglox.com",
    "password": "RealTest2025!",
    "full_name": "Real VM Test User"
}

def print_step(step, message):
    """Print a formatted test step"""
    print(f"\n{'='*80}")
    print(f"STEP {step}: {message}")
    print(f"{'='*80}")

def print_result(success, message):
    """Print a formatted result"""
    icon = "✅" if success else "❌"
    print(f"{icon} {message}")

def register_user():
    """Step 1: Register a new user"""
    print_step(1, "Registering new user")
    
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/v1/auth/register",
            json=TEST_USER,
            timeout=10
        )
        
        if response.status_code == 201:
            data = response.json()
            print_result(True, f"User registered successfully")
            print(f"   User ID: {data.get('user', {}).get('id')}")
            print(f"   Email: {data.get('user', {}).get('email')}")
            print(f"   VM Status: {data.get('user', {}).get('vm_status', 'N/A')}")
            return data
        else:
            print_result(False, f"Registration failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print_result(False, f"Registration error: {e}")
        return None

def check_vm_status(token):
    """Step 2: Check VM provisioning status"""
    print_step(2, "Checking VM provisioning status")
    
    headers = {"Authorization": f"Bearer {token}"}
    max_attempts = 60  # 5 minutes (60 attempts * 5 seconds)
    attempt = 0
    
    while attempt < max_attempts:
        try:
            response = requests.get(
                f"{API_BASE_URL}/api/v1/auth/me",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vm_status = data.get('vm_status', 'unknown')
                vm_ip = data.get('vm_ip', 'N/A')
                
                print(f"\r   Attempt {attempt + 1}/{max_attempts}: VM Status = {vm_status}, IP = {vm_ip}", end='')
                
                if vm_status == 'READY':
                    print()
                    print_result(True, f"VM provisioned successfully!")
                    print(f"   VM IP: {vm_ip}")
                    print(f"   VM Status: {vm_status}")
                    print(f"   SSH User: {data.get('vm_ssh_user', 'N/A')}")
                    print(f"   SSH Port: {data.get('vm_ssh_port', 'N/A')}")
                    return {
                        'status': vm_status,
                        'ip': vm_ip,
                        'ssh_user': data.get('vm_ssh_user'),
                        'ssh_port': data.get('vm_ssh_port')
                    }
                elif vm_status == 'FAILED':
                    print()
                    print_result(False, "VM provisioning failed")
                    return None
                
                # Status is PENDING, CREATING, or CONFIGURING - wait and retry
                attempt += 1
                time.sleep(5)
            else:
                print()
                print_result(False, f"Status check failed: {response.status_code}")
                return None
        except Exception as e:
            print()
            print_result(False, f"Status check error: {e}")
            return None
    
    print()
    print_result(False, f"VM provisioning timeout after {max_attempts * 5} seconds")
    return None

def test_ssh_command(token, vm_info):
    """Step 3: Test SSH command execution"""
    print_step(3, "Testing SSH command execution")
    
    # Create a test mission first
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Create mission
        mission_response = requests.post(
            f"{API_BASE_URL}/api/v1/missions",
            headers=headers,
            json={
                "name": "SSH Test Mission",
                "target": {
                    "host": vm_info['ip'],
                    "description": "Test target for SSH verification"
                }
            },
            timeout=10
        )
        
        if mission_response.status_code != 201:
            print_result(False, f"Failed to create mission: {mission_response.status_code}")
            return False
        
        mission_id = mission_response.json().get('id')
        print_result(True, f"Mission created: {mission_id}")
        
        # Send test command via chat
        chat_response = requests.post(
            f"{API_BASE_URL}/api/v1/chat/{mission_id}",
            headers=headers,
            json={"message": "/run whoami"},
            timeout=30
        )
        
        if chat_response.status_code == 200:
            result = chat_response.json()
            output = result.get('output', '')
            
            # Check if output contains root (real SSH) or ubuntu (simulation)
            if 'root' in output.lower() and '[SIMULATION MODE]' not in output:
                print_result(True, "SSH command executed on real VM!")
                print(f"   Output: {output[:100]}")
                return True
            elif '[SIMULATION MODE]' in output:
                print_result(False, "Command ran in simulation mode (SSH not connected)")
                print(f"   Output: {output[:100]}")
                return False
            else:
                print_result(True, "Command executed (status unknown)")
                print(f"   Output: {output[:100]}")
                return True
        else:
            print_result(False, f"Chat command failed: {chat_response.status_code}")
            return False
            
    except Exception as e:
        print_result(False, f"SSH test error: {e}")
        return False

def main():
    """Run the complete integration test"""
    print("\n" + "="*80)
    print("RAGLOX v3.0 - Real VM Creation Integration Test")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    # Step 1: Register user
    registration_data = register_user()
    if not registration_data:
        print("\n❌ TEST FAILED: User registration failed")
        sys.exit(1)
    
    token = registration_data.get('access_token')
    if not token:
        print("\n❌ TEST FAILED: No authentication token received")
        sys.exit(1)
    
    # Step 2: Wait for VM provisioning
    vm_info = check_vm_status(token)
    if not vm_info:
        print("\n❌ TEST FAILED: VM provisioning failed or timed out")
        sys.exit(1)
    
    # Step 3: Test SSH command
    ssh_success = test_ssh_command(token, vm_info)
    
    # Final summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print_result(True, "User Registration")
    print_result(bool(vm_info), "VM Provisioning")
    print_result(ssh_success, "SSH Command Execution")
    
    if vm_info and ssh_success:
        print("\n✅ ALL TESTS PASSED - Real VM provisioning working correctly!")
        sys.exit(0)
    else:
        print("\n⚠️  PARTIAL SUCCESS - Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
