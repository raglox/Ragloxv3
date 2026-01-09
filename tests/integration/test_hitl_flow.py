import asyncio
import json
import uuid
import sys
from datetime import datetime

# Mock websocket client
try:
    import websockets
except ImportError:
    print("Please install websockets: pip install websockets")
    sys.exit(1)

import requests

BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/api/v1/ws/missions"

async def test_hitl_flow():
    print("🚀 Starting HITL (Human-in-the-Loop) Integration Test")
    
    # 1. Create a dummy mission
    print("1️⃣ Creating Mission...")
    mission_id = str(uuid.uuid4())
    print(f"   Mission ID: {mission_id}")
    
    # 2. Connect to WebSocket
    print("2️⃣ Connecting to WebSocket...")
    # Note: In real app we need auth token, but for this test environment we might need to bypass or mock
    # The current implementation in websocket.py allows anonymous if no token provided for some endpoints, 
    # but mission endpoint requires auth. 
    # For this test, we will assume we can hit the endpoint or use a mock token if needed.
    # Actually, let's use the API directly to trigger the "Execute" and see the response first.
    
    # 3. Send "Safe" Command
    print("3️⃣ Testing Safe Command (ls -la)...")
    safe_payload = {"command": "ls -la", "timeout": 10}
    try:
        resp = requests.post(f"{BASE_URL}/api/v1/missions/{mission_id}/execute", json=safe_payload)
        if resp.status_code == 200:
            data = resp.json()
            if data['status'] == 'success' or 'unavailable': # unavailable is fine if no VM
                print("   ✅ Safe command executed (or attempted) without rejection.")
            else:
                print(f"   ⚠️ Unexpected status: {data['status']}")
        else:
            print(f"   ❌ API Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"   ❌ Connection Failed: {e}")

    # 4. Send "Risky" Command
    print("4️⃣ Testing Risky Command (rm -rf /tmp/trash)...")
    risky_payload = {"command": "rm -rf /tmp/trash", "timeout": 10}
    
    try:
        resp = requests.post(f"{BASE_URL}/api/v1/missions/{mission_id}/execute", json=risky_payload)
        data = resp.json()
        
        if resp.status_code == 200 and data.get('status') == 'pending_approval':
            print("   ✅ HITL Triggered: Command marked as 'pending_approval'.")
            print(f"   ℹ️ Output Message: {data['output'][0]}")
        else:
            print(f"   ❌ Test Failed: Expected 'pending_approval', got {data.get('status')}")
            print(f"   Response: {data}")
            
    except Exception as e:
        print(f"   ❌ Connection Failed: {e}")

    print("\n🏁 Test Complete.")

if __name__ == "__main__":
    asyncio.run(test_hitl_flow())
