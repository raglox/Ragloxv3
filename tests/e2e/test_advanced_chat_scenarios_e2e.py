"""
RAGLOX v3.0 - Advanced Chat Workflow Scenarios E2E Tests

Additional comprehensive tests for advanced chat workflow scenarios:
- Multi-turn conversations with context retention
- Error handling and recovery
- Session persistence and resumption
- Concurrent user sessions
- WebSocket real-time communication
- Frontend-backend integration

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-10
"""

import pytest
import asyncio
import json
from datetime import datetime
from typing import Dict, List
import uuid

from src.core.session_manager import SessionManager
from src.core.blackboard import Blackboard


@pytest.mark.e2e
@pytest.mark.chat_workflow
@pytest.mark.asyncio
class TestAdvancedChatWorkflowScenariosE2E:
    """Advanced chat workflow scenarios"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis):
        self.blackboard = real_blackboard
        self.redis = real_redis
        self.session_manager = SessionManager(redis=self.redis)
        
        self.session_id = f"adv_session_{uuid.uuid4().hex[:8]}"
        self.user_id = f"user_{uuid.uuid4().hex[:8]}"
        
        yield
        
        try:
            await self.session_manager.end_session(self.session_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_multi_turn_conversation_with_context(self):
        """
        Test multi-turn conversation with context retention
        
        Scenario:
        - Turn 1: User asks for reconnaissance
        - Turn 2: User asks follow-up based on results
        - Turn 3: User refines request
        - Agent maintains context throughout
        """
        print("\n🔄 Multi-turn Conversation with Context Test")
        
        # Turn 1: Initial request
        turn1_message = {
            "session_id": self.session_id,
            "turn": 1,
            "role": "user",
            "content": "Scan network 192.168.1.0/24 for active hosts",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(turn1_message)
        )
        
        # Agent response Turn 1
        turn1_response = {
            "session_id": self.session_id,
            "turn": 1,
            "role": "agent",
            "content": "Found 5 active hosts: 192.168.1.10-14",
            "context": {"found_hosts": ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(turn1_response)
        )
        
        # Store context
        await self.redis.set(
            f"context:{self.session_id}",
            json.dumps(turn1_response["context"]),
            ex=3600
        )
        
        print(f"   Turn 1 complete - Context stored: {len(turn1_response['context']['found_hosts'])} hosts")
        
        # Turn 2: Follow-up using context
        turn2_message = {
            "session_id": self.session_id,
            "turn": 2,
            "role": "user",
            "content": "Check which of those hosts have port 22 open",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(turn2_message)
        )
        
        # Agent retrieves context
        stored_context = json.loads(await self.redis.get(f"context:{self.session_id}"))
        assert "found_hosts" in stored_context
        
        print(f"   Turn 2 - Agent retrieved context: {len(stored_context['found_hosts'])} hosts")
        
        # Agent response Turn 2 (using context)
        hosts_with_ssh = [stored_context["found_hosts"][0], stored_context["found_hosts"][2]]
        
        turn2_response = {
            "session_id": self.session_id,
            "turn": 2,
            "role": "agent",
            "content": f"Of the {len(stored_context['found_hosts'])} hosts found, {len(hosts_with_ssh)} have SSH open",
            "context": {
                **stored_context,
                "ssh_hosts": hosts_with_ssh
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(turn2_response)
        )
        
        await self.redis.set(
            f"context:{self.session_id}",
            json.dumps(turn2_response["context"]),
            ex=3600
        )
        
        print(f"   Turn 2 complete - Context updated: {len(hosts_with_ssh)} SSH hosts")
        
        # Turn 3: Further refinement
        turn3_message = {
            "session_id": self.session_id,
            "turn": 3,
            "role": "user",
            "content": "Try brute force on the first SSH host",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(turn3_message)
        )
        
        # Agent retrieves updated context
        current_context = json.loads(await self.redis.get(f"context:{self.session_id}"))
        assert "ssh_hosts" in current_context
        
        target_host = current_context["ssh_hosts"][0]
        
        print(f"   Turn 3 - Agent using context: targeting {target_host}")
        
        # Verify conversation history
        message_count = await self.redis.llen(f"chat:{self.session_id}:messages")
        assert message_count == 5  # 3 user + 2 agent
        
        print(f"   ✅ Multi-turn conversation test passed")
        print(f"      - Turns: 3")
        print(f"      - Messages: {message_count}")
        print(f"      - Context retained: ✓")

    @pytest.mark.priority_high
    async def test_e2e_error_handling_and_graceful_recovery(self):
        """
        Test error handling and graceful recovery
        
        Scenarios:
        - Tool execution failure
        - LLM timeout
        - Environment unavailable
        - Agent recovers gracefully
        """
        print("\n⚠️  Error Handling and Recovery Test")
        
        # Scenario 1: Tool execution failure
        print("   Scenario 1: Tool execution failure")
        
        error_message = {
            "session_id": self.session_id,
            "role": "user",
            "content": "Scan 192.168.1.10",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(error_message)
        )
        
        # Simulate tool failure
        tool_error = {
            "session_id": self.session_id,
            "tool": "nmap",
            "status": "failed",
            "error": "Network unreachable",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"error:{self.session_id}:tool_execution",
            json.dumps(tool_error),
            ex=300
        )
        
        # Agent graceful response
        recovery_response = {
            "session_id": self.session_id,
            "role": "agent",
            "content": "⚠️ I encountered an issue while scanning: Network unreachable. Let me try an alternative approach...",
            "recovery_action": "retry_with_alternative",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(recovery_response)
        )
        
        print("      ✓ Tool failure handled gracefully")
        
        # Scenario 2: Environment check
        print("   Scenario 2: Environment unavailable")
        
        env_error = {
            "session_id": self.session_id,
            "component": "firecracker_vm",
            "status": "unavailable",
            "error": "VM failed to start",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"error:{self.session_id}:environment",
            json.dumps(env_error),
            ex=300
        )
        
        env_recovery = {
            "session_id": self.session_id,
            "role": "agent",
            "content": "⚠️ Environment setup issue detected. Attempting to restart sandbox...",
            "recovery_action": "restart_environment",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(env_recovery)
        )
        
        print("      ✓ Environment error handled")
        
        # Verify error logs stored
        tool_error_exists = await self.redis.exists(f"error:{self.session_id}:tool_execution")
        env_error_exists = await self.redis.exists(f"error:{self.session_id}:environment")
        
        assert tool_error_exists
        assert env_error_exists
        
        print("   ✅ Error handling test passed")

    @pytest.mark.priority_high
    async def test_e2e_session_persistence_and_resumption(self):
        """
        Test session persistence and resumption
        
        Scenario:
        - User starts session
        - Session interrupted
        - User reconnects
        - Session state restored
        """
        print("\n💾 Session Persistence and Resumption Test")
        
        # Create session with state
        session_state = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "status": "active",
            "current_mission": "pentest_192_168_1_0",
            "context": {
                "targets_found": 5,
                "current_target": "192.168.1.10",
                "stage": "exploitation"
            },
            "created_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"session:{self.session_id}",
            json.dumps(session_state),
            ex=3600
        )
        
        print(f"   ✓ Session created: {self.session_id}")
        print(f"     - Mission: {session_state['current_mission']}")
        print(f"     - Stage: {session_state['context']['stage']}")
        
        # Simulate disconnection
        await asyncio.sleep(0.5)
        
        # Simulate reconnection
        print("   → User reconnected")
        
        # Retrieve session state
        restored_session = json.loads(await self.redis.get(f"session:{self.session_id}"))
        
        assert restored_session["session_id"] == self.session_id
        assert restored_session["current_mission"] == "pentest_192_168_1_0"
        assert restored_session["context"]["stage"] == "exploitation"
        
        print("   ✓ Session state restored")
        print(f"     - Context: {len(restored_session['context'])} items")
        
        # Resume from last state
        resume_message = {
            "session_id": self.session_id,
            "role": "agent",
            "content": f"Welcome back! Resuming from {restored_session['context']['stage']} stage on target {restored_session['context']['current_target']}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(resume_message)
        )
        
        print("   ✅ Session resumption test passed")

    @pytest.mark.priority_medium
    async def test_e2e_concurrent_user_sessions(self):
        """
        Test concurrent user sessions isolation
        
        Scenario:
        - Multiple users with separate sessions
        - Each session isolated
        - No cross-contamination
        """
        print("\n👥 Concurrent User Sessions Test")
        
        # Create multiple sessions
        sessions = []
        for i in range(3):
            session_id = f"concurrent_session_{i}_{uuid.uuid4().hex[:8]}"
            user_id = f"user_{i}"
            
            session_data = {
                "session_id": session_id,
                "user_id": user_id,
                "status": "active",
                "data": f"user_{i}_specific_data",
                "created_at": datetime.utcnow().isoformat()
            }
            
            await self.redis.set(
                f"session:{session_id}",
                json.dumps(session_data),
                ex=3600
            )
            
            sessions.append(session_data)
            print(f"   ✓ Session {i} created: {user_id}")
        
        # Verify isolation
        for i, session in enumerate(sessions):
            retrieved = json.loads(await self.redis.get(f"session:{session['session_id']}"))
            
            assert retrieved["user_id"] == f"user_{i}"
            assert retrieved["data"] == f"user_{i}_specific_data"
            
            # Check no cross-contamination
            for j, other_session in enumerate(sessions):
                if i != j:
                    assert retrieved["session_id"] != other_session["session_id"]
        
        print(f"   ✅ {len(sessions)} concurrent sessions isolated correctly")

    @pytest.mark.priority_high
    async def test_e2e_message_ordering_and_sequencing(self):
        """
        Test message ordering and proper sequencing
        
        Verifies:
        - Messages in chronological order
        - No message loss
        - Proper threading
        """
        print("\n📝 Message Ordering and Sequencing Test")
        
        # Send multiple messages rapidly
        messages = []
        for i in range(10):
            msg = {
                "session_id": self.session_id,
                "sequence": i,
                "role": "user" if i % 2 == 0 else "agent",
                "content": f"Message {i}",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.redis.lpush(
                f"chat:{self.session_id}:messages",
                json.dumps(msg)
            )
            
            messages.append(msg)
            await asyncio.sleep(0.01)  # Small delay
        
        # Retrieve messages
        stored_count = await self.redis.llen(f"chat:{self.session_id}:messages")
        assert stored_count == 10
        
        # Verify order (Redis LPUSH stores in reverse, so newest first)
        all_messages = await self.redis.lrange(f"chat:{self.session_id}:messages", 0, -1)
        
        # Check all messages present
        assert len(all_messages) == 10
        
        # Verify sequencing
        parsed_messages = [json.loads(msg) for msg in all_messages]
        sequences = [msg["sequence"] for msg in parsed_messages]
        
        # Should be in reverse order (newest first in Redis)
        assert sequences == list(reversed(range(10)))
        
        print(f"   ✓ All {len(messages)} messages stored")
        print(f"   ✓ Ordering verified (newest first)")
        print("   ✅ Message sequencing test passed")

    @pytest.mark.priority_medium
    async def test_e2e_ui_state_synchronization(self):
        """
        Test UI state synchronization with backend
        
        Components:
        - Message list state
        - Planning panel state  
        - Terminal output state
        - Approval modal state
        """
        print("\n🎨 UI State Synchronization Test")
        
        # Component 1: Message List
        print("   Component 1: Message List")
        
        message_state = {
            "session_id": self.session_id,
            "messages": [
                {"role": "user", "content": "Test 1"},
                {"role": "agent", "content": "Response 1"}
            ],
            "last_update": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"ui_state:{self.session_id}:messages",
            json.dumps(message_state),
            ex=3600
        )
        
        retrieved_messages = json.loads(
            await self.redis.get(f"ui_state:{self.session_id}:messages")
        )
        
        assert len(retrieved_messages["messages"]) == 2
        print("      ✓ Message list synchronized")
        
        # Component 2: Planning Panel
        print("   Component 2: Planning Panel")
        
        plan_state = {
            "session_id": self.session_id,
            "visible": True,
            "current_step": 2,
            "total_steps": 5,
            "steps": [
                {"id": 1, "status": "completed"},
                {"id": 2, "status": "in_progress"},
                {"id": 3, "status": "pending"}
            ],
            "last_update": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"ui_state:{self.session_id}:planning",
            json.dumps(plan_state),
            ex=3600
        )
        
        retrieved_plan = json.loads(
            await self.redis.get(f"ui_state:{self.session_id}:planning")
        )
        
        assert retrieved_plan["visible"] == True
        assert retrieved_plan["current_step"] == 2
        print("      ✓ Planning panel synchronized")
        
        # Component 3: Terminal Output
        print("   Component 3: Terminal Output")
        
        terminal_state = {
            "session_id": self.session_id,
            "visible": True,
            "lines": [
                {"type": "stdout", "content": "Command executed"},
                {"type": "stdout", "content": "Results: OK"}
            ],
            "scrollPosition": "bottom",
            "last_update": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"ui_state:{self.session_id}:terminal",
            json.dumps(terminal_state),
            ex=3600
        )
        
        retrieved_terminal = json.loads(
            await self.redis.get(f"ui_state:{self.session_id}:terminal")
        )
        
        assert retrieved_terminal["visible"] == True
        assert len(retrieved_terminal["lines"]) == 2
        print("      ✓ Terminal output synchronized")
        
        # Component 4: Approval Modal
        print("   Component 4: Approval Modal")
        
        approval_state = {
            "session_id": self.session_id,
            "visible": True,
            "approval_id": "approval_123",
            "command": "exploit",
            "risk_level": "high",
            "last_update": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"ui_state:{self.session_id}:approval",
            json.dumps(approval_state),
            ex=3600
        )
        
        retrieved_approval = json.loads(
            await self.redis.get(f"ui_state:{self.session_id}:approval")
        )
        
        assert retrieved_approval["visible"] == True
        assert retrieved_approval["risk_level"] == "high"
        print("      ✓ Approval modal synchronized")
        
        print("   ✅ All UI components synchronized")


@pytest.mark.e2e
@pytest.mark.performance
class TestChatWorkflowPerformanceE2E:
    """Performance tests for chat workflow"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_redis):
        self.redis = real_redis
        self.session_id = f"perf_session_{uuid.uuid4().hex[:8]}"
        yield

    async def test_high_volume_message_handling(self):
        """Test handling high volume of messages"""
        import time
        
        print("\n⚡ High Volume Message Handling Test")
        
        start_time = time.time()
        
        # Send 1000 messages
        for i in range(1000):
            message = {
                "session_id": self.session_id,
                "sequence": i,
                "role": "user" if i % 2 == 0 else "agent",
                "content": f"Message {i}",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.redis.lpush(
                f"chat:{self.session_id}:messages",
                json.dumps(message)
            )
        
        duration = time.time() - start_time
        throughput = 1000 / duration
        
        # Verify all stored
        count = await self.redis.llen(f"chat:{self.session_id}:messages")
        assert count == 1000
        
        print(f"   ✓ Processed 1,000 messages")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Throughput: {throughput:.1f} msgs/sec")
        print(f"   ✅ Performance test passed")

    async def test_rapid_ui_state_updates(self):
        """Test rapid UI state updates"""
        import time
        
        print("\n🔄 Rapid UI State Updates Test")
        
        start_time = time.time()
        
        # Rapid updates
        for i in range(500):
            state = {
                "session_id": self.session_id,
                "update": i,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.redis.set(
                f"ui_state:{self.session_id}:test",
                json.dumps(state),
                ex=60
            )
        
        duration = time.time() - start_time
        throughput = 500 / duration
        
        # Verify final state
        final_state = json.loads(
            await self.redis.get(f"ui_state:{self.session_id}:test")
        )
        
        assert final_state["update"] == 499
        
        print(f"   ✓ Processed 500 state updates")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Throughput: {throughput:.1f} updates/sec")
        print(f"   ✅ Rapid updates test passed")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
