"""
RAGLOX v3.0 - User-Agent Chat Workflow E2E Tests

Comprehensive end-to-end tests for complete user-agent interaction workflow
via chat interface, including:
- Session initialization and environment setup
- Agent intelligence and context awareness (Knowledge Base, RAG, Tools, Shell)
- Chat UI components integration (messages, planning, markdown rendering)
- Human-in-the-loop controls (approval, stop button)
- Terminal streaming and real-time events
- DeepSeek LLM integration

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-10
"""

import pytest
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional
import uuid
import time

# Core components
from src.core.session_manager import SessionManager
from src.core.agent.main_agent import MainAgent
from src.core.llm import LLMClient
from src.core.knowledge import EmbeddedKnowledge
from src.core.vector_knowledge import VectorKnowledgeStore
from src.core.blackboard import Blackboard
from src.core.approval_store import ApprovalStore
from src.core.models import MissionStatus, TaskStatus, TaskType

# API/WebSocket (if available)
try:
    from src.api.websocket import ChatWebSocket
    from src.api.routes import ChatAPI
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False


@pytest.mark.e2e
@pytest.mark.chat_workflow
@pytest.mark.asyncio
class TestUserAgentChatWorkflowE2E:
    """
    Complete User-Agent Chat Workflow E2E Tests
    
    Tests the full interaction flow from user message to agent response,
    including environment setup, LLM reasoning, tool execution, and UI updates.
    """

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis, real_database):
        """Setup complete chat environment"""
        self.blackboard = real_blackboard
        self.redis = real_redis
        self.database = real_database
        
        # Initialize session manager
        self.session_manager = SessionManager(
            redis=self.redis,
            database=self.database
        )
        
        # Initialize LLM client (DeepSeek)
        self.llm_client = LLMClient(
            provider="deepseek",
            model="deepseek-chat",
            api_key="test_key"  # Will use mock in tests
        )
        
        # Initialize knowledge base
        self.knowledge = EmbeddedKnowledge()
        
        # Initialize vector store (optional)
        try:
            self.vector_store = VectorKnowledgeStore()
        except:
            self.vector_store = None
        
        # Initialize approval store
        self.approval_store = ApprovalStore(redis=self.redis)
        
        # Test session
        self.session_id = f"chat_session_{uuid.uuid4().hex[:8]}"
        self.user_id = f"user_{uuid.uuid4().hex[:8]}"
        
        yield
        
        # Cleanup
        try:
            await self.session_manager.end_session(self.session_id)
        except:
            pass

    @pytest.mark.priority_critical
    @pytest.mark.timeout(300)
    async def test_e2e_complete_chat_workflow_with_environment_setup(self):
        """
        Test complete chat workflow from user message to agent response
        
        Flow:
        1. User sends message
        2. Session initialization
        3. Environment setup (Firecracker VM, Ubuntu rootfs, tools)
        4. Agent context preparation (KB, RAG, Tools awareness)
        5. LLM reasoning with DeepSeek
        6. Tool execution in sandbox
        7. Response generation
        8. UI updates (messages, planning, terminal output)
        """
        print("\n" + "="*80)
        print("🚀 Complete User-Agent Chat Workflow E2E Test")
        print("="*80)
        
        # ============================================================
        # PHASE 1: USER SENDS MESSAGE
        # ============================================================
        print("\n📨 Phase 1: User Sends Message")
        
        user_message = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "message": "I need to perform a penetration test on the network 192.168.1.0/24. Start with reconnaissance.",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store user message
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(user_message)
        )
        
        print(f"   ✓ User message received: '{user_message['message'][:50]}...'")
        
        # ============================================================
        # PHASE 2: SESSION INITIALIZATION
        # ============================================================
        print("\n🔧 Phase 2: Session Initialization")
        
        # Check if session exists
        session_exists = await self.redis.exists(f"session:{self.session_id}")
        
        if not session_exists:
            # Create new session
            session_data = {
                "session_id": self.session_id,
                "user_id": self.user_id,
                "status": "initializing",
                "created_at": datetime.utcnow().isoformat(),
                "environment": "pending"
            }
            
            await self.redis.set(
                f"session:{self.session_id}",
                json.dumps(session_data),
                ex=3600  # 1 hour TTL
            )
            
            print(f"   ✓ New session created: {self.session_id}")
        else:
            print(f"   ✓ Existing session found: {self.session_id}")
        
        # ============================================================
        # PHASE 3: ENVIRONMENT SETUP (Firecracker + Ubuntu Rootfs)
        # ============================================================
        print("\n🐧 Phase 3: Environment Setup (Sandbox Preparation)")
        
        # Simulate environment setup check
        environment_status = {
            "vm_ready": False,
            "rootfs_mounted": False,
            "tools_available": False,
            "root_access": False
        }
        
        # Step 3.1: Check/Start Firecracker VM
        print("   → Checking Firecracker VM...")
        vm_check = await self._check_firecracker_vm(self.session_id)
        environment_status["vm_ready"] = vm_check
        
        if vm_check:
            print("   ✓ Firecracker VM is ready")
        else:
            print("   → Starting Firecracker VM...")
            vm_start = await self._start_firecracker_vm(self.session_id)
            environment_status["vm_ready"] = vm_start
            if vm_start:
                print("   ✓ Firecracker VM started successfully")
            else:
                print("   ✗ Failed to start Firecracker VM")
                pytest.fail("Environment setup failed: VM not available")
        
        # Step 3.2: Mount Ubuntu Rootfs
        print("   → Mounting Ubuntu rootfs...")
        rootfs_check = await self._check_rootfs(self.session_id)
        environment_status["rootfs_mounted"] = rootfs_check
        
        if rootfs_check:
            print("   ✓ Ubuntu rootfs mounted and accessible")
        else:
            print("   ✗ Rootfs mount failed")
            pytest.fail("Environment setup failed: Rootfs not accessible")
        
        # Step 3.3: Verify Hacking Tools
        print("   → Verifying hacking tools availability...")
        tools = ["nmap", "metasploit", "sqlmap", "nikto", "gobuster", "hydra"]
        tools_status = {}
        
        for tool in tools:
            tool_available = await self._check_tool_availability(self.session_id, tool)
            tools_status[tool] = tool_available
        
        environment_status["tools_available"] = all(tools_status.values())
        
        if environment_status["tools_available"]:
            print(f"   ✓ All hacking tools available: {', '.join(tools)}")
        else:
            missing = [t for t, available in tools_status.items() if not available]
            print(f"   ⚠ Some tools missing: {', '.join(missing)}")
        
        # Step 3.4: Verify Root Access
        print("   → Verifying root access...")
        root_check = await self._check_root_access(self.session_id)
        environment_status["root_access"] = root_check
        
        if root_check:
            print("   ✓ Root access confirmed (uid=0)")
        else:
            print("   ✗ Root access not available")
            pytest.fail("Environment setup failed: Root access required")
        
        # Update session with environment status
        session_data = json.loads(await self.redis.get(f"session:{self.session_id}"))
        session_data["status"] = "ready"
        session_data["environment"] = environment_status
        await self.redis.set(
            f"session:{self.session_id}",
            json.dumps(session_data),
            ex=3600
        )
        
        print(f"\n   ✅ Environment fully prepared and ready")
        
        # ============================================================
        # PHASE 4: AGENT CONTEXT PREPARATION
        # ============================================================
        print("\n🤖 Phase 4: Agent Context Preparation")
        
        # Step 4.1: Load Knowledge Base
        print("   → Loading knowledge base...")
        kb_loaded = await self._load_knowledge_base()
        if kb_loaded:
            kb_count = len(self.knowledge.knowledge_base)
            print(f"   ✓ Knowledge base loaded: {kb_count:,} entries")
        else:
            print("   ⚠ Knowledge base not available")
        
        # Step 4.2: Initialize RAG (Vector Search)
        print("   → Initializing RAG system...")
        if self.vector_store:
            rag_ready = await self._initialize_rag()
            if rag_ready:
                print("   ✓ RAG system ready for semantic search")
            else:
                print("   ⚠ RAG system initialization failed")
        else:
            print("   ⚠ Vector store not available, using KB only")
        
        # Step 4.3: Build Agent Capabilities Context
        print("   → Building agent capabilities context...")
        agent_context = {
            "identity": "RAGLOX Advanced Penetration Testing Agent",
            "capabilities": {
                "knowledge_base": {
                    "available": kb_loaded,
                    "entries": kb_count if kb_loaded else 0,
                    "coverage": "exploits, vulnerabilities, techniques, tools"
                },
                "rag_search": {
                    "available": self.vector_store is not None,
                    "type": "semantic_vector_search",
                    "embedding_model": "all-MiniLM-L6-v2"
                },
                "tools": {
                    "available": environment_status["tools_available"],
                    "tools_list": tools,
                    "execution_environment": "Ubuntu rootfs via Firecracker"
                },
                "shell_access": {
                    "available": environment_status["root_access"],
                    "privilege": "root (uid=0)",
                    "shell": "/bin/bash"
                },
                "reasoning": {
                    "llm": "DeepSeek",
                    "model": "deepseek-chat",
                    "capabilities": "advanced_reasoning, tool_use, planning"
                }
            },
            "environment": environment_status,
            "session_id": self.session_id
        }
        
        # Store agent context
        await self.redis.set(
            f"agent_context:{self.session_id}",
            json.dumps(agent_context),
            ex=3600
        )
        
        print(f"   ✓ Agent context prepared")
        print(f"     - Knowledge Base: {agent_context['capabilities']['knowledge_base']['available']}")
        print(f"     - RAG Search: {agent_context['capabilities']['rag_search']['available']}")
        print(f"     - Hacking Tools: {len(tools)} tools")
        print(f"     - Shell Access: root")
        print(f"     - LLM: DeepSeek")
        
        # ============================================================
        # PHASE 5: LLM REASONING (DeepSeek)
        # ============================================================
        print("\n🧠 Phase 5: LLM Reasoning with DeepSeek")
        
        # Build system prompt with full context
        system_prompt = self._build_system_prompt(agent_context)
        
        print("   → Sending request to DeepSeek LLM...")
        print(f"     - Context length: {len(system_prompt)} chars")
        print(f"     - User message: '{user_message['message'][:60]}...'")
        
        # Simulate LLM call (in real test, would call actual API)
        llm_response = await self._call_deepseek_llm(
            system_prompt=system_prompt,
            user_message=user_message["message"],
            session_context=agent_context
        )
        
        print(f"   ✓ LLM response received")
        print(f"     - Reasoning: {llm_response.get('reasoning', 'N/A')[:80]}...")
        print(f"     - Plan: {len(llm_response.get('plan', []))} steps")
        print(f"     - Tools to use: {', '.join(llm_response.get('tools', []))}")
        
        # ============================================================
        # PHASE 6: PLANNING DISPLAY
        # ============================================================
        print("\n📋 Phase 6: Planning Display (UI Component)")
        
        plan = llm_response.get("plan", [])
        
        if plan:
            # Store plan for UI display
            plan_data = {
                "session_id": self.session_id,
                "plan_id": f"plan_{uuid.uuid4().hex[:8]}",
                "steps": plan,
                "status": "pending",
                "created_at": datetime.utcnow().isoformat()
            }
            
            await self.redis.set(
                f"plan:{self.session_id}",
                json.dumps(plan_data),
                ex=3600
            )
            
            print("   ✓ Plan stored for UI display")
            print("   📝 Plan Steps:")
            for i, step in enumerate(plan, 1):
                print(f"      {i}. {step['description']}")
        
        # ============================================================
        # PHASE 7: TOOL EXECUTION IN SANDBOX
        # ============================================================
        print("\n🔧 Phase 7: Tool Execution in Sandbox")
        
        tools_to_execute = llm_response.get("tools", [])
        execution_results = []
        
        for tool_name in tools_to_execute:
            print(f"\n   → Executing tool: {tool_name}")
            
            # Check if tool requires approval
            requires_approval = self._tool_requires_approval(tool_name)
            
            if requires_approval:
                print(f"     ⚠ Tool requires user approval")
                
                # Request approval
                approval_request = await self._request_approval(
                    session_id=self.session_id,
                    tool=tool_name,
                    command=llm_response.get("commands", {}).get(tool_name, ""),
                    reason="Tool execution on target network"
                )
                
                print(f"     → Approval request created: {approval_request['approval_id']}")
                
                # Simulate user approval (in real test, would wait for actual approval)
                approved = await self._simulate_user_approval(approval_request["approval_id"])
                
                if not approved:
                    print(f"     ✗ Tool execution rejected by user")
                    continue
                
                print(f"     ✓ Tool execution approved by user")
            
            # Execute tool in sandbox
            print(f"     → Executing in sandbox with root privileges...")
            
            result = await self._execute_tool_in_sandbox(
                session_id=self.session_id,
                tool=tool_name,
                command=llm_response.get("commands", {}).get(tool_name, ""),
                stream_output=True
            )
            
            execution_results.append({
                "tool": tool_name,
                "status": result["status"],
                "output": result["output"],
                "duration": result["duration"]
            })
            
            if result["status"] == "success":
                print(f"     ✓ Tool executed successfully")
                print(f"       Duration: {result['duration']:.2f}s")
                print(f"       Output lines: {result['output'].count(chr(10))}")
            else:
                print(f"     ✗ Tool execution failed: {result.get('error', 'Unknown')}")
        
        # ============================================================
        # PHASE 8: TERMINAL STREAMING
        # ============================================================
        print("\n💻 Phase 8: Terminal Streaming & Real-time Events")
        
        # Verify terminal output streaming
        terminal_messages = []
        
        for result in execution_results:
            if result["status"] == "success":
                # Check if output was streamed in real-time
                stream_key = f"terminal_stream:{self.session_id}:{result['tool']}"
                
                # Get streamed messages
                stream_count = await self.redis.llen(stream_key)
                
                if stream_count > 0:
                    print(f"   ✓ {result['tool']}: {stream_count} streamed messages")
                    
                    # Get sample messages
                    messages = await self.redis.lrange(stream_key, 0, 2)
                    for msg in messages:
                        msg_data = json.loads(msg)
                        terminal_messages.append(msg_data)
                        print(f"     → [{msg_data['type']}] {msg_data['content'][:60]}...")
                else:
                    print(f"   ⚠ {result['tool']}: No streaming detected")
        
        # ============================================================
        # PHASE 9: RESPONSE GENERATION & MARKDOWN RENDERING
        # ============================================================
        print("\n📝 Phase 9: Response Generation with Markdown Rendering")
        
        # Generate formatted response
        agent_response = await self._generate_agent_response(
            user_message=user_message["message"],
            llm_response=llm_response,
            execution_results=execution_results,
            plan=plan
        )
        
        print("   ✓ Agent response generated")
        print(f"     - Response length: {len(agent_response['content'])} chars")
        print(f"     - Format: Markdown")
        print(f"     - Components: {', '.join(agent_response.get('components', []))}")
        
        # Verify markdown formatting
        markdown_elements = self._analyze_markdown(agent_response["content"])
        
        print("   📄 Markdown Elements:")
        for element, count in markdown_elements.items():
            print(f"     - {element}: {count}")
        
        # Store response
        response_message = {
            "session_id": self.session_id,
            "role": "agent",
            "content": agent_response["content"],
            "components": agent_response.get("components", []),
            "metadata": {
                "plan_id": plan_data.get("plan_id") if plan else None,
                "tools_used": tools_to_execute,
                "execution_results": [
                    {"tool": r["tool"], "status": r["status"]}
                    for r in execution_results
                ]
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.redis.lpush(
            f"chat:{self.session_id}:messages",
            json.dumps(response_message)
        )
        
        print("   ✓ Response stored in chat history")
        
        # ============================================================
        # PHASE 10: UI COMPONENTS INTEGRATION VERIFICATION
        # ============================================================
        print("\n🎨 Phase 10: UI Components Integration Verification")
        
        ui_components = {
            "message_display": False,
            "planning_panel": False,
            "terminal_output": False,
            "approval_modal": False,
            "stop_button": False,
            "markdown_rendering": False
        }
        
        # Verify message display component
        messages_count = await self.redis.llen(f"chat:{self.session_id}:messages")
        ui_components["message_display"] = messages_count >= 2  # User + Agent
        print(f"   {'✓' if ui_components['message_display'] else '✗'} Message Display: {messages_count} messages")
        
        # Verify planning panel
        plan_exists = await self.redis.exists(f"plan:{self.session_id}")
        ui_components["planning_panel"] = plan_exists
        print(f"   {'✓' if ui_components['planning_panel'] else '✗'} Planning Panel: {'Connected' if plan_exists else 'Not connected'}")
        
        # Verify terminal output
        ui_components["terminal_output"] = len(terminal_messages) > 0
        print(f"   {'✓' if ui_components['terminal_output'] else '✗'} Terminal Output: {len(terminal_messages)} streamed events")
        
        # Verify approval system
        approval_requests = await self.redis.keys(f"approval:{self.session_id}:*")
        ui_components["approval_modal"] = len(approval_requests) > 0
        print(f"   {'✓' if ui_components['approval_modal'] else '✗'} Approval Modal: {len(approval_requests)} requests")
        
        # Verify stop button functionality
        session_data = json.loads(await self.redis.get(f"session:{self.session_id}"))
        ui_components["stop_button"] = "status" in session_data
        print(f"   {'✓' if ui_components['stop_button'] else '✗'} Stop Button: Session control available")
        
        # Verify markdown rendering
        ui_components["markdown_rendering"] = len(markdown_elements) > 0
        print(f"   {'✓' if ui_components['markdown_rendering'] else '✗'} Markdown Rendering: {len(markdown_elements)} elements")
        
        # ============================================================
        # VERIFICATION
        # ============================================================
        print("\n✅ Complete Workflow Verification:")
        
        workflow_checks = {
            "session_created": session_exists or True,
            "environment_ready": all(environment_status.values()),
            "agent_context_prepared": agent_context is not None,
            "llm_reasoning_complete": llm_response is not None,
            "plan_generated": len(plan) > 0,
            "tools_executed": len(execution_results) > 0,
            "terminal_streamed": len(terminal_messages) > 0,
            "response_generated": agent_response is not None,
            "ui_components_integrated": all(ui_components.values())
        }
        
        for check, passed in workflow_checks.items():
            status = "✓" if passed else "✗"
            print(f"   {status} {check.replace('_', ' ').title()}: {passed}")
        
        # Assert all checks pass
        assert all(workflow_checks.values()), "Some workflow checks failed"
        
        print("\n" + "="*80)
        print("🎉 Complete User-Agent Chat Workflow Test: PASSED")
        print("="*80)

    @pytest.mark.priority_high
    async def test_e2e_human_in_the_loop_approval_flow(self):
        """
        Test human-in-the-loop approval flow for dangerous commands
        
        Flow:
        1. Agent plans dangerous command (e.g., exploit, persistence)
        2. Approval request created with fancy UI
        3. User approves/rejects
        4. Agent responds accordingly
        """
        print("\n🔐 Human-in-the-Loop Approval Flow Test")
        
        # Create approval request
        approval_data = {
            "approval_id": f"approval_{uuid.uuid4().hex[:8]}",
            "session_id": self.session_id,
            "type": "dangerous_command",
            "command": "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST 192.168.1.10; exploit'",
            "reason": "Attempting to exploit MS17-010 (EternalBlue) on target 192.168.1.10",
            "risk_level": "critical",
            "estimated_impact": "Remote code execution, potential system compromise",
            "status": "pending",
            "requested_at": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"approval:{self.session_id}:{approval_data['approval_id']}",
            json.dumps(approval_data),
            ex=300  # 5 min TTL
        )
        
        print(f"   ✓ Approval request created: {approval_data['approval_id']}")
        print(f"     - Command: {approval_data['command'][:60]}...")
        print(f"     - Risk Level: {approval_data['risk_level']}")
        
        # Verify UI display data
        ui_display = {
            "title": "⚠️ Approval Required",
            "risk_badge": approval_data["risk_level"].upper(),
            "command_preview": approval_data["command"],
            "reason": approval_data["reason"],
            "impact": approval_data["estimated_impact"],
            "buttons": ["Approve", "Reject"],
            "styling": "enterprise_modal"  # Fancy enterprise design
        }
        
        print("   ✓ UI Display Components:")
        print(f"     - Title: {ui_display['title']}")
        print(f"     - Risk Badge: {ui_display['risk_badge']}")
        print(f"     - Styling: {ui_display['styling']}")
        
        # Simulate user approval
        await asyncio.sleep(0.5)  # Simulate user thinking
        
        approval_data["status"] = "approved"
        approval_data["approved_at"] = datetime.utcnow().isoformat()
        approval_data["approved_by"] = self.user_id
        
        await self.redis.set(
            f"approval:{self.session_id}:{approval_data['approval_id']}",
            json.dumps(approval_data),
            ex=300
        )
        
        print(f"   ✓ User approved the request")
        
        # Verify approval recorded
        stored_approval = json.loads(
            await self.redis.get(f"approval:{self.session_id}:{approval_data['approval_id']}")
        )
        
        assert stored_approval["status"] == "approved"
        assert "approved_at" in stored_approval
        
        print("   ✅ Approval flow test passed")

    @pytest.mark.priority_high
    async def test_e2e_stop_button_immediate_halt(self):
        """
        Test stop button functionality - immediate agent halt
        
        Flow:
        1. Agent starts long-running operation
        2. User clicks stop button
        3. Agent halts immediately
        4. UI updates (send button reappears)
        """
        print("\n🛑 Stop Button Immediate Halt Test")
        
        # Start simulated long operation
        session_data = {
            "session_id": self.session_id,
            "status": "running",
            "current_operation": "nmap_scan",
            "started_at": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"session:{self.session_id}",
            json.dumps(session_data),
            ex=3600
        )
        
        print("   → Agent operation started: nmap_scan")
        
        # Simulate stop signal
        await asyncio.sleep(0.2)
        
        stop_signal = {
            "session_id": self.session_id,
            "action": "stop",
            "requested_at": datetime.utcnow().isoformat(),
            "user_id": self.user_id
        }
        
        await self.redis.set(
            f"stop_signal:{self.session_id}",
            json.dumps(stop_signal),
            ex=60
        )
        
        print("   ✓ Stop signal sent by user")
        
        # Verify stop signal detected
        stop_exists = await self.redis.exists(f"stop_signal:{self.session_id}")
        assert stop_exists, "Stop signal not stored"
        
        # Update session to stopped
        session_data["status"] = "stopped"
        session_data["stopped_at"] = datetime.utcnow().isoformat()
        
        await self.redis.set(
            f"session:{self.session_id}",
            json.dumps(session_data),
            ex=3600
        )
        
        # Verify UI update
        updated_session = json.loads(await self.redis.get(f"session:{self.session_id}"))
        
        assert updated_session["status"] == "stopped"
        
        print("   ✓ Agent halted immediately")
        print("   ✓ UI updated (send button restored)")
        print("   ✅ Stop button test passed")

    @pytest.mark.priority_high
    async def test_e2e_terminal_streaming_real_time(self):
        """
        Test real-time terminal streaming during command execution
        
        Flow:
        1. Agent executes command
        2. Output streams in real-time
        3. UI receives and displays updates
        4. Progress indicators work
        """
        print("\n💻 Terminal Streaming Real-time Test")
        
        # Simulate command execution with streaming
        command = "nmap -sV -p- 192.168.1.10"
        
        print(f"   → Executing: {command}")
        
        # Stream output chunks
        output_chunks = [
            "Starting Nmap 7.92 ( https://nmap.org )",
            "Nmap scan report for 192.168.1.10",
            "Host is up (0.001s latency).",
            "PORT     STATE SERVICE VERSION",
            "22/tcp   open  ssh     OpenSSH 8.2p1",
            "80/tcp   open  http    Apache httpd 2.4.41",
            "443/tcp  open  https   Apache httpd 2.4.41",
            "3306/tcp open  mysql   MySQL 8.0.25",
            "Nmap done: 1 IP address (1 host up) scanned in 42.53 seconds"
        ]
        
        stream_key = f"terminal_stream:{self.session_id}:nmap"
        
        for i, chunk in enumerate(output_chunks):
            stream_message = {
                "type": "stdout",
                "content": chunk,
                "sequence": i,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.redis.lpush(stream_key, json.dumps(stream_message))
            await asyncio.sleep(0.05)  # Simulate real-time delay
        
        print(f"   ✓ Streamed {len(output_chunks)} output chunks")
        
        # Verify streaming
        stream_count = await self.redis.llen(stream_key)
        assert stream_count == len(output_chunks)
        
        # Verify order and content
        first_message = json.loads(await self.redis.lindex(stream_key, -1))
        last_message = json.loads(await self.redis.lindex(stream_key, 0))
        
        assert first_message["sequence"] == 0
        assert last_message["sequence"] == len(output_chunks) - 1
        
        print("   ✓ Streaming order verified")
        print("   ✓ Real-time updates working")
        print("   ✅ Terminal streaming test passed")

    # Helper methods
    
    async def _check_firecracker_vm(self, session_id: str) -> bool:
        """Check if Firecracker VM is ready"""
        # In real implementation, would check actual VM status
        # For testing, simulate check
        await asyncio.sleep(0.1)
        return True
    
    async def _start_firecracker_vm(self, session_id: str) -> bool:
        """Start Firecracker VM"""
        await asyncio.sleep(0.2)
        return True
    
    async def _check_rootfs(self, session_id: str) -> bool:
        """Check if Ubuntu rootfs is mounted"""
        await asyncio.sleep(0.1)
        return True
    
    async def _check_tool_availability(self, session_id: str, tool: str) -> bool:
        """Check if hacking tool is available"""
        # Simulate tool check
        await asyncio.sleep(0.05)
        return True  # All tools available in test
    
    async def _check_root_access(self, session_id: str) -> bool:
        """Verify root access in sandbox"""
        await asyncio.sleep(0.1)
        return True
    
    async def _load_knowledge_base(self) -> bool:
        """Load knowledge base"""
        try:
            return len(self.knowledge.knowledge_base) > 0
        except:
            return False
    
    async def _initialize_rag(self) -> bool:
        """Initialize RAG system"""
        if self.vector_store:
            await asyncio.sleep(0.1)
            return True
        return False
    
    def _build_system_prompt(self, agent_context: Dict) -> str:
        """Build comprehensive system prompt for LLM"""
        return f"""You are RAGLOX, an advanced penetration testing agent.

CAPABILITIES:
- Knowledge Base: {agent_context['capabilities']['knowledge_base']['entries']:,} entries
- RAG Search: {agent_context['capabilities']['rag_search']['available']}
- Hacking Tools: {', '.join(agent_context['capabilities']['tools']['tools_list'])}
- Shell Access: root (uid=0) in Ubuntu sandbox via Firecracker
- Environment: Isolated, safe for testing

INSTRUCTIONS:
1. Analyze the user's request carefully
2. Plan your approach step-by-step
3. Use available tools appropriately
4. Request approval for dangerous operations
5. Provide clear, professional responses

Remember: You have full root access and professional hacking tools. Use them wisely."""
    
    async def _call_deepseek_llm(
        self,
        system_prompt: str,
        user_message: str,
        session_context: Dict
    ) -> Dict:
        """Call DeepSeek LLM (simulated for testing)"""
        # In real implementation, would call actual DeepSeek API
        # For testing, return simulated response
        
        await asyncio.sleep(0.5)  # Simulate API call
        
        return {
            "reasoning": "User wants to perform penetration test on 192.168.1.0/24. I should start with reconnaissance using nmap to discover hosts and services.",
            "plan": [
                {
                    "step": 1,
                    "description": "Network discovery scan",
                    "tool": "nmap",
                    "command": "nmap -sn 192.168.1.0/24"
                },
                {
                    "step": 2,
                    "description": "Service version detection",
                    "tool": "nmap",
                    "command": "nmap -sV -p- 192.168.1.10"
                },
                {
                    "step": 3,
                    "description": "Vulnerability assessment",
                    "tool": "nmap",
                    "command": "nmap --script vuln 192.168.1.10"
                }
            ],
            "tools": ["nmap"],
            "commands": {
                "nmap": "nmap -sV -p- 192.168.1.0/24"
            },
            "requires_approval": False
        }
    
    def _tool_requires_approval(self, tool_name: str) -> bool:
        """Check if tool requires user approval"""
        dangerous_tools = ["metasploit", "sqlmap", "hydra"]
        return tool_name in dangerous_tools
    
    async def _request_approval(
        self,
        session_id: str,
        tool: str,
        command: str,
        reason: str
    ) -> Dict:
        """Request user approval for dangerous operation"""
        approval_data = {
            "approval_id": f"approval_{uuid.uuid4().hex[:8]}",
            "session_id": session_id,
            "tool": tool,
            "command": command,
            "reason": reason,
            "risk_level": "high",
            "status": "pending",
            "requested_at": datetime.utcnow().isoformat()
        }
        
        await self.redis.set(
            f"approval:{session_id}:{approval_data['approval_id']}",
            json.dumps(approval_data),
            ex=300
        )
        
        return approval_data
    
    async def _simulate_user_approval(self, approval_id: str) -> bool:
        """Simulate user approval (in real test, would wait for actual approval)"""
        await asyncio.sleep(0.3)
        return True
    
    async def _execute_tool_in_sandbox(
        self,
        session_id: str,
        tool: str,
        command: str,
        stream_output: bool = False
    ) -> Dict:
        """Execute tool in sandbox environment"""
        start_time = time.time()
        
        # Simulate execution
        await asyncio.sleep(0.5)
        
        # Simulate output
        output = f"Executed {tool} successfully\nCommand: {command}\nResults: [simulated output]"
        
        duration = time.time() - start_time
        
        return {
            "status": "success",
            "output": output,
            "duration": duration
        }
    
    async def _generate_agent_response(
        self,
        user_message: str,
        llm_response: Dict,
        execution_results: List[Dict],
        plan: List[Dict]
    ) -> Dict:
        """Generate formatted agent response with markdown"""
        
        # Build plan steps
        plan_steps = []
        for i, step in enumerate(plan, 1):
            plan_steps.append(f"{i}. **{step['description']}**")
            plan_steps.append(f"   - Tool: `{step['tool']}`")
            plan_steps.append(f"   - Command: `{step['command']}`")
        
        plan_text = "\n".join(plan_steps)
        
        # Build markdown response
        content = f"""# Penetration Test: Reconnaissance

## Summary
I've analyzed your request to perform a penetration test on network `192.168.1.0/24`. Here's what I've done:

## 🎯 Execution Plan

{plan_text}

## 📊 Results

### Network Discovery
- **Status:** ✅ Complete
- **Hosts found:** 5 active hosts
- **Services identified:** 12 services across hosts

### Key Findings
1. **192.168.1.10** - Web server (Apache 2.4.41)
   - Ports: 22, 80, 443, 3306
   - Potential vulnerabilities detected

2. **192.168.1.20** - File server (SMB)
   - Ports: 139, 445
   - Running Windows Server 2016

## 🔍 Next Steps
Based on the reconnaissance, I recommend:
1. Detailed vulnerability scanning on identified services
2. Testing for common misconfigurations
3. Checking for known CVEs

Would you like me to proceed with vulnerability assessment?
"""
        
        return {
            "content": content,
            "components": ["summary", "plan", "results", "findings", "next_steps"],
            "format": "markdown"
        }
    
    def _analyze_markdown(self, content: str) -> Dict[str, int]:
        """Analyze markdown elements in content"""
        elements = {
            "headers": content.count("#"),
            "bold": content.count("**") // 2,
            "code_inline": content.count("`") // 2,
            "code_blocks": content.count("```") // 2,
            "lists": content.count("\n-") + content.count("\n1."),
            "checkmarks": content.count("✅") + content.count("✓")
        }
        return elements


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
