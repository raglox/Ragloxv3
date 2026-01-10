# 🚀 Phase 1: Agent Integration Implementation Plan

**Duration:** 5-7 days  
**Goal:** Connect HackerAgent with MissionController for intelligent chat responses

---

## 📋 Task Breakdown

### Day 1: Setup & Foundation
- [x] Create feature branch: `feature/enterprise-ai-agent`
- [ ] Add agent management to MissionController
- [ ] Implement `_get_or_create_agent()` method
- [ ] Add agent lifecycle management
- [ ] Write unit tests for agent creation

### Day 2: Context Building
- [ ] Implement `_build_agent_context()` method
- [ ] Add VM metadata fetching
- [ ] Add chat history formatting
- [ ] Add mission state aggregation
- [ ] Test context building with mock data

### Day 3: Chat Integration
- [ ] Refactor `_process_chat_message()` to use agent
- [ ] Replace if/else logic with agent.process()
- [ ] Handle agent responses properly
- [ ] Add error handling and fallbacks
- [ ] Test basic chat flow

### Day 4: Streaming Support
- [ ] Implement `stream_chat_response()` method
- [ ] Add streaming endpoint in routes.py
- [ ] Integrate with WebSocket broadcaster
- [ ] Test streaming with frontend
- [ ] Handle streaming errors gracefully

### Day 5: LLM Integration
- [ ] Verify LLM service configuration
- [ ] Test with different LLM providers
- [ ] Add provider fallback logic
- [ ] Optimize token usage
- [ ] Test response quality

### Day 6: Testing & Debugging
- [ ] Integration tests for full flow
- [ ] Test with real missions
- [ ] Test error scenarios
- [ ] Performance testing
- [ ] Memory leak checks

### Day 7: Documentation & PR
- [ ] Update API documentation
- [ ] Write developer guide
- [ ] Create demo video/screenshots
- [ ] Submit Pull Request
- [ ] Code review and iterations

---

## 🔧 Technical Implementation Details

### 1. Agent Management in MissionController

```python
# src/controller/mission.py

class MissionController:
    def __init__(self, ...):
        # ... existing init code ...
        
        # Agent management
        self._agents: Dict[str, HackerAgent] = {}
        self._agent_contexts: Dict[str, AgentContext] = {}
        self._agent_lock = asyncio.Lock()  # Thread-safe agent creation
    
    async def _get_or_create_agent(self, mission_id: str) -> HackerAgent:
        """
        Get or create HackerAgent for a mission.
        
        Thread-safe agent creation with caching.
        """
        async with self._agent_lock:
            if mission_id not in self._agents:
                self.logger.info(f"Creating new HackerAgent for mission {mission_id}")
                
                # Get user metadata (VM info, SSH config)
                user_metadata = await self._get_user_vm_metadata(mission_id)
                
                # Create agent
                agent = await create_hacker_agent(
                    mission_id=mission_id,
                    user_metadata=user_metadata
                )
                
                self._agents[mission_id] = agent
                
                self.logger.info(f"HackerAgent created for mission {mission_id}")
            
            return self._agents[mission_id]
    
    async def _cleanup_agent(self, mission_id: str):
        """Cleanup agent when mission is completed/stopped"""
        if mission_id in self._agents:
            agent = self._agents.pop(mission_id)
            # Cleanup agent resources if needed
            self.logger.info(f"Cleaned up HackerAgent for mission {mission_id}")
```

### 2. Context Building

```python
async def _build_agent_context(self, mission_id: str) -> AgentContext:
    """
    Build comprehensive agent context from mission state.
    
    Includes:
    - Mission details (name, goals, status)
    - Targets discovered
    - Vulnerabilities found
    - Credentials harvested
    - Active sessions
    - VM/Environment status
    - Chat history
    """
    try:
        # Fetch all mission data in parallel
        results = await asyncio.gather(
            self.get_mission(mission_id),
            self.get_targets(mission_id),
            self.get_vulnerabilities(mission_id),
            self.get_credentials(mission_id),
            self.get_sessions(mission_id),
            self._get_user_vm_metadata(mission_id),
            return_exceptions=True
        )
        
        mission, targets, vulns, creds, sessions, vm_metadata = results
        
        # Handle errors in individual fetches
        if isinstance(mission, Exception):
            self.logger.error(f"Failed to get mission: {mission}")
            mission = None
        
        # Build context
        context = AgentContext(
            mission_id=mission_id,
            mission_name=mission.name if mission else None,
            goals=mission.goals if mission else [],
            targets=[t.model_dump() for t in (targets if not isinstance(targets, Exception) else [])],
            vulnerabilities=[v.model_dump() for v in (vulns if not isinstance(vulns, Exception) else [])],
            credentials=[c.model_dump() for c in (creds if not isinstance(creds, Exception) else [])],
            sessions=[s.model_dump() for s in (sessions if not isinstance(sessions, Exception) else [])],
            vm_status=vm_metadata.get("vm_status", "unknown") if not isinstance(vm_metadata, Exception) else "unknown",
            vm_ip=vm_metadata.get("vm_ip") if not isinstance(vm_metadata, Exception) else None,
            ssh_connected=vm_metadata.get("ssh_connected", False) if not isinstance(vm_metadata, Exception) else False,
            chat_history=self._chat_history.get(mission_id, [])
        )
        
        return context
        
    except Exception as e:
        self.logger.error(f"Failed to build agent context: {e}", exc_info=True)
        # Return minimal context
        return AgentContext(
            mission_id=mission_id,
            vm_status="unknown"
        )
```

### 3. New Chat Processing Logic

```python
async def _process_chat_message(
    self,
    mission_id: str,
    message: ChatMessage
) -> Optional[ChatMessage]:
    """
    Process chat message using HackerAgent.
    
    NEW IMPLEMENTATION:
    - Uses HackerAgent instead of if/else logic
    - Passes full context to agent
    - Handles agent responses with rich formatting
    - Includes error handling with graceful fallback
    """
    try:
        # Get agent for this mission
        agent = await self._get_or_create_agent(mission_id)
        
        # Build context
        context = await self._build_agent_context(mission_id)
        
        self.logger.info(f"Processing message with agent: {message.content[:50]}...")
        
        # Process with agent
        agent_response = await agent.process(message.content, context)
        
        # Extract command if executed
        command = None
        output = None
        if agent_response.commands_executed:
            last_cmd = agent_response.commands_executed[-1]
            command = last_cmd.get("command")
            output = last_cmd.get("output", [])
            if isinstance(output, list):
                output = "\n".join(output)
        
        # Create response message
        response_message = ChatMessage(
            mission_id=message.mission_id,
            role="assistant",
            content=agent_response.content,
            command=command,
            output=output
        )
        
        # Broadcast events if tools were used
        if agent_response.tools_used:
            try:
                from ..api.websocket import broadcast_ai_plan
                await broadcast_ai_plan(
                    mission_id=mission_id,
                    tasks=[{
                        "id": f"tool-{i}",
                        "title": tool,
                        "status": "completed",
                        "order": i + 1
                    } for i, tool in enumerate(agent_response.tools_used)],
                    message="Agent executed tools",
                    reasoning="Processing user request"
                )
            except Exception as e:
                self.logger.warning(f"Failed to broadcast AI plan: {e}")
        
        return response_message
        
    except Exception as e:
        self.logger.error(f"Agent processing failed: {e}", exc_info=True)
        
        # Fallback to simple response
        return ChatMessage(
            mission_id=message.mission_id,
            role="assistant",
            content=(
                f"⚠️ **معذرة، حدث خطأ أثناء معالجة طلبك**\n\n"
                f"الخطأ: {str(e)}\n\n"
                f"يمكنك المحاولة مرة أخرى أو استخدام أوامر مباشرة مثل:\n"
                f"- `run ls -la` للحصول على قائمة الملفات\n"
                f"- `scan target` لبدء الفحص\n"
                f"- `status` لمعرفة حالة المهمة"
            )
        )
```

### 4. Streaming Implementation

```python
async def stream_chat_response(
    self,
    mission_id: str,
    message: str
) -> AsyncIterator[Dict[str, Any]]:
    """
    Stream chat response using HackerAgent.
    
    Yields chunks of response for real-time display.
    """
    try:
        # Get agent
        agent = await self._get_or_create_agent(mission_id)
        
        # Build context
        context = await self._build_agent_context(mission_id)
        
        # Stream from agent
        async for chunk in agent.stream_process(message, context):
            # Broadcast via WebSocket
            try:
                from ..api.websocket import broadcast_streaming_chunk
                await broadcast_streaming_chunk(mission_id, chunk)
            except Exception as e:
                self.logger.warning(f"Failed to broadcast chunk: {e}")
            
            yield chunk
            
    except Exception as e:
        self.logger.error(f"Streaming failed: {e}", exc_info=True)
        yield {
            "type": "error",
            "message": f"عذراً، حدث خطأ: {str(e)}"
        }
```

---

## 🧪 Testing Strategy

### Unit Tests
```python
# tests/controller/test_agent_integration.py

async def test_agent_creation():
    """Test agent is created correctly"""
    controller = MissionController()
    agent = await controller._get_or_create_agent("test-mission-id")
    assert agent is not None
    assert isinstance(agent, HackerAgent)

async def test_agent_caching():
    """Test agent is cached and reused"""
    controller = MissionController()
    agent1 = await controller._get_or_create_agent("test-mission-id")
    agent2 = await controller._get_or_create_agent("test-mission-id")
    assert agent1 is agent2  # Same instance

async def test_context_building():
    """Test context is built correctly"""
    controller = MissionController()
    context = await controller._build_agent_context("test-mission-id")
    assert context.mission_id == "test-mission-id"
    assert isinstance(context.targets, list)

async def test_chat_processing():
    """Test chat message is processed by agent"""
    controller = MissionController()
    message = ChatMessage(
        mission_id=UUID("..."),
        role="user",
        content="Show me mission status"
    )
    response = await controller._process_chat_message("test-mission-id", message)
    assert response is not None
    assert response.role == "assistant"
    assert len(response.content) > 0
```

### Integration Tests
```python
# tests/integration/test_agent_e2e.py

async def test_full_chat_flow():
    """Test complete chat flow from API to agent"""
    # Create mission
    # Send chat message via API
    # Verify agent processes it
    # Check response quality
    pass

async def test_streaming_flow():
    """Test streaming chat response"""
    # Create mission
    # Send streaming request
    # Verify chunks are received
    # Check final response
    pass
```

---

## 📊 Success Criteria

### Phase 1 Complete When:
- ✅ Agent is created for each mission
- ✅ Chat messages are processed by agent (not if/else)
- ✅ Context is passed correctly
- ✅ LLM responses are generated
- ✅ Streaming works
- ✅ All tests pass
- ✅ No performance degradation
- ✅ Memory usage is stable

### Quality Checks:
- Response time < 2 seconds for simple queries
- Response time < 5 seconds for complex queries with tool use
- Agent responses are intelligent and contextual
- No crashes or exceptions in normal operation
- Graceful error handling

---

## 🚨 Risks & Mitigation

### Risk 1: LLM Service Unavailable
**Mitigation:** 
- Implement fallback to simple responses
- Show clear error message to user
- Retry logic with exponential backoff

### Risk 2: Performance Issues
**Mitigation:**
- Implement agent caching
- Optimize context building
- Use connection pooling

### Risk 3: Context Too Large
**Mitigation:**
- Implement context window management
- Summarize old messages
- Only include recent findings

### Risk 4: Memory Leaks
**Mitigation:**
- Implement agent cleanup on mission end
- Monitor memory usage
- Add resource limits

---

## 📝 Documentation Updates Needed

1. **API Documentation:**
   - Update chat endpoint documentation
   - Add streaming endpoint docs
   - Document new response format

2. **Developer Guide:**
   - How agents work
   - How to extend agent capabilities
   - How to add new tools

3. **User Guide:**
   - New chat capabilities
   - Example prompts
   - Tips for best results

---

## ✅ Definition of Done

Phase 1 is complete when:
- [ ] All code is written and committed
- [ ] All tests pass (unit + integration)
- [ ] Code review completed
- [ ] Documentation updated
- [ ] Pull Request merged
- [ ] Deployed to staging
- [ ] User acceptance testing passed

---

**Next Steps:** Start with Day 1 tasks and proceed sequentially. Update this document as you progress.
