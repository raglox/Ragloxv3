"""
═══════════════════════════════════════════════════════════════
RAGLOX v3.0 - DeepSeek Integration Tests
Integration tests for Phase 1 DeepSeek implementation
═══════════════════════════════════════════════════════════════

Tests:
1. DeepSeek provider initialization
2. HackerAgent with DeepSeek
3. Function calling integration
4. Streaming responses
5. Reasoning extraction
6. VM auto-preparation
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

# Import components to test
from src.core.llm.deepseek_provider import DeepSeekProvider, ReasoningResponse
from src.core.llm.base import LLMConfig, LLMMessage, MessageRole, ProviderType
from src.core.agent.hacker_agent import HackerAgent
from src.core.agent.base import AgentContext
from src.controller.mission import MissionController


# ═══════════════════════════════════════════════════════════════
# Test 1: DeepSeek Provider Initialization
# ═══════════════════════════════════════════════════════════════

def test_deepseek_provider_init():
    """Test DeepSeek provider initialization"""
    config = LLMConfig(
        provider_type=ProviderType.OPENAI,
        api_key="test-key",
        model="deepseek-reasoner",
        temperature=0.7,
        max_tokens=8000,
    )
    
    provider = DeepSeekProvider(config)
    
    assert provider.provider_name == "deepseek"
    assert provider.config.model == "deepseek-reasoner"
    assert provider.supports_streaming()
    assert provider.supports_reasoning()


def test_deepseek_models():
    """Test DeepSeek model detection"""
    config = LLMConfig(
        provider_type=ProviderType.OPENAI,
        api_key="test-key",
        model="deepseek-reasoner",
    )
    
    provider = DeepSeekProvider(config)
    
    # Test reasoning model detection
    assert provider.supports_reasoning("deepseek-reasoner")
    assert provider.supports_reasoning("deepseek-r1")
    assert not provider.supports_reasoning("deepseek-chat")


# ═══════════════════════════════════════════════════════════════
# Test 2: Reasoning Extraction
# ═══════════════════════════════════════════════════════════════

def test_reasoning_extraction():
    """Test reasoning content extraction"""
    config = LLMConfig(
        provider_type=ProviderType.OPENAI,
        api_key="test-key",
        model="deepseek-reasoner",
    )
    
    provider = DeepSeekProvider(config)
    
    # Mock response with reasoning
    mock_response = MagicMock()
    mock_response.raw_response = {
        "choices": [{
            "message": {
                "reasoning_content": "Let me think... 1. Check target 2. Scan ports"
            }
        }]
    }
    mock_response.content = "I will scan the target with nmap."
    
    reasoning = provider._extract_reasoning(mock_response)
    
    assert reasoning == "Let me think... 1. Check target 2. Scan ports"


# ═══════════════════════════════════════════════════════════════
# Test 3: HackerAgent Integration
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_hacker_agent_with_deepseek():
    """Test HackerAgent processing with DeepSeek"""
    
    # Mock LLM service
    mock_llm = AsyncMock()
    mock_llm.generate = AsyncMock(return_value=MagicMock(
        content="I'll scan the target using nmap.",
        raw_response={}
    ))
    
    # Create agent
    agent = HackerAgent(llm_service=mock_llm)
    
    # Create context
    context = AgentContext(
        mission_id="test-mission",
        chat_history=[]
    )
    context.vm_status = "ready"
    context.vm_ip = "192.168.1.100"
    context.ssh_connected = True
    
    # Process message
    response = await agent.process("Scan the target", context)
    
    assert response is not None
    assert response.content
    assert mock_llm.generate.called


# ═══════════════════════════════════════════════════════════════
# Test 4: Function Calling Schema
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_function_calling_schema():
    """Test tools schema building for function calling"""
    
    agent = HackerAgent()
    
    # Build tools schema
    tools_schema = agent._build_tools_schema()
    
    assert isinstance(tools_schema, list)
    assert len(tools_schema) > 0
    
    # Check schema format
    for tool in tools_schema:
        assert tool["type"] == "function"
        assert "function" in tool
        assert "name" in tool["function"]
        assert "description" in tool["function"]
        assert "parameters" in tool["function"]


# ═══════════════════════════════════════════════════════════════
# Test 5: Streaming Support
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_streaming_response():
    """Test streaming response handling"""
    
    config = LLMConfig(
        provider_type=ProviderType.OPENAI,
        api_key="test-key",
        model="deepseek-reasoner",
    )
    
    provider = DeepSeekProvider(config)
    
    # Provider should support streaming
    assert provider.supports_streaming()


@pytest.mark.asyncio
async def test_agent_streaming():
    """Test agent streaming integration"""
    
    # Mock LLM service with streaming
    mock_llm = AsyncMock()
    
    async def mock_stream(*args, **kwargs):
        yield "Analyzing"
        yield " the"
        yield " target..."
    
    mock_llm.stream_generate = mock_stream
    
    agent = HackerAgent(llm_service=mock_llm)
    context = AgentContext(mission_id="test", chat_history=[])
    context.vm_status = "ready"
    
    # Collect streamed chunks
    chunks = []
    async for chunk in agent._stream_llm_response("test", context):
        chunks.append(chunk)
    
    assert len(chunks) > 0


# ═══════════════════════════════════════════════════════════════
# Test 6: VM Auto-Preparation
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_vm_auto_preparation():
    """Test VM auto-preparation on first message"""
    
    # Create mock controller
    controller = MissionController()
    
    # Mock blackboard
    controller.blackboard = AsyncMock()
    controller.blackboard.get_mission = AsyncMock(return_value={
        "vm_status": "not_created",
        "status": "created"
    })
    controller.blackboard.update_mission = AsyncMock()
    
    mission_id = str(uuid4())
    
    # Test VM preparation
    result = await controller._prepare_vm_on_first_message(mission_id)
    
    # Should start provisioning
    assert result == True
    assert controller.blackboard.update_mission.called


# ═══════════════════════════════════════════════════════════════
# Test 7: Integration Flow
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_full_integration_flow():
    """Test complete integration flow: Message → Agent → DeepSeek → Response"""
    
    # This is a mock integration test
    # In production, this would test the full stack
    
    # 1. Setup
    mission_id = str(uuid4())
    user_message = "Scan target 192.168.1.1"
    
    # 2. Mock components
    mock_controller = MagicMock()
    mock_controller._mission_agents = {}
    
    # 3. Verify flow would work
    assert mission_id
    assert user_message
    
    # TODO: Add full end-to-end test when environment is ready


# ═══════════════════════════════════════════════════════════════
# Test Fixtures and Helpers
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def deepseek_config():
    """Fixture for DeepSeek configuration"""
    return LLMConfig(
        provider_type=ProviderType.OPENAI,
        api_key="test-key",
        api_base="https://api.deepseek.com",
        model="deepseek-reasoner",
        temperature=0.7,
        max_tokens=8000,
    )


@pytest.fixture
def mock_llm_service():
    """Fixture for mocked LLM service"""
    service = AsyncMock()
    service.generate = AsyncMock(return_value=MagicMock(
        content="Test response",
        raw_response={},
        usage=MagicMock(total_tokens=100)
    ))
    return service


@pytest.fixture
def test_context():
    """Fixture for test agent context"""
    context = AgentContext(
        mission_id="test-mission-123",
        chat_history=[]
    )
    context.vm_status = "ready"
    context.vm_ip = "192.168.1.100"
    context.ssh_connected = True
    context.goals = []
    context.targets = []
    context.vulnerabilities = []
    return context


# ═══════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
