# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Base Agent Architecture
# Foundation classes for the AI Agent framework
# ═══════════════════════════════════════════════════════════════
"""
Base Agent Module - Core abstractions for AI agents

Provides:
- AgentState: Tracks agent's current state and context
- AgentCapability: Defines what the agent can do
- BaseAgent: Abstract base class for all agents
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID, uuid4
import logging


class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"                    # Waiting for input
    THINKING = "thinking"            # Analyzing/planning
    EXECUTING = "executing"          # Running a tool
    WAITING = "waiting"              # Waiting for user input (HITL)
    STREAMING = "streaming"          # Streaming response
    ERROR = "error"                  # Error state
    COMPLETED = "completed"          # Task completed


class AgentCapability(Enum):
    """Capabilities an agent can have"""
    SHELL_EXECUTE = "shell_execute"              # Execute shell commands
    NETWORK_SCAN = "network_scan"                # Network reconnaissance  
    VULNERABILITY_SCAN = "vulnerability_scan"    # Vulnerability assessment
    EXPLOIT_EXECUTE = "exploit_execute"          # Run exploits
    CREDENTIAL_HARVEST = "credential_harvest"    # Extract credentials
    LATERAL_MOVEMENT = "lateral_movement"        # Move between systems
    PERSISTENCE = "persistence"                  # Establish persistence
    DATA_EXFIL = "data_exfil"                   # Data extraction
    REPORTING = "reporting"                      # Generate reports
    PLANNING = "planning"                        # Create attack plans


@dataclass
class AgentContext:
    """
    Context information for agent execution.
    
    This contains all the information the agent needs to make decisions
    and execute actions within a mission.
    """
    mission_id: str
    user_id: str
    organization_id: str
    
    # Environment info
    vm_status: str = "unknown"
    vm_ip: Optional[str] = None
    ssh_connected: bool = False
    
    # Mission context
    targets: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    sessions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Goals and constraints
    goals: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    
    # Chat history (last N messages for context)
    chat_history: List[Dict[str, str]] = field(default_factory=list)
    max_history: int = 20
    
    # Current state
    current_plan: Optional[Dict[str, Any]] = None
    pending_approvals: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_message(self, role: str, content: str) -> None:
        """Add a message to chat history, maintaining max size"""
        self.chat_history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
        if len(self.chat_history) > self.max_history:
            self.chat_history = self.chat_history[-self.max_history:]
    
    def get_formatted_history(self) -> str:
        """Get chat history formatted for LLM context"""
        formatted = []
        for msg in self.chat_history:
            formatted.append(f"{msg['role'].upper()}: {msg['content']}")
        return "\n".join(formatted)


@dataclass
class AgentResponse:
    """
    Structured response from an agent.
    
    Contains both the content and metadata about what actions
    were taken or are planned.
    """
    id: UUID = field(default_factory=uuid4)
    content: str = ""
    
    # What happened
    tools_used: List[str] = field(default_factory=list)
    commands_executed: List[Dict[str, Any]] = field(default_factory=list)
    
    # Plan (if planning was done)
    plan_tasks: List[Dict[str, Any]] = field(default_factory=list)
    
    # For HITL
    requires_approval: bool = False
    approval_request: Optional[Dict[str, Any]] = None
    
    # Status
    state: AgentState = AgentState.COMPLETED
    error: Optional[str] = None
    
    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    def complete(self) -> None:
        """Mark response as complete"""
        self.completed_at = datetime.utcnow()
        if self.state != AgentState.ERROR:
            self.state = AgentState.COMPLETED


class BaseAgent(ABC):
    """
    Abstract base class for all RAGLOX agents.
    
    Agents implement the cognitive layer that processes user requests,
    plans actions, selects tools, and orchestrates execution.
    """
    
    def __init__(
        self,
        name: str,
        capabilities: List[AgentCapability],
        logger: Optional[logging.Logger] = None
    ):
        self.id = uuid4()
        self.name = name
        self.capabilities = capabilities
        self.state = AgentState.IDLE
        self.logger = logger or logging.getLogger(f"raglox.agent.{name}")
        
        # Track execution
        self._current_context: Optional[AgentContext] = None
        self._execution_count = 0
    
    @property
    def has_capability(self) -> Dict[AgentCapability, bool]:
        """Quick lookup for capabilities"""
        return {cap: cap in self.capabilities for cap in AgentCapability}
    
    @abstractmethod
    async def process(
        self,
        message: str,
        context: AgentContext
    ) -> AgentResponse:
        """
        Process a user message and generate a response.
        
        This is the main entry point for agent interaction.
        
        Args:
            message: User's message/command
            context: Current context including mission info, history, etc.
            
        Returns:
            AgentResponse with the agent's response and any actions taken
        """
        pass
    
    @abstractmethod
    async def stream_process(
        self,
        message: str,
        context: AgentContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Process a message with streaming response.
        
        Yields chunks of the response as they're generated,
        enabling real-time display.
        
        Yields:
            Dict with type and data:
            - {"type": "thinking", "content": "..."}
            - {"type": "text", "content": "..."}
            - {"type": "tool_call", "tool": "...", "args": {...}}
            - {"type": "tool_result", "tool": "...", "result": {...}}
            - {"type": "plan", "tasks": [...]}
            - {"type": "complete", "response": AgentResponse}
        """
        pass
    
    @abstractmethod
    async def verify_environment(self, context: AgentContext) -> Dict[str, Any]:
        """
        Verify the execution environment is ready.
        
        This should check:
        - VM is created and running
        - SSH connection is possible
        - Required tools are available
        
        Returns:
            Dict with status and details:
            {
                "ready": bool,
                "status": str,
                "details": Dict,
                "message": str  # Human-readable status
            }
        """
        pass
    
    async def create_plan(
        self,
        objective: str,
        context: AgentContext
    ) -> List[Dict[str, Any]]:
        """
        Create an execution plan for an objective.
        
        Override this to customize planning behavior.
        
        Args:
            objective: What to accomplish
            context: Current context
            
        Returns:
            List of plan tasks with structure:
            [
                {
                    "id": str,
                    "title": str,
                    "description": str,
                    "status": "pending" | "running" | "completed" | "failed",
                    "order": int,
                    "tool": str,  # Tool to use
                    "args": Dict,  # Arguments for the tool
                }
            ]
        """
        return []
    
    def _set_state(self, state: AgentState) -> None:
        """Update agent state with logging"""
        old_state = self.state
        self.state = state
        self.logger.debug(f"State: {old_state.value} -> {state.value}")
    
    def __repr__(self) -> str:
        caps = [c.value for c in self.capabilities]
        return f"<{self.__class__.__name__} name={self.name} caps={caps}>"
