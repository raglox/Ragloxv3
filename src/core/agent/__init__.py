# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - AI Agent Framework
# Enterprise-grade agent architecture with tool calling capabilities
# ═══════════════════════════════════════════════════════════════
"""
RAGLOX AI Agent Framework - Hacker-Mindset Agent Implementation

This module provides a professional AI agent framework that:
- Operates with real Ubuntu Firecracker VMs under root access
- Implements ReAct (Reasoning + Acting) pattern for intelligent decision making
- Provides tool calling capabilities similar to Copilot/Claude agents
- Executes real penetration testing commands on target environments

Architecture:
    AgentExecutive (Planning & Strategy)
        └── AgentCoordinator (Tool Selection & Execution)
                └── Tools (Shell, Network, Exploit, etc.)

Design Principles:
    - NO SIMULATION: All executions are real
    - Tool-based Architecture: LLM reasons about which tool to use
    - Streaming Support: Real-time response streaming
    - Environment Awareness: Verifies VM status before execution
    - Professional Logging: Full audit trail of all actions
"""

from .base import BaseAgent, AgentCapability, AgentState
from .tools import BaseTool, ToolResult, ToolRegistry
from .executor import AgentExecutor
from .hacker_agent import HackerAgent

__all__ = [
    "BaseAgent",
    "AgentCapability", 
    "AgentState",
    "BaseTool",
    "ToolResult",
    "ToolRegistry",
    "AgentExecutor",
    "HackerAgent",
]
