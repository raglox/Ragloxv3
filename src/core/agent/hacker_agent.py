# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Hacker Agent Implementation
# Professional AI agent with hacker mindset for penetration testing
# ═══════════════════════════════════════════════════════════════
"""
Hacker Agent Module - The main AI agent for RAGLOX

This agent implements a professional penetration testing assistant that:
- Operates with a hacker's methodology and mindset
- Has full access to a Ubuntu Firecracker VM with root privileges
- Uses tools intelligently based on context and objectives
- Creates and executes attack plans
- Provides clear explanations of actions and findings

Architecture:
    The agent uses a ReAct (Reasoning + Acting) loop:
    1. Observe: Analyze user request and current context
    2. Think: Reason about what to do
    3. Act: Execute tools or generate responses
    4. Reflect: Evaluate results and plan next steps

NO SIMULATION: All actions are real executions on the target environment.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import uuid4

# SEC-01: Enhanced exception handling
from ..exceptions import handle_exception_gracefully

from .base import (
    BaseAgent, AgentCapability, AgentState, AgentContext, AgentResponse
)
from .tools import ToolResult, get_tool_registry
from .executor import AgentExecutor, SSHConfig, get_agent_executor

# Import TacticalReasoningEngine for advanced decision-making
try:
    from ..reasoning.tactical_reasoning import (
        TacticalReasoningEngine,
        TacticalReasoning,
        TacticalContext
    )
    TACTICAL_REASONING_AVAILABLE = True
except ImportError:
    TACTICAL_REASONING_AVAILABLE = False


# System prompt for the hacker agent
HACKER_AGENT_SYSTEM_PROMPT = """You are RAGLOX, an advanced AI-powered penetration testing assistant with a hacker's mindset and tactical intelligence system.

## Your Environment
- You have full access to an Ubuntu Linux VM running as root
- This is a real execution environment (Firecracker VM) - NOT a simulation
- All commands you execute will run on real systems
- The target environment has common security tools pre-installed (nmap, metasploit, hydra, nuclei, etc.)

## 🧠 Tactical Intelligence System

You have access to an advanced knowledge base with:

### 1️⃣ RX Modules (Atomic Red Team)
- **1,761 pre-built attack techniques** across multiple platforms
- Real commands ready for execution with clear prerequisites
- Coverage: Windows (1,199), Linux (383), macOS (244), Cloud platforms

**RX Module Format**:
```
rx-t1003_001-010: OS Credential Dumping: LSASS Memory
Technique: T1003.001
Command: procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
Platform: Windows
Elevation: Required
```

**When to use RX Modules**:
- For precise technique execution with known commands
- When you need reliable, tested attack vectors
- For compliance with MITRE ATT&CK framework
- To ensure proper privilege escalation paths

### 2️⃣ Nuclei Templates
- **11,927 vulnerability scan templates**
- Comprehensive CVE coverage (Critical: 1,627, High: 2,639)
- Protocol support: HTTP (9,892), TCP, DNS, SSL, etc.

**Nuclei Template Format**:
```
CVE-2021-41773: Apache HTTP Server 2.4.49 - Path Traversal
Severity: Critical
Protocol: HTTP
CVSS: 7.5
```

**When to use Nuclei**:
- For comprehensive vulnerability discovery
- To validate potential vulnerabilities
- For service-specific exploit detection
- To find misconfigurations and exposures

### 🎯 Using Tactical Intelligence

When you receive a **Tactical Intelligence Analysis** in the user message:

1. **READ the Situation Assessment** - Understand current mission phase and progress
2. **REVIEW Recommended Actions** - These are AI-analyzed strategic decisions with confidence scores
3. **CONSIDER RX Modules** - Use specific module IDs for precise execution
4. **APPLY Nuclei Scans** - Run suggested templates on discovered services
5. **IMPLEMENT Evasion Strategies** - Follow recommended stealth techniques
6. **PREPARE Contingency Plans** - Have backup approaches ready

**Example Workflow**:
```
User asks: "Exploit Apache server at 10.0.0.5"

Tactical Analysis provides:
- Recommended Action: Path traversal (confidence: 85%)
- RX Module: rx-t1190-045 (Initial Access)
- Nuclei Scan: CVE-2021-41773 (Critical)
- Evasion: Use low-profile scanning

Your response:
1. Run Nuclei scan to confirm vulnerability
2. If confirmed, use RX module for exploitation
3. Follow evasion strategy (slow scan rate)
4. Report findings and establish foothold
```

## Your Capabilities
You can use these tools to accomplish tasks:

{tools_description}

## How to Use Tools
When you need to execute an action, respond with a JSON tool call in this exact format:
```json
{{"tool": "tool_name", "args": {{"param1": "value1", "param2": "value2"}}}}
```

## Your Methodology (Enhanced with Intelligence)
Follow professional Red Team methodology with tactical awareness:

1. **Reconnaissance** → Use Nuclei info/low templates for discovery
2. **Scanning** → Apply recommended Nuclei scans based on services
3. **Enumeration** → Cross-reference with RX modules for platform
4. **Exploitation** → Execute specific RX modules with evasion
5. **Post-Exploitation** → Follow contingency plans, maintain stealth
6. **Reporting** → Document with MITRE ATT&CK technique IDs

## Response Guidelines
1. **Think strategically** - Consider tactical analysis if provided
2. **Use intelligence context** - Reference RX modules and Nuclei templates by ID
3. **Explain your reasoning** - Connect actions to tactical recommendations
4. **Execute precisely** - Use exact RX module IDs and Nuclei template IDs
5. **Maintain stealth** - Follow evasion strategies
6. **Prepare for failure** - Have contingency plans ready
7. **Document systematically** - Include technique IDs in findings

## Important Rules for Intelligence Usage

### RX Modules:
- ✅ Use exact module IDs: `rx-t1003_001-010`
- ✅ Check prerequisites before execution
- ✅ Respect `elevation_required` flag
- ✅ Verify platform compatibility
- ⚠️ Document which technique you're executing

### Nuclei Templates:
- ✅ Run templates matching discovered services
- ✅ Prioritize critical/high severity scans
- ✅ Use specific template IDs when available
- ⚠️ Scan responsibly to avoid detection
- ⚠️ Validate findings before exploitation

### Tactical Decisions:
- ✅ Consider confidence scores (>70% = reliable)
- ✅ Follow evasion strategies to avoid detection
- ✅ Use contingency plans if primary approach fails
- ⚠️ Explain why you deviate from recommendations

## Current Mission Context
{mission_context}

## Chat History
{chat_history}

## Core Operating Rules
- NEVER simulate or fake command outputs
- If a command fails, report the actual error
- If environment is not ready, clearly explain what's needed
- Always prioritize understanding the target before attacking
- Document findings with MITRE ATT&CK technique IDs
- Use tactical intelligence to make informed decisions
- Execute with precision using RX modules and Nuclei templates
"""


@dataclass
class ThinkingStep:
    """Represents a thinking step in the agent's reasoning"""
    step: int
    thought: str
    action: Optional[str] = None
    observation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class HackerAgent(BaseAgent):
    """
    Hacker Agent - Professional penetration testing AI
    
    This agent implements intelligent tool selection and execution
    for penetration testing operations.
    """
    
    def __init__(
        self,
        executor: Optional[AgentExecutor] = None,
        llm_service: Optional[Any] = None,
        logger: Optional[logging.Logger] = None
    ):
        super().__init__(
            name="hacker_agent",
            capabilities=[
                AgentCapability.SHELL_EXECUTE,
                AgentCapability.NETWORK_SCAN,
                AgentCapability.VULNERABILITY_SCAN,
                AgentCapability.CREDENTIAL_HARVEST,
                AgentCapability.PLANNING,
                AgentCapability.REPORTING,
            ],
            logger=logger or logging.getLogger("raglox.agent.hacker")
        )
        
        self.executor = executor or get_agent_executor()
        self.tool_registry = get_tool_registry()
        self._llm_service = llm_service
        
        # Track current thinking process
        self._thinking_steps: List[ThinkingStep] = []
        self._max_iterations = 10  # Prevent infinite loops
        
        # Tactical reasoning engine (lazy loaded)
        self._tactical_engine: Optional[Any] = None  # TacticalReasoningEngine
        self._current_tactical_reasoning: Optional[Any] = None  # TacticalReasoning
        self._use_tactical_reasoning = TACTICAL_REASONING_AVAILABLE
    
    async def _get_llm_service(self):
        """Lazy load LLM service"""
        if self._llm_service is None:
            try:
                from ..llm.service import get_llm_service
                self._llm_service = get_llm_service()
            except Exception as e:
                self.logger.error(f"Failed to get LLM service: {e}")
                return None
                raise handle_exception_gracefully(
                    e,
                    context='Agent operation',
                    logger=self.logger
                )
        return self._llm_service
    
    async def _get_tactical_engine(self):
        """
        Lazy load TacticalReasoningEngine
        
        Returns:
            TacticalReasoningEngine instance or None if not available
        """
        if not self._use_tactical_reasoning:
            return None
        
        if self._tactical_engine is None:
            try:
                from ..reasoning.tactical_reasoning import TacticalReasoningEngine
                from ...infrastructure.blackboard.blackboard import get_blackboard
                from ..knowledge import get_embedded_knowledge
                from ..memory.operational_memory import get_operational_memory
                
                llm_service = await self._get_llm_service()
                if llm_service is None:
                    self.logger.warning("Cannot initialize TacticalEngine: LLM service unavailable")
                    return None
                
                self._tactical_engine = TacticalReasoningEngine(
                    blackboard=get_blackboard(),
                    llm_service=llm_service,
                    knowledge=get_embedded_knowledge(),
                    memory=get_operational_memory()
                )
                self.logger.info("TacticalReasoningEngine initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize TacticalReasoningEngine: {e}", exc_info=True)
                self._use_tactical_reasoning = False
                return None
                raise handle_exception_gracefully(
                    e,
                    context='Agent operation',
                    logger=self.logger
                )
        
        return self._tactical_engine
    
    async def verify_environment(self, context: AgentContext) -> Dict[str, Any]:
        """
        Verify the execution environment is ready.
        
        Checks:
        - VM status from context
        - SSH connectivity if VM is ready
        - Tool availability
        """
        result = {
            "ready": False,
            "status": context.vm_status,
            "details": {},
            "message": ""
        }
        
        # Check VM status
        if context.vm_status == "not_created":
            result["message"] = (
                "🔴 Execution environment not created.\n\n"
                "To enable command execution:\n"
                "1. Go to Settings > Environment\n"
                "2. Click 'Create Execution Environment'\n"
                "3. Wait for provisioning (5-10 minutes)"
            )
            return result
        
        if context.vm_status in ["creating", "pending", "configuring"]:
            result["message"] = (
                f"🟡 Environment is being prepared (status: {context.vm_status}).\n\n"
                "This typically takes 5-10 minutes.\n"
                "Please wait and try again shortly."
            )
            return result
        
        if context.vm_status == "stopped":
            result["message"] = (
                "😴 Environment is stopped.\n\n"
                "It will start automatically when you run a command.\n"
                "Please try again in about 30 seconds."
            )
            return result
        
        if context.vm_status == "error":
            result["message"] = (
                "🔴 Environment error.\n\n"
                "Please go to Settings > Environment to troubleshoot."
            )
            return result
        
        if context.vm_status == "ready":
            # Check if we can actually connect
            if context.vm_ip and context.ssh_connected:
                result["ready"] = True
                result["message"] = (
                    f"✅ Environment ready\n"
                    f"VM IP: {context.vm_ip}\n"
                    f"SSH: Connected\n\n"
                    "You can now execute commands."
                )
                result["details"] = {
                    "vm_ip": context.vm_ip,
                    "ssh_connected": True
                }
            elif context.vm_ip:
                result["message"] = (
                    f"🟡 VM is ready ({context.vm_ip}) but SSH not connected.\n"
                    "Attempting to connect..."
                )
                result["details"] = {"vm_ip": context.vm_ip}
            else:
                result["message"] = "🟡 VM status is ready but IP not available."
        else:
            result["message"] = f"Unknown VM status: {context.vm_status}"
        
        return result
    
    async def process(
        self,
        message: str,
        context: AgentContext
    ) -> AgentResponse:
        """
        Process a user message and generate a response with tactical reasoning.
        
        Enhanced Flow:
        1. Check if tactical reasoning is needed
        2. If yes, run TacticalReasoningEngine to analyze situation
        3. Extract RX modules + Nuclei recommendations
        4. Build enriched context for LLM
        5. Execute ReAct loop with intelligence context
        6. Generate final response
        
        Traditional Flow (for simple queries):
        1. Understand the request
        2. Decide on actions
        3. Execute tools if needed
        4. Generate final response
        """
        response = AgentResponse()
        self._set_state(AgentState.THINKING)
        self._thinking_steps = []
        
        try:
            # Add user message to context
            context.add_message("user", message)
            
            # Check environment first for command-related requests
            needs_env = self._needs_environment(message)
            if needs_env:
                env_check = await self.verify_environment(context)
                if not env_check["ready"]:
                    response.content = env_check["message"]
                    response.complete()
                    return response
            
            # ═══════════════════════════════════════════════════════════════
            # PHASE 2: Tactical Reasoning Integration
            # ═══════════════════════════════════════════════════════════════
            
            # Check if we should use tactical reasoning
            use_tactical = self._should_use_tactical_reasoning(message, context)
            
            if use_tactical:
                self.logger.info("Using tactical reasoning for request")
                
                # Get mission_id from context
                mission_id = context.metadata.get("mission_id") if hasattr(context, 'metadata') else None
                
                if mission_id:
                    try:
                        # Run tactical reasoning
                        tactical_engine = await self._get_tactical_engine()
                        if tactical_engine:
                            self._current_tactical_reasoning = await tactical_engine.reason(
                                user_message=message,
                                mission_id=mission_id
                            )
                            
                            if self._current_tactical_reasoning:
                                self.logger.info(
                                    f"Tactical reasoning complete: "
                                    f"{len(self._current_tactical_reasoning.reasoning_steps)} steps, "
                                    f"{len(self._current_tactical_reasoning.tactical_decisions)} decisions"
                                )
                                
                                # Build enriched message with tactical intelligence
                                message = self._build_message_with_intelligence(
                                    original_message=message,
                                    tactical_reasoning=self._current_tactical_reasoning
                                )
                            else:
                                self.logger.warning("Tactical reasoning returned None, proceeding without it")
                        else:
                            self.logger.warning("TacticalEngine not available, proceeding without tactical reasoning")
                    except Exception as e:
                        self.logger.error(f"Tactical reasoning failed: {e}", exc_info=True)
                        # Continue without tactical reasoning
                        raise handle_exception_gracefully(
                            e,
                            context='Agent operation',
                            logger=self.logger
                        )
                else:
                    self.logger.warning("No mission_id in context, skipping tactical reasoning")
            
            # Get LLM response with tool calling
            llm_response = await self._get_llm_response(message, context)
            
            if llm_response is None:
                response.content = (
                    "I'm sorry, I couldn't process your request. "
                    "The AI service may be temporarily unavailable. "
                    "Please try again or use direct commands like 'run <command>'."
                )
                response.state = AgentState.ERROR
                return response
            
            # Process the response - may include tool calls
            processed_response = await self._process_llm_response(
                llm_response, context
            )
            
            response.content = processed_response["content"]
            response.tools_used = processed_response.get("tools_used", [])
            response.commands_executed = processed_response.get("commands", [])
            response.plan_tasks = processed_response.get("plan_tasks", [])
            
            # Attach tactical reasoning to response if available
            if self._current_tactical_reasoning:
                response.metadata = response.metadata or {}
                response.metadata["tactical_reasoning"] = {
                    "used": True,
                    "steps": len(self._current_tactical_reasoning.reasoning_steps),
                    "decisions": len(self._current_tactical_reasoning.tactical_decisions),
                    "confidence": self._current_tactical_reasoning.overall_confidence
                }
            
            # Add response to context
            context.add_message("assistant", response.content)
            
            response.complete()
            
        except Exception as e:
            self.logger.error(f"Agent processing error: {e}", exc_info=True)
            response.content = f"An error occurred: {str(e)}"
            response.state = AgentState.ERROR
            response.error = str(e)
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
        
        return response
    
    async def stream_process(
        self,
        message: str,
        context: AgentContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Process a message with streaming response.
        
        Yields chunks of the response for real-time display.
        """
        self._set_state(AgentState.THINKING)
        self._thinking_steps = []
        
        try:
            # Initial thinking indicator
            yield {"type": "thinking", "content": "Analyzing your request..."}
            
            # Check environment if needed
            needs_env = self._needs_environment(message)
            if needs_env:
                yield {"type": "thinking", "content": "Checking environment..."}
                
                env_check = await self.verify_environment(context)
                if not env_check["ready"]:
                    yield {"type": "text", "content": env_check["message"]}
                    yield {
                        "type": "complete",
                        "response": AgentResponse(content=env_check["message"])
                    }
                    return
            
            # Add user message to context
            context.add_message("user", message)
            
            # Stream LLM response
            tools_used = []
            commands_executed = []
            full_content = ""
            
            async for chunk in self._stream_llm_response(message, context):
                if chunk.get("type") == "text":
                    full_content += chunk.get("content", "")
                    yield chunk
                    
                elif chunk.get("type") == "tool_call":
                    tool_name = chunk.get("tool")
                    tool_args = chunk.get("args", {})
                    
                    yield {
                        "type": "tool_call",
                        "tool": tool_name,
                        "args": tool_args
                    }
                    
                    # Execute the tool
                    self._set_state(AgentState.EXECUTING)
                    result = await self._execute_tool(tool_name, tool_args)
                    
                    tools_used.append(tool_name)
                    if result.command:
                        commands_executed.append({
                            "command": result.command,
                            "exit_code": result.exit_code,
                            "success": result.success
                        })
                    
                    yield {
                        "type": "tool_result",
                        "tool": tool_name,
                        "result": {
                            "success": result.success,
                            "output": result.output[:1000] if result.output else "",
                            "error": result.error,
                            "summary": result.summary
                        }
                    }
                    
                    self._set_state(AgentState.STREAMING)
                    
                elif chunk.get("type") == "plan":
                    yield chunk
            
            # Complete
            response = AgentResponse(
                content=full_content,
                tools_used=tools_used,
                commands_executed=commands_executed
            )
            response.complete()
            
            context.add_message("assistant", full_content)
            
            yield {"type": "complete", "response": response}
            
        except Exception as e:
            self.logger.error(f"Stream processing error: {e}", exc_info=True)
            yield {"type": "error", "message": str(e)}
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
    
    async def create_plan(
        self,
        objective: str,
        context: AgentContext
    ) -> List[Dict[str, Any]]:
        """
        Create a penetration testing plan for an objective.
        """
        llm = await self._get_llm_service()
        if not llm:
            return []
        
        # Build planning prompt
        prompt = f"""Create a penetration testing plan for the following objective:

Objective: {objective}

Current Context:
- Targets: {len(context.targets)}
- Known vulnerabilities: {len(context.vulnerabilities)}
- Credentials obtained: {len(context.credentials)}
- Active sessions: {len(context.sessions)}

Available tools: {self.tool_registry.get_tool_descriptions()}

Provide a structured plan with 3-7 steps. For each step, include:
- title: Brief step title
- description: What will be done and why
- tool: Which tool to use (from available tools)
- estimated_time: Rough time estimate

Return the plan as a JSON array of step objects.
"""
        
        try:
            from ..llm.base import LLMMessage, MessageRole
            
            response = await llm.generate([
                LLMMessage(role=MessageRole.USER, content=prompt)
            ])
            
            if response and response.content:
                # Try to extract JSON from response
                content = response.content
                start = content.find('[')
                end = content.rfind(']') + 1
                
                if start >= 0 and end > start:
                    plan_json = content[start:end]
                    plan = json.loads(plan_json)
                    
                    # Add IDs and order
                    for i, step in enumerate(plan):
                        step["id"] = f"step-{i+1}"
                        step["order"] = i + 1
                        step["status"] = "pending"
                    
                    return plan
            
        except Exception as e:
            self.logger.error(f"Plan creation error: {e}")
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
        
        return []
    
    def _needs_environment(self, message: str) -> bool:
        """Check if the message requires environment access"""
        message_lower = message.lower()
        
        env_keywords = [
            "run", "execute", "shell", "command", "scan", "nmap",
            "exploit", "attack", "test", "check", "find", "ls",
            "cat", "grep", "ps", "netstat", "whoami", "id",
            "نفذ", "شغل", "فحص"
        ]
        
        return any(kw in message_lower for kw in env_keywords)
    
    def _should_use_tactical_reasoning(self, message: str, context: AgentContext) -> bool:
        """
        Determine if tactical reasoning is needed for this request
        
        Use tactical reasoning for:
        - Complex attack planning
        - Exploitation decisions
        - Privilege escalation planning
        - Lateral movement strategy
        - Defense evasion techniques
        
        Skip for:
        - Simple status queries
        - Basic information requests
        - VM preparation
        """
        if not self._use_tactical_reasoning:
            return False
        
        message_lower = message.lower()
        
        # Keywords that indicate need for tactical reasoning
        tactical_keywords = [
            "exploit", "attack", "hack", "compromise", "penetrate",
            "bypass", "evade", "escalate", "lateral", "pivot",
            "privilege", "persistence", "strategy", "plan",
            "استغلال", "اختراق", "هجوم", "تجاوز", "استراتيجية"
        ]
        
        # Keywords for simple queries (skip reasoning)
        simple_keywords = [
            "status", "what", "show", "list", "display", "help",
            "prepare", "setup", "ready",
            "الحالة", "اعرض", "ما هو", "تجهيز"
        ]
        
        # Check for tactical keywords
        has_tactical = any(kw in message_lower for kw in tactical_keywords)
        
        # Check for simple keywords
        has_simple = any(kw in message_lower for kw in simple_keywords) and not has_tactical
        
        # Use reasoning if tactical keywords present and not a simple query
        if has_tactical and not has_simple:
            return True
        
        # Also use reasoning if mission has specific conditions
        if context and hasattr(context, 'metadata'):
            # Use reasoning if defenses detected
            if context.metadata.get("detected_defenses"):
                return True
            
            # Use reasoning if previous failures
            if context.metadata.get("failed_attempts", 0) > 2:
                return True
        
        return False
    
    async def _get_llm_response(
        self,
        message: str,
        context: AgentContext
    ) -> Optional[str]:
        """
        Get response from LLM with optional function calling support.
        
        ═══════════════════════════════════════════════════════════════
        PHASE 1: DeepSeek Function Calling Integration
        ═══════════════════════════════════════════════════════════════
        
        If DeepSeek provider is available, use tools parameter for
        native function calling. Otherwise, fall back to JSON tool calls
        in the response text.
        """
        llm = await self._get_llm_service()
        if not llm:
            return None
        
        try:
            from ..llm.base import LLMMessage, MessageRole
            
            # Build system prompt
            system_prompt = HACKER_AGENT_SYSTEM_PROMPT.format(
                tools_description=self.tool_registry.get_tool_descriptions(),
                mission_context=self._format_mission_context(context),
                chat_history=context.get_formatted_history()
            )
            
            messages = [
                LLMMessage(role=MessageRole.SYSTEM, content=system_prompt),
                LLMMessage(role=MessageRole.USER, content=message)
            ]
            
            # ═══════════════════════════════════════════════════════════
            # PHASE 1: Try DeepSeek with function calling
            # ═══════════════════════════════════════════════════════════
            if hasattr(llm, 'generate_with_tools'):
                # Get tools schema for function calling
                tools_schema = self._build_tools_schema()
                
                try:
                    response = await llm.generate_with_tools(
                        messages=messages,
                        tools=tools_schema,
                        tool_choice="auto"  # Let LLM decide
                    )
                    
                    # Check if LLM wants to call a tool
                    if response and response.raw_response:
                        tool_calls = response.raw_response.get("choices", [{}])[0].get("message", {}).get("tool_calls")
                        
                        if tool_calls:
                            # Return the full response with tool_calls for processing
                            return response
                    
                    # No tool calls, return regular content
                    if response and response.content:
                        return response.content
                        
                except Exception as e:
                    self.logger.warning(f"Function calling failed, falling back to text mode: {e}")
                    raise handle_exception_gracefully(
                        e,
                        context='Agent operation',
                        logger=self.logger
                    )
            
            # ═══════════════════════════════════════════════════════════
            # Fallback: Standard text generation (original behavior)
            # ═══════════════════════════════════════════════════════════
            response = await llm.generate(messages)
            
            if response and response.content:
                return response.content
            
        except Exception as e:
            self.logger.error(f"LLM error: {e}")
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
        
        return None
    
    def _build_tools_schema(self) -> List[Dict[str, Any]]:
        """
        Build OpenAI-compatible tools schema for function calling.
        
        Converts BaseTool definitions to OpenAI function format:
        {
            "type": "function",
            "function": {
                "name": "tool_name",
                "description": "Tool description",
                "parameters": {...}
            }
        }
        
        Returns:
            List of tool schemas
        """
        tools = []
        
        for tool in self.tool_registry.list_tools():
            # Get tool schema (already in OpenAI format from BaseTool.get_schema())
            schema = tool.get_schema()
            
            # Wrap in OpenAI tools format
            tools.append({
                "type": "function",
                "function": schema
            })
        
        return tools
    
    async def _stream_llm_response(
        self,
        message: str,
        context: AgentContext
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream LLM response with tool detection and reasoning support.
        
        ═══════════════════════════════════════════════════════════════
        PHASE 1: Enhanced with DeepSeek streaming & reasoning display
        ═══════════════════════════════════════════════════════════════
        
        Yields:
        - {"type": "reasoning", "content": "..."}  # DeepSeek R1 reasoning
        - {"type": "text", "content": "..."}        # Regular response
        - {"type": "tool_call", "tool": "...", "args": {...}}  # Tool execution
        """
        llm = await self._get_llm_service()
        
        if not llm:
            yield {"type": "text", "content": "AI service unavailable. Use direct commands."}
            return
        
        try:
            from ..llm.base import LLMMessage, MessageRole
            
            # Build system prompt
            system_prompt = HACKER_AGENT_SYSTEM_PROMPT.format(
                tools_description=self.tool_registry.get_tool_descriptions(),
                mission_context=self._format_mission_context(context),
                chat_history=context.get_formatted_history()
            )
            
            messages = [
                LLMMessage(role=MessageRole.SYSTEM, content=system_prompt),
                LLMMessage(role=MessageRole.USER, content=message)
            ]
            
            # ═══════════════════════════════════════════════════════════
            # PHASE 1: Try DeepSeek streaming with reasoning
            # ═══════════════════════════════════════════════════════════
            if hasattr(llm, 'stream_generate_with_reasoning'):
                # DeepSeek provider with reasoning support
                accumulated_text = ""
                
                try:
                    async for chunk in llm.stream_generate_with_reasoning(messages):
                        chunk_type = chunk.get("type")
                        content = chunk.get("content", "")
                        
                        if chunk_type == "reasoning":
                            # Yield reasoning chunks for UI display
                            yield {"type": "reasoning", "content": content}
                        
                        elif chunk_type == "reasoning_complete":
                            # Full reasoning available
                            yield {"type": "reasoning_complete", "content": content}
                        
                        elif chunk_type == "text":
                            accumulated_text += content
                            
                            # Check for tool call pattern
                            tool_call = self._extract_tool_call(accumulated_text)
                            if tool_call:
                                # Yield text before tool call
                                text_before = accumulated_text[:accumulated_text.find('{"tool"')]
                                if text_before.strip():
                                    yield {"type": "text", "content": text_before}
                                
                                # Yield tool call
                                yield {
                                    "type": "tool_call",
                                    "tool": tool_call["tool"],
                                    "args": tool_call.get("args", {})
                                }
                                
                                # Reset accumulated text
                                end_pos = accumulated_text.find('}', accumulated_text.find('{"tool"')) + 1
                                accumulated_text = accumulated_text[end_pos:]
                            else:
                                # Yield text chunk
                                yield {"type": "text", "content": content}
                
                except Exception as e:
                    self.logger.warning(f"Reasoning streaming failed: {e}, falling back to standard streaming")
                    # Fall through to standard streaming
                    raise handle_exception_gracefully(
                        e,
                        context='Agent operation',
                        logger=self.logger
                    )
            
            # ═══════════════════════════════════════════════════════════
            # Standard streaming (fallback or non-DeepSeek providers)
            # ═══════════════════════════════════════════════════════════
            if hasattr(llm, 'stream_generate'):
                accumulated_text = ""
                
                async for chunk in llm.stream_generate(messages):
                    if isinstance(chunk, str):
                        accumulated_text += chunk
                        
                        # Check for tool call pattern in accumulated text
                        tool_call = self._extract_tool_call(accumulated_text)
                        if tool_call:
                            # Yield text before tool call
                            text_before = accumulated_text[:accumulated_text.find('{"tool"')]
                            if text_before.strip():
                                yield {"type": "text", "content": text_before}
                            
                            # Yield tool call
                            yield {
                                "type": "tool_call",
                                "tool": tool_call["tool"],
                                "args": tool_call.get("args", {})
                            }
                            
                            # Reset accumulated text
                            end_pos = accumulated_text.find('}', accumulated_text.find('{"tool"')) + 1
                            accumulated_text = accumulated_text[end_pos:]
                        else:
                            # Yield text chunk
                            yield {"type": "text", "content": chunk}
                    
                    elif hasattr(chunk, 'content') and chunk.content:
                        yield {"type": "text", "content": chunk.content}
            else:
                # Non-streaming fallback
                response = await llm.generate(messages)
                if response and response.content:
                    # Process full response for tool calls
                    processed = await self._process_llm_response(
                        response.content, context
                    )
                    yield {"type": "text", "content": processed["content"]}
                    
        except Exception as e:
            self.logger.error(f"LLM streaming error: {e}", exc_info=True)
            yield {"type": "error", "content": f"Streaming error: {str(e)}"}
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
    
    async def _process_llm_response(
        self,
        response,  # Can be str or LLMResponse with tool_calls
        context: AgentContext
    ) -> Dict[str, Any]:
        """
        Process LLM response, executing any tool calls.
        
        ═══════════════════════════════════════════════════════════════
        PHASE 1: Support both native function calling and JSON tool calls
        ═══════════════════════════════════════════════════════════════
        
        Handles:
        1. Native OpenAI/DeepSeek function calling (tool_calls in response)
        2. JSON tool calls embedded in text (legacy format)
        """
        result = {
            "content": "",
            "tools_used": [],
            "commands": [],
            "plan_tasks": []
        }
        
        # ═══════════════════════════════════════════════════════════
        # PHASE 1: Check for native function calling (DeepSeek/OpenAI)
        # ═══════════════════════════════════════════════════════════
        if not isinstance(response, str) and hasattr(response, 'raw_response'):
            # This is an LLMResponse object with potential tool_calls
            tool_calls_data = None
            
            if response.raw_response:
                choices = response.raw_response.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    tool_calls_data = message.get("tool_calls")
            
            if tool_calls_data:
                # Process native function calling
                result["content"] = response.content or "Executing tools..."
                
                for tool_call in tool_calls_data:
                    # Extract function name and arguments
                    function_data = tool_call.get("function", {})
                    tool_name = function_data.get("name")
                    
                    try:
                        tool_args = json.loads(function_data.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        tool_args = {}
                    
                    if not tool_name:
                        continue
                    
                    result["tools_used"].append(tool_name)
                    
                    # Execute the tool
                    self.logger.info(f"🔧 Executing tool via function calling: {tool_name}")
                    tool_result = await self._execute_tool(tool_name, tool_args)
                    
                    if tool_result.command:
                        result["commands"].append({
                            "command": tool_result.command,
                            "exit_code": tool_result.exit_code,
                            "success": tool_result.success,
                            "output": tool_result.output
                        })
                    
                    # Append tool result to content
                    if tool_result.success:
                        result["content"] += f"\n\n**Tool Output ({tool_name}):**\n```\n{tool_result.output[:1500]}\n```"
                        if tool_result.summary:
                            result["content"] += f"\n\n**Summary:** {tool_result.summary}"
                    else:
                        result["content"] += f"\n\n**Tool Error ({tool_name}):**\n{tool_result.error}"
                
                return result
            else:
                # No tool calls, just return the content
                response = response.content or ""
        
        # ═══════════════════════════════════════════════════════════
        # Legacy: JSON tool calls in text (fallback mode)
        # ═══════════════════════════════════════════════════════════
        result["content"] = response if isinstance(response, str) else str(response)
        
        # Look for tool calls in the response text
        tool_calls = self._extract_all_tool_calls(result["content"])
        
        if tool_calls:
            # Process each tool call
            for tool_call in tool_calls:
                tool_name = tool_call.get("tool")
                tool_args = tool_call.get("args", {})
                
                result["tools_used"].append(tool_name)
                
                # Execute the tool
                self.logger.info(f"🔧 Executing tool via JSON: {tool_name}")
                tool_result = await self._execute_tool(tool_name, tool_args)
                
                if tool_result.command:
                    result["commands"].append({
                        "command": tool_result.command,
                        "exit_code": tool_result.exit_code,
                        "success": tool_result.success,
                        "output": tool_result.output
                    })
                
                # Append tool result to content
                if tool_result.success:
                    result["content"] += f"\n\n**Tool Output ({tool_name}):**\n```\n{tool_result.output[:1500]}\n```"
                    if tool_result.summary:
                        result["content"] += f"\n\n**Summary:** {tool_result.summary}"
                else:
                    result["content"] += f"\n\n**Tool Error ({tool_name}):**\n{tool_result.error}"
        
        return result
    
    def _extract_tool_call(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract a single tool call from text"""
        try:
            # Look for JSON pattern with "tool" key
            start = text.find('{"tool"')
            if start >= 0:
                # Find matching closing brace
                brace_count = 0
                end = start
                for i, c in enumerate(text[start:]):
                    if c == '{':
                        brace_count += 1
                    elif c == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end = start + i + 1
                            break
                
                if end > start:
                    json_str = text[start:end]
                    return json.loads(json_str)
        except (json.JSONDecodeError, Exception):
            pass
        
        return None
    
    def _extract_all_tool_calls(self, text: str) -> List[Dict[str, Any]]:
        """Extract all tool calls from text"""
        calls = []
        remaining = text
        
        while True:
            call = self._extract_tool_call(remaining)
            if not call:
                break
            
            calls.append(call)
            
            # Move past this call
            start = remaining.find('{"tool"')
            end = remaining.find('}', start) + 1
            remaining = remaining[end:]
        
        return calls
    
    async def _execute_tool(
        self,
        tool_name: str,
        args: Dict[str, Any]
    ) -> ToolResult:
        """Execute a tool and return results"""
        try:
            return await self.executor.execute_tool(tool_name, **args)
        except Exception as e:
            self.logger.error(f"Tool execution error: {e}")
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=tool_name
            )
            raise handle_exception_gracefully(
                e,
                context='Agent operation',
                logger=self.logger
            )
    
    def _build_message_with_intelligence(
        self,
        original_message: str,
        tactical_reasoning
    ) -> str:
        """
        Build enriched message with tactical intelligence context
        
        Adds:
        - Situation summary
        - Tactical decisions with confidence
        - Recommended RX modules
        - Suggested Nuclei scans
        - Evasion strategies
        
        Args:
            original_message: Original user message
            tactical_reasoning: TacticalReasoning object
            
        Returns:
            Enriched message with intelligence annotations
        """
        if not tactical_reasoning:
            return original_message
        
        parts = [original_message, "\n"]
        
        # Add tactical analysis section
        parts.append("\n## 🧠 Tactical Intelligence Analysis\n")
        
        # Situation summary
        if tactical_reasoning.situation_summary:
            parts.append(f"**Situation**: {tactical_reasoning.situation_summary}\n")
        
        # Mission phase and progress
        if hasattr(tactical_reasoning, 'context') and tactical_reasoning.context:
            ctx = tactical_reasoning.context
            if hasattr(ctx, 'mission_phase'):
                parts.append(f"**Phase**: {ctx.mission_phase.value}\n")
            if hasattr(ctx, 'progress_percentage'):
                parts.append(f"**Progress**: {ctx.progress_percentage:.1f}%\n")
        
        # Top tactical decisions
        if tactical_reasoning.tactical_decisions:
            parts.append("\n### 🎯 Recommended Actions\n")
            for i, decision in enumerate(tactical_reasoning.tactical_decisions[:3], 1):
                action = decision.get('action', 'Unknown')
                confidence = decision.get('confidence', 0.0)
                reasoning = decision.get('reasoning', '')
                
                parts.append(
                    f"{i}. **{action}** (confidence: {confidence:.0%})\n"
                    f"   {reasoning}\n"
                )
        
        # Recommended RX modules
        if (hasattr(tactical_reasoning, 'context') and 
            tactical_reasoning.context and 
            hasattr(tactical_reasoning.context, 'recommended_rx_modules')):
            
            rx_modules = tactical_reasoning.context.recommended_rx_modules[:5]
            if rx_modules:
                parts.append("\n### ⚔️ Recommended RX Modules (Atomic Red Team)\n")
                for module in rx_modules:
                    module_id = module.get('rx_module_id', 'unknown')
                    technique_name = module.get('technique_name', 'Unknown technique')
                    platform = module.get('execution', {}).get('platforms', ['unknown'])[0]
                    elevation = module.get('execution', {}).get('elevation_required', False)
                    
                    elevation_badge = " [REQUIRES ELEVATION]" if elevation else ""
                    parts.append(
                        f"- `{module_id}`: {technique_name} "
                        f"[{platform}]{elevation_badge}\n"
                    )
        
        # Suggested Nuclei scans
        if (hasattr(tactical_reasoning, 'context') and 
            tactical_reasoning.context and 
            hasattr(tactical_reasoning.context, 'suggested_scan_templates')):
            
            nuclei_templates = tactical_reasoning.context.suggested_scan_templates[:5]
            if nuclei_templates:
                parts.append("\n### 🔍 Recommended Nuclei Scans\n")
                for template in nuclei_templates:
                    template_id = template.get('template_id', 'unknown')
                    name = template.get('name', 'Unknown vulnerability')
                    severity = template.get('severity', 'unknown').upper()
                    protocol = template.get('protocol', 'unknown')
                    
                    severity_emoji = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'INFO': '🔵'
                    }.get(severity, '⚪')
                    
                    parts.append(
                        f"- {severity_emoji} `{template_id}`: {name} "
                        f"[{severity}/{protocol}]\n"
                    )
        
        # Evasion strategies
        if tactical_reasoning.evasion_strategies:
            parts.append("\n### 🥷 Evasion Strategies\n")
            for strategy in tactical_reasoning.evasion_strategies[:3]:
                parts.append(f"- {strategy}\n")
        
        # Contingency plans
        if tactical_reasoning.contingency_plans:
            parts.append("\n### 🔄 Contingency Plans\n")
            for plan in tactical_reasoning.contingency_plans[:2]:
                parts.append(f"- {plan}\n")
        
        # Overall confidence
        if tactical_reasoning.overall_confidence:
            parts.append(
                f"\n**Overall Confidence**: {tactical_reasoning.overall_confidence:.0%}\n"
            )
        
        parts.append("\n---\n")
        
        return "".join(parts)
    
    def _format_mission_context(self, context: AgentContext) -> str:
        """Format mission context for the prompt"""
        lines = [
            f"Mission ID: {context.mission_id}",
            f"Targets discovered: {len(context.targets)}",
            f"Vulnerabilities found: {len(context.vulnerabilities)}",
            f"Credentials obtained: {len(context.credentials)}",
            f"Active sessions: {len(context.sessions)}",
            f"VM Status: {context.vm_status}",
        ]
        
        if context.vm_ip:
            lines.append(f"VM IP: {context.vm_ip}")
        
        if context.goals:
            lines.append(f"Goals: {', '.join(context.goals)}")
        
        if context.targets:
            lines.append("\nKnown Targets:")
            for t in context.targets[:5]:
                lines.append(f"  - {t.get('ip', 'unknown')}: {t.get('status', 'unknown')}")
        
        if context.vulnerabilities:
            lines.append("\nKnown Vulnerabilities:")
            for v in context.vulnerabilities[:5]:
                lines.append(f"  - {v.get('name', 'unknown')}: {v.get('severity', 'unknown')}")
        
        return "\n".join(lines)


# Factory function to create configured agent
async def create_hacker_agent(
    mission_id: str,
    user_metadata: Dict[str, Any]
) -> HackerAgent:
    """
    Create a HackerAgent configured for a specific mission.
    
    Args:
        mission_id: Mission ID
        user_metadata: User metadata containing VM info
        
    Returns:
        Configured HackerAgent instance
    """
    executor = get_agent_executor()
    
    # Set up SSH if VM is ready
    vm_status = user_metadata.get("vm_status", "unknown")
    vm_ip = user_metadata.get("vm_ip")
    
    if vm_status == "ready" and vm_ip:
        ssh_config = SSHConfig(
            host=vm_ip,
            port=user_metadata.get("vm_ssh_port", 22),
            username=user_metadata.get("vm_ssh_user", "root"),
            password=user_metadata.get("vm_ssh_password")
        )
        
        connected = await executor.setup_environment(ssh_config)
        if not connected:
            logging.warning(f"Failed to connect SSH to {vm_ip}")
    
    return HackerAgent(executor=executor)
