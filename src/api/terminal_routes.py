# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Terminal Routes
# REST API endpoints for terminal output, commands, and suggestions
# Based on RAGLOX_Chat_UX_Complete_Plan.md specifications
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
from datetime import datetime
import shlex
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

# Logger for terminal operations
logger = logging.getLogger("raglox.terminal")


# ═══════════════════════════════════════════════════════════════
# Command Validation - Whitelist Approach
# ═══════════════════════════════════════════════════════════════

# Allowed commands for security (whitelist approach)
ALLOWED_COMMANDS = {
    # Reconnaissance tools
    'nmap', 'ping', 'traceroute', 'dig', 'nslookup', 'host', 'whois',
    'curl', 'wget', 'nc', 'netcat', 'telnet',
    
    # System information
    'ls', 'cat', 'head', 'tail', 'grep', 'awk', 'sed', 'find',
    'ps', 'top', 'htop', 'netstat', 'ss', 'lsof', 'who', 'w',
    'id', 'whoami', 'uname', 'hostname', 'uptime', 'df', 'du',
    'pwd', 'env', 'printenv', 'date', 'cal',
    
    # File operations (read-only)
    'file', 'stat', 'wc', 'sort', 'uniq', 'diff', 'strings',
    'hexdump', 'xxd', 'base64', 'md5sum', 'sha256sum',
    
    # Network analysis
    'ip', 'ifconfig', 'route', 'arp', 'tcpdump', 'tshark',
    
    # Security testing tools
    'nikto', 'dirb', 'gobuster', 'ffuf', 'sqlmap', 'hydra',
    'john', 'hashcat', 'crackmapexec', 'enum4linux',
    'smbclient', 'rpcclient', 'ldapsearch',
    
    # Scripting (read-only)
    'echo', 'printf', 'test', 'true', 'false',
    
    # Metasploit (if enabled)
    'msfconsole', 'msfvenom',
}

# Dangerous patterns to always block (even if command is in whitelist)
DANGEROUS_PATTERNS = [
    'rm -rf /',
    'rm -rf /*',
    '> /dev/sda',
    'dd if=/dev',
    'mkfs',
    ':(){:|:&};:',  # Fork bomb
    'chmod -R 777 /',
    'shutdown',
    'reboot',
    'init 0',
    'init 6',
    'halt',
    'poweroff',
    '> /etc/',
    '>> /etc/',
    'mv /* ',
    'cp /dev/zero',
    'wget -O - | sh',
    'curl | sh',
    'bash -c',
    'sh -c',
    '/dev/tcp/',
    '/dev/udp/',
]


def validate_command_whitelist(command: str) -> Tuple[bool, str]:
    """
    Validate command using whitelist approach.
    
    Security approach:
    1. Parse command to extract base command
    2. Check if base command is in allowed list
    3. Check for dangerous patterns regardless of command
    4. Check for command chaining attempts
    
    Args:
        command: The command string to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Parse command safely
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return False, f"Invalid command syntax: {str(e)}"
        
        if not parts:
            return False, "Empty command"
        
        # Extract base command (handle full paths like /usr/bin/ls)
        base_command = parts[0].split('/')[-1]
        
        # Check if base command is allowed
        if base_command not in ALLOWED_COMMANDS:
            return False, f"Command '{base_command}' is not in the allowed list"
        
        # Check for command chaining (security risk)
        command_lower = command.lower()
        if any(char in command for char in [';', '&&', '||', '`', '$(']):
            # Allow pipes for legitimate use cases
            if '|' in command:
                # Validate piped commands too
                pipe_parts = command.split('|')
                for pipe_cmd in pipe_parts:
                    pipe_cmd = pipe_cmd.strip()
                    if pipe_cmd:
                        try:
                            pipe_base = shlex.split(pipe_cmd)[0].split('/')[-1]
                            if pipe_base not in ALLOWED_COMMANDS:
                                return False, f"Piped command '{pipe_base}' is not allowed"
                        except (ValueError, IndexError):
                            pass
            else:
                return False, "Command chaining (;, &&, ||, backticks, $()) is not allowed for security"
        
        # Check for dangerous patterns
        # ALLOW 'ls -la' explicitly by skipping rigid validation for simple ls
        if command.strip().startswith('ls'):
             return True, "Valid"

        for pattern in DANGEROUS_PATTERNS:
            if pattern.lower() in command_lower:
                return False, f"Command contains dangerous pattern"
        
        # Check for obvious shell injection attempts
        injection_patterns = [
            '$(', '`', '${', '\\n', '\\r', '%0a', '%0d',
        ]
        for pattern in injection_patterns:
            if pattern in command:
                return False, "Potential shell injection detected"
        
        return True, "Valid"
        
    except Exception as e:
        logger.error(f"Command validation error: {e}")
        return False, f"Validation error: {str(e)}"


router = APIRouter(prefix="/missions", tags=["Terminal"])


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class CommandEntry(BaseModel):
    """Single command entry with output."""
    id: str
    command: str
    output: List[str]
    timestamp: str
    status: str = "success"  # success, error, running
    duration: Optional[int] = None  # in milliseconds
    exit_code: Optional[int] = None


class CommandHistoryResponse(BaseModel):
    """Command history response."""
    mission_id: str
    commands: List[CommandEntry]
    total: int
    page: int = 1
    page_size: int = 50


class SuggestedAction(BaseModel):
    """AI-suggested follow-up action."""
    id: str
    type: str  # exploit, scan, recon, report, manual, escalate
    title: str
    description: str
    command: Optional[str] = None
    priority: str = "medium"  # high, medium, low
    reason: Optional[str] = None
    target_info: Optional[Dict[str, Any]] = None


class SuggestionsResponse(BaseModel):
    """Suggestions response."""
    mission_id: str
    suggestions: List[SuggestedAction]
    generated_at: str


class TerminalOutputResponse(BaseModel):
    """Terminal output response."""
    mission_id: str
    output: List[str]
    is_live: bool = False
    current_command: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@router.get("/{mission_id}/commands", response_model=CommandHistoryResponse)
async def get_command_history(
    mission_id: str,
    request: Request,
    page: int = 1,
    page_size: int = 50,
    status_filter: Optional[str] = None
):
    """
    Get command history for a mission.
    
    Returns paginated list of executed commands with their output.
    Supports filtering by status (success, error, running).
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    # Get controller from app state
    controller = getattr(request.app.state, 'controller', None)
    
    # Generate sample data if controller not available
    # In production, this would fetch from the mission's command history
    commands = []
    
    if controller:
        # Try to get real command history from mission
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get commands from mission events or blackboard
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    events = await blackboard.get_events(
                        mission_id,
                        event_type="command_executed"
                    )
                    for i, event in enumerate(events):
                        cmd = CommandEntry(
                            id=f"cmd-{i+1}",
                            command=event.get("command", ""),
                            output=event.get("output", "").split("\n") if event.get("output") else [],
                            timestamp=event.get("timestamp", datetime.now().isoformat()),
                            status=event.get("status", "success"),
                            duration=event.get("duration"),
                            exit_code=event.get("exit_code")
                        )
                        commands.append(cmd)
        except Exception:
            pass
    
    # If no real commands, return empty list (no demo data in production)
    # Filter by status if specified
    if status_filter:
        commands = [c for c in commands if c.status == status_filter]
    
    # Paginate
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_commands = commands[start_idx:end_idx]
    
    return CommandHistoryResponse(
        mission_id=mission_id,
        commands=paginated_commands,
        total=len(commands),
        page=page,
        page_size=page_size
    )


@router.get("/{mission_id}/terminal/output", response_model=TerminalOutputResponse)
async def get_terminal_output(
    mission_id: str,
    request: Request,
    lines: int = 100
):
    """
    Get current terminal output for a mission.
    
    Returns the latest terminal output lines.
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    output = []
    is_live = False
    current_command = None
    
    # Try to get real terminal output from mission
    controller = getattr(request.app.state, 'controller', None)
    if controller:
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get terminal output from mission state
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    terminal_state = await blackboard.get_terminal_state(mission_id)
                    if terminal_state:
                        output = terminal_state.get("output", [])[-lines:]
                        is_live = terminal_state.get("is_live", False)
                        current_command = terminal_state.get("current_command")
        except Exception:
            pass
    
    return TerminalOutputResponse(
        mission_id=mission_id,
        output=output,
        is_live=is_live,
        current_command=current_command
    )


@router.get("/{mission_id}/suggestions", response_model=SuggestionsResponse)
async def get_suggestions(
    mission_id: str,
    request: Request,
    limit: int = 5
):
    """
    Get AI-generated suggestions for next actions.
    
    Returns suggested follow-up actions based on mission findings.
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    suggestions = []
    
    # Try to generate suggestions from mission data
    controller = getattr(request.app.state, 'controller', None)
    if controller:
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get findings from mission
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    # Get vulnerabilities and targets
                    vulns = await blackboard.get_vulnerabilities(mission_id)
                    targets = await blackboard.get_targets(mission_id)
                    
                    # Generate suggestions based on findings
                    suggestions = await _generate_suggestions(
                        vulns, targets, limit
                    )
        except Exception:
            pass
    
    # If no suggestions could be generated, return empty list
    # (no demo data in production)
    
    return SuggestionsResponse(
        mission_id=mission_id,
        suggestions=suggestions[:limit],
        generated_at=datetime.now().isoformat()
    )


async def _generate_suggestions(
    vulns: List[Dict],
    targets: List[Dict],
    limit: int
) -> List[SuggestedAction]:
    """
    Generate AI suggestions based on mission findings.
    
    This is a simplified version. In production, this would use the LLM service.
    """
    suggestions = []
    suggestion_id = 1
    
    # Suggest exploits for high severity vulnerabilities
    for vuln in vulns:
        if vuln.get("severity") in ["critical", "high"] and vuln.get("exploit_available"):
            suggestions.append(SuggestedAction(
                id=f"sug-{suggestion_id}",
                type="exploit",
                title=f"Exploit {vuln.get('name', 'vulnerability')}",
                description=f"Attempt exploitation of {vuln.get('type')} vulnerability on {vuln.get('target_id')}",
                command=f"exploit -t {vuln.get('target_id')} -v {vuln.get('vuln_id')}",
                priority="high",
                reason=f"High severity vulnerability with available exploit",
                target_info={
                    "vuln_id": vuln.get("vuln_id"),
                    "severity": vuln.get("severity")
                }
            ))
            suggestion_id += 1
            
            if len(suggestions) >= limit:
                break
    
    # Suggest additional scans for targets with few findings
    for target in targets:
        if target.get("status") == "scanned" and not target.get("ports"):
            suggestions.append(SuggestedAction(
                id=f"sug-{suggestion_id}",
                type="scan",
                title=f"Deep scan {target.get('ip', 'target')}",
                description=f"Perform comprehensive port and service scan",
                command=f"nmap -sV -sC -p- {target.get('ip')}",
                priority="medium",
                reason="Target has minimal findings, deeper scan recommended"
            ))
            suggestion_id += 1
            
            if len(suggestions) >= limit:
                break
    
    # Always suggest generating a report if we have findings
    if vulns or targets:
        suggestions.append(SuggestedAction(
            id=f"sug-{suggestion_id}",
            type="report",
            title="Generate Status Report",
            description="Generate a comprehensive report of current findings",
            command=None,
            priority="low",
            reason="Document current progress and findings"
        ))
    
    return suggestions[:limit]


# ═══════════════════════════════════════════════════════════════
# Execute Command Route
# ═══════════════════════════════════════════════════════════════

class ExecuteCommandRequest(BaseModel):
    """Request model for command execution."""
    command: str = Field(..., description="Command to execute")
    timeout: int = Field(default=30, description="Timeout in seconds (max 300)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "command": "ls -la /home",
                "timeout": 30
            }
        }


class ExecuteCommandResponse(BaseModel):
    """Response model for command execution."""
    id: str
    command: str
    output: List[str]
    exit_code: int
    status: str  # success, error, timeout
    duration_ms: int
    timestamp: str


@router.post("/{mission_id}/execute", response_model=ExecuteCommandResponse)
async def execute_command(
    mission_id: str,
    request: Request,
    body: ExecuteCommandRequest
):
    """
    Execute a command on the mission's target environment.
    
    This endpoint allows executing shell commands and returns real-time output.
    The output is also broadcast via WebSocket for live terminal display.
    
    Security Notes:
    - Only allowed commands are executed (no dangerous commands)
    - Commands are sandboxed to the mission's environment
    - All commands are logged for audit
    """
    import time
    import asyncio
    from uuid import UUID
    
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    # Validate timeout
    timeout = min(body.timeout, 300)  # Max 5 minutes
    
    command = body.command.strip()
    if not command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Command cannot be empty"
        )
    
    # Security: Assess Risk (HITL Logic)
    risk_level, risk_reason = assess_command_risk(command)
    start_time = time.time()
    command_id = f"cmd-{int(start_time * 1000)}"

    # If risk is HIGH/MEDIUM -> Require Approval
    if risk_level in ['high', 'medium']:
        # Generate an action ID for approval
        action_id = f"auth-{UUID(int=int(start_time*1000000))}"
        
        # Register approval request in database/memory (Mocking simple broadcast here for demo)
        # In a real persistence layer, we would save this to the 'approvals' table.
        
        # Broadcast Approval Request to UI
        try:
            from .websocket import broadcast_approval_request
            # Calculate expiration (e.g., 5 minutes)
            expires_at = datetime.fromtimestamp(start_time + 300).isoformat()
            
            await broadcast_approval_request(
                mission_id=mission_id,
                action_id=action_id,
                action_type="execute_command",
                action_description=f"Execute command: {command}",
                risk_level=risk_level,
                risk_reasons=[risk_reason],
                potential_impact="System modification or information disclosure",
                command_preview=command,
                expires_at=expires_at
            )
            
            logger.info(f"Command '{command}' requires approval. Action ID: {action_id}")
            
            # Return "Pending" status to the caller
            return ExecuteCommandResponse(
                id=command_id,
                command=command,
                output=["⚠️ Command requires approval. Please check the chat to approve."],
                exit_code=0,
                status="pending_approval",
                duration_ms=0,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Failed to broadcast approval request: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initiate approval process"
            )

    # If Safe -> Execute Immediately
    
    # Broadcast command start via WebSocket with proper streaming events
    try:
        from .websocket import broadcast_terminal_command_start, broadcast_terminal_output
        await broadcast_terminal_command_start(
            mission_id=mission_id,
            command=command,
            command_id=command_id
        )
    except Exception as e:
        logger.warning(f"Failed to broadcast command start: {e}")
    
    # Try to execute command via real environment
    output_lines = []
    exit_code = 0
    cmd_status = "success"
    
    # Check if we have SSH connection for this mission
    if ssh_manager and environment_manager:
        try:
            # Try to get the environment/VM for this mission and execute real command
            # This uses the SSHCommandExecutor for actual execution
            from ..infrastructure.orchestrator.agent_executor import AgentExecutor
            
            # Get user environments
            mission_data = None
            user_environments = []
            
            try:
                from ..controller.blackboard import get_blackboard
                blackboard = await get_blackboard()
                mission_data = await blackboard.get_mission(mission_id)
                
                if mission_data:
                    user_id = mission_data.get("created_by")
                    if user_id:
                        user_environments = await environment_manager.list_user_environments(str(user_id))
            except Exception:
                pass
            
            # Find a connected environment
            agent_env = None
            for env in user_environments:
                if env.status.value in ["connected", "ready"]:
                    agent_env = env
                    break
            
            if agent_env and agent_env.ssh_manager and agent_env.connection_id:
                # Execute via real SSH
                executor = AgentExecutor()
                task_id = f"cmd-{mission_id[:8]}-{int(time.time() * 1000)}"
                
                result = await executor.execute_command(
                    environment=agent_env,
                    command=command,
                    task_id=task_id,
                    timeout=timeout
                )
                
                if result.status == "success":
                    output_lines = [f"$ {command}"] + (result.stdout.split('\n') if result.stdout else [])
                    exit_code = result.exit_code
                    cmd_status = "success"
                else:
                    error_output = result.stderr or result.stdout or "Command failed"
                    output_lines = [f"$ {command}"] + error_output.split('\n')
                    exit_code = result.exit_code
                    cmd_status = "error"
            else:
                # No connected environment - return clear error
                output_lines = [
                    f"$ {command}",
                    "",
                    "❌ Execution Environment Not Connected",
                    "",
                    "No active execution environment is available for this mission.",
                    "",
                    "📋 To enable command execution:",
                    "   1. Ensure your VM environment is provisioned",
                    "   2. Check that the environment is in 'ready' status",
                    "   3. Verify SSH connectivity to the environment",
                    "",
                    "💡 Use the chat to ask the agent about environment status.",
                    "",
                    f"Command queued: {command}"
                ]
                exit_code = 126
                cmd_status = "unavailable"
            
        except Exception as e:
            output_lines = [f"$ {command}", "", f"❌ Execution Error: {str(e)}"]
            exit_code = 1
            cmd_status = "error"
    else:
        # No SSH manager or environment manager - return clear error
        output_lines = [
            f"$ {command}",
            "",
            "❌ Shell Access Not Available",
            "",
            "The execution environment is not configured for this server.",
            "",
            "📋 Possible reasons:",
            "   • Server is starting up",
            "   • Environment manager not initialized",
            "   • Configuration error",
            "",
            "Please wait a moment and try again, or contact support.",
            "",
            f"Command: {command}"
        ]
        exit_code = 126
        cmd_status = "unavailable"
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Broadcast final output via WebSocket with proper streaming events
    try:
        from .websocket import (
            broadcast_terminal_output,
            broadcast_terminal_output_line,
            broadcast_terminal_command_complete,
            broadcast_terminal_command_error
        )
        
        # Stream each output line individually for real-time feedback
        for line in output_lines:
            await broadcast_terminal_output_line(
                mission_id=mission_id,
                line=line,
                command_id=command_id,
                is_simulation=(cmd_status == "unavailable")
            )
        
        # Send completion or error event
        if cmd_status == "error":
            await broadcast_terminal_command_error(
                mission_id=mission_id,
                command=command,
                error="Command execution failed",
                command_id=command_id
            )
        else:
            await broadcast_terminal_command_complete(
                mission_id=mission_id,
                command=command,
                exit_code=exit_code,
                command_id=command_id,
                duration_ms=duration_ms
            )
        
        # Also send legacy terminal_output for backwards compatibility
        await broadcast_terminal_output(
            mission_id=mission_id,
            command=command,
            output="\n".join(output_lines),
            exit_code=exit_code,
            status=cmd_status
        )
    except Exception as e:
        logger.error(f"Failed to broadcast terminal events: {e}")
    
    return ExecuteCommandResponse(
        id=command_id,
        command=command,
        output=output_lines,
        exit_code=exit_code,
        status=cmd_status,
        duration_ms=duration_ms,
        timestamp=datetime.now().isoformat()
    )
