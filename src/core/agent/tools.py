# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Agent Tools Framework
# Tool definitions and registry for agent capabilities
# ═══════════════════════════════════════════════════════════════
"""
Tools Module - Callable tools for the AI Agent

This module defines the tool interface and provides concrete implementations
for penetration testing operations. Tools are the "hands" of the agent -
they perform actual operations on the target environment.

Tool Categories:
    - Shell Tools: Execute commands, manage files
    - Network Tools: Scanning, enumeration, traffic analysis
    - Exploit Tools: Vulnerability exploitation
    - Credential Tools: Password attacks, hash cracking
    - Post-Exploitation: Privilege escalation, persistence
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Callable
import asyncio
import logging
import json


class ToolCategory(Enum):
    """Categories of tools"""
    SHELL = "shell"                 # Shell/terminal operations
    NETWORK = "network"             # Network operations
    RECONNAISSANCE = "recon"        # Information gathering
    VULNERABILITY = "vuln"          # Vulnerability scanning
    EXPLOITATION = "exploit"        # Exploitation
    POST_EXPLOIT = "post_exploit"   # Post-exploitation
    CREDENTIAL = "credential"       # Credential operations
    LATERAL = "lateral"             # Lateral movement
    PERSISTENCE = "persistence"     # Maintaining access
    EXFILTRATION = "exfil"         # Data extraction
    UTILITY = "utility"             # General utilities


@dataclass
class ToolParameter:
    """Definition of a tool parameter"""
    name: str
    description: str
    type: str = "string"           # string, int, bool, array, object
    required: bool = False
    default: Any = None
    enum: Optional[List[str]] = None  # Allowed values


@dataclass
class ToolResult:
    """
    Result from a tool execution.
    
    All tools return this standardized result format.
    """
    success: bool
    output: str = ""
    error: Optional[str] = None
    
    # Structured data from the tool
    data: Dict[str, Any] = field(default_factory=dict)
    
    # Execution details
    tool_name: str = ""
    command: Optional[str] = None     # Command that was executed
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    
    # Findings (for scanning tools)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # For the agent to understand
    summary: str = ""                 # Brief summary for LLM
    next_steps: List[str] = field(default_factory=list)  # Suggested follow-ups
    
    def to_agent_context(self) -> str:
        """Format result for LLM context"""
        lines = [f"Tool: {self.tool_name}"]
        
        if self.command:
            lines.append(f"Command: {self.command}")
        
        if self.success:
            lines.append("Status: SUCCESS")
            if self.output:
                lines.append(f"Output:\n{self.output[:2000]}")  # Truncate long output
            if self.findings:
                lines.append(f"Findings: {len(self.findings)} items")
        else:
            lines.append("Status: FAILED")
            if self.error:
                lines.append(f"Error: {self.error}")
        
        if self.summary:
            lines.append(f"Summary: {self.summary}")
        
        if self.next_steps:
            lines.append("Suggested next steps:")
            for step in self.next_steps[:3]:
                lines.append(f"  - {step}")
        
        return "\n".join(lines)


class BaseTool(ABC):
    """
    Abstract base class for all agent tools.
    
    Tools encapsulate specific operations that the agent can perform.
    Each tool has a clear interface with defined parameters and
    returns standardized results.
    """
    
    # Tool metadata - override in subclasses
    name: str = "base_tool"
    description: str = "Base tool description"
    category: ToolCategory = ToolCategory.UTILITY
    
    # Risk level for HITL decisions
    risk_level: str = "low"  # low, medium, high, critical
    requires_approval: bool = False
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(f"raglox.tool.{self.name}")
        self._execution_count = 0
    
    @abstractmethod
    def get_parameters(self) -> List[ToolParameter]:
        """
        Define the parameters this tool accepts.
        
        Returns:
            List of ToolParameter definitions
        """
        pass
    
    @abstractmethod
    async def execute(
        self,
        ssh_executor: Any,  # SSHCommandExecutor
        **kwargs
    ) -> ToolResult:
        """
        Execute the tool with given parameters.
        
        Args:
            ssh_executor: SSH executor for running commands
            **kwargs: Tool-specific parameters
            
        Returns:
            ToolResult with execution results
        """
        pass
    
    def get_schema(self) -> Dict[str, Any]:
        """
        Get JSON schema for this tool (for LLM function calling).
        
        Returns schema compatible with OpenAI/Anthropic function calling.
        """
        params = self.get_parameters()
        
        properties = {}
        required = []
        
        for param in params:
            prop = {
                "type": param.type,
                "description": param.description
            }
            if param.enum:
                prop["enum"] = param.enum
            if param.default is not None:
                prop["default"] = param.default
            
            properties[param.name] = prop
            
            if param.required:
                required.append(param.name)
        
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }
    
    def validate_params(self, **kwargs) -> Optional[str]:
        """
        Validate parameters before execution.
        
        Returns:
            Error message if validation fails, None if valid
        """
        params = {p.name: p for p in self.get_parameters()}
        
        # Check required params
        for name, param in params.items():
            if param.required and name not in kwargs:
                return f"Missing required parameter: {name}"
            
            if name in kwargs and param.enum:
                if kwargs[name] not in param.enum:
                    return f"Invalid value for {name}. Must be one of: {param.enum}"
        
        return None
    
    def __repr__(self) -> str:
        return f"<Tool {self.name} category={self.category.value}>"


# ═══════════════════════════════════════════════════════════════
# Concrete Tool Implementations
# ═══════════════════════════════════════════════════════════════

class ShellCommandTool(BaseTool):
    """Execute arbitrary shell commands"""
    
    name = "shell_command"
    description = "Execute a shell command on the target environment. Use for any Linux command execution."
    category = ToolCategory.SHELL
    risk_level = "medium"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="command",
                description="The shell command to execute",
                type="string",
                required=True
            ),
            ToolParameter(
                name="timeout",
                description="Timeout in seconds (default: 60)",
                type="integer",
                required=False,
                default=60
            ),
            ToolParameter(
                name="working_dir",
                description="Working directory for the command",
                type="string",
                required=False,
                default="/tmp"
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        command = kwargs.get("command")
        timeout = kwargs.get("timeout", 60)
        working_dir = kwargs.get("working_dir", "/tmp")
        
        if not command:
            return ToolResult(
                success=False,
                error="No command provided",
                tool_name=self.name
            )
        
        start_time = datetime.utcnow()
        
        try:
            # Prepend cd to working directory
            full_command = f"cd {working_dir} && {command}"
            
            result = await ssh_executor.execute(full_command, timeout=timeout)
            
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            return ToolResult(
                success=result.exit_code == 0,
                output=result.stdout or "",
                error=result.stderr if result.exit_code != 0 else None,
                tool_name=self.name,
                command=command,
                exit_code=result.exit_code,
                duration_ms=duration,
                summary=f"Command executed with exit code {result.exit_code}",
                next_steps=self._suggest_next_steps(command, result)
            )
        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                error=f"Command timed out after {timeout}s",
                tool_name=self.name,
                command=command
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=self.name,
                command=command
            )
    
    def _suggest_next_steps(self, command: str, result: Any) -> List[str]:
        """Suggest next steps based on command and result"""
        suggestions = []
        cmd_lower = command.lower()
        
        if "nmap" in cmd_lower:
            suggestions.append("Analyze discovered services for vulnerabilities")
            suggestions.append("Run service-specific enumeration scripts")
        elif "ls" in cmd_lower or "find" in cmd_lower:
            suggestions.append("Examine interesting files found")
            suggestions.append("Check file permissions")
        elif "whoami" in cmd_lower or "id" in cmd_lower:
            suggestions.append("Check for privilege escalation paths")
            suggestions.append("List sudo permissions")
        
        return suggestions


class NmapScanTool(BaseTool):
    """Network scanning with nmap"""
    
    name = "nmap_scan"
    description = "Perform network scanning using nmap. Discovers hosts, ports, and services."
    category = ToolCategory.NETWORK
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="target",
                description="Target IP, hostname, or CIDR range",
                type="string",
                required=True
            ),
            ToolParameter(
                name="scan_type",
                description="Type of scan to perform",
                type="string",
                required=False,
                default="service",
                enum=["quick", "service", "full", "udp", "stealth"]
            ),
            ToolParameter(
                name="ports",
                description="Ports to scan (e.g., '1-1000', '22,80,443', 'all')",
                type="string",
                required=False,
                default="1-1000"
            ),
            ToolParameter(
                name="scripts",
                description="NSE scripts to run (comma-separated)",
                type="string",
                required=False
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        target = kwargs.get("target")
        scan_type = kwargs.get("scan_type", "service")
        ports = kwargs.get("ports", "1-1000")
        scripts = kwargs.get("scripts")
        
        if not target:
            return ToolResult(
                success=False,
                error="No target specified",
                tool_name=self.name
            )
        
        # Build nmap command based on scan type
        scan_flags = {
            "quick": "-T4 -F",
            "service": "-sV -sC",
            "full": "-sV -sC -A",
            "udp": "-sU --top-ports 100",
            "stealth": "-sS -T2"
        }
        
        flags = scan_flags.get(scan_type, "-sV -sC")
        
        # Build command
        cmd_parts = ["nmap", flags]
        
        if ports != "all":
            cmd_parts.extend(["-p", ports])
        else:
            cmd_parts.append("-p-")
        
        if scripts:
            cmd_parts.extend(["--script", scripts])
        
        cmd_parts.extend(["-oN", "/tmp/nmap_scan.txt", target])
        
        command = " ".join(cmd_parts)
        
        # Use shell command tool for execution
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command, timeout=300)
        
        # Parse nmap output for findings
        findings = self._parse_nmap_output(result.output)
        
        result.tool_name = self.name
        result.findings = findings
        result.summary = f"Scanned {target}, found {len(findings)} open ports/services"
        result.next_steps = [
            "Enumerate discovered services for vulnerabilities",
            "Check for default credentials on services",
            "Run service-specific exploits"
        ]
        
        return result
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output to extract findings"""
        findings = []
        
        if not output:
            return findings
        
        # Simple parsing - look for open ports
        for line in output.split('\n'):
            line = line.strip()
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    state = parts[1] if len(parts) > 1 else "unknown"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    
                    if state == "open":
                        findings.append({
                            "port": port_proto,
                            "state": state,
                            "service": service,
                            "version": version
                        })
        
        return findings


class FileReadTool(BaseTool):
    """Read file contents"""
    
    name = "read_file"
    description = "Read the contents of a file on the target system."
    category = ToolCategory.SHELL
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="path",
                description="Path to the file to read",
                type="string",
                required=True
            ),
            ToolParameter(
                name="lines",
                description="Number of lines to read (0 for all)",
                type="integer",
                required=False,
                default=100
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        path = kwargs.get("path")
        lines = kwargs.get("lines", 100)
        
        if not path:
            return ToolResult(
                success=False,
                error="No file path specified",
                tool_name=self.name
            )
        
        if lines > 0:
            command = f"head -n {lines} '{path}'"
        else:
            command = f"cat '{path}'"
        
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command)
        
        result.tool_name = self.name
        result.summary = f"Read {path}"
        
        return result


class FindFilesTool(BaseTool):
    """Search for files"""
    
    name = "find_files"
    description = "Search for files matching criteria on the target system."
    category = ToolCategory.SHELL
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="path",
                description="Starting path for search",
                type="string",
                required=False,
                default="/"
            ),
            ToolParameter(
                name="name",
                description="File name pattern (supports wildcards)",
                type="string",
                required=False
            ),
            ToolParameter(
                name="type",
                description="Type: f=file, d=directory",
                type="string",
                required=False,
                enum=["f", "d"]
            ),
            ToolParameter(
                name="perm",
                description="Permission to search for (e.g., -4000 for SUID)",
                type="string",
                required=False
            ),
            ToolParameter(
                name="max_depth",
                description="Maximum directory depth",
                type="integer",
                required=False,
                default=5
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        path = kwargs.get("path", "/")
        name = kwargs.get("name")
        file_type = kwargs.get("type")
        perm = kwargs.get("perm")
        max_depth = kwargs.get("max_depth", 5)
        
        cmd_parts = ["find", path, "-maxdepth", str(max_depth)]
        
        if file_type:
            cmd_parts.extend(["-type", file_type])
        if name:
            cmd_parts.extend(["-name", f"'{name}'"])
        if perm:
            cmd_parts.extend(["-perm", perm])
        
        cmd_parts.append("2>/dev/null | head -50")  # Suppress errors, limit results
        
        command = " ".join(cmd_parts)
        
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command)
        
        result.tool_name = self.name
        
        # Parse findings
        if result.success and result.output:
            files = [f.strip() for f in result.output.split('\n') if f.strip()]
            result.findings = [{"path": f} for f in files]
            result.summary = f"Found {len(files)} files matching criteria"
        
        return result


class ProcessListTool(BaseTool):
    """List running processes"""
    
    name = "list_processes"
    description = "List running processes on the target system."
    category = ToolCategory.RECONNAISSANCE
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="filter",
                description="Filter processes by name",
                type="string",
                required=False
            ),
            ToolParameter(
                name="user",
                description="Filter by user",
                type="string",
                required=False
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        filter_name = kwargs.get("filter")
        user = kwargs.get("user")
        
        command = "ps aux"
        
        if filter_name:
            command += f" | grep -i '{filter_name}'"
        if user:
            command += f" | grep '^{user}'"
        
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command)
        
        result.tool_name = self.name
        result.summary = "Listed running processes"
        
        return result


class NetworkInfoTool(BaseTool):
    """Get network information"""
    
    name = "network_info"
    description = "Get network configuration and connection information."
    category = ToolCategory.RECONNAISSANCE
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="info_type",
                description="Type of network info to get",
                type="string",
                required=False,
                default="all",
                enum=["all", "interfaces", "routes", "connections", "dns"]
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        info_type = kwargs.get("info_type", "all")
        
        commands = {
            "interfaces": "ip addr || ifconfig",
            "routes": "ip route || route -n",
            "connections": "netstat -tuln || ss -tuln",
            "dns": "cat /etc/resolv.conf"
        }
        
        if info_type == "all":
            command = " && echo '---' && ".join(commands.values())
        else:
            command = commands.get(info_type, commands["interfaces"])
        
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command)
        
        result.tool_name = self.name
        result.summary = f"Retrieved {info_type} network information"
        
        return result


class SystemInfoTool(BaseTool):
    """Get system information"""
    
    name = "system_info"
    description = "Get comprehensive system information about the target."
    category = ToolCategory.RECONNAISSANCE
    risk_level = "low"
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="detailed",
                description="Get detailed information",
                type="boolean",
                required=False,
                default=True
            )
        ]
    
    async def execute(self, ssh_executor: Any, **kwargs) -> ToolResult:
        detailed = kwargs.get("detailed", True)
        
        basic_cmds = [
            "uname -a",
            "hostname",
            "whoami",
            "id"
        ]
        
        detailed_cmds = [
            "cat /etc/os-release 2>/dev/null || cat /etc/issue",
            "df -h",
            "free -m",
            "cat /etc/passwd | head -20",
            "cat /etc/shadow 2>/dev/null | head -5 || echo 'No shadow access'"
        ]
        
        cmds = basic_cmds + (detailed_cmds if detailed else [])
        command = " && echo '---' && ".join(cmds)
        
        shell_tool = ShellCommandTool(self.logger)
        result = await shell_tool.execute(ssh_executor, command=command)
        
        result.tool_name = self.name
        result.summary = "Collected system information"
        result.next_steps = [
            "Check for kernel exploits based on version",
            "Look for privilege escalation vectors",
            "Enumerate installed software"
        ]
        
        return result


# ═══════════════════════════════════════════════════════════════
# RAGLOX Intelligence Tools - RX Modules & Nuclei
# ═══════════════════════════════════════════════════════════════

class RXModuleExecuteTool(BaseTool):
    """
    Execute an RX Module (Atomic Red Team technique)
    
    RX Modules are pre-built attack techniques from Atomic Red Team.
    Use this tool to execute specific MITRE ATT&CK techniques with
    precise commands and proper prerequisites.
    
    Example usage:
    ```
    rx_execute(
        module_id="rx-t1003_001-010",
        target="10.0.0.5",
        variables={"output_file": "/tmp/lsass.dmp"}
    )
    ```
    """
    
    name = "rx_execute"
    description = (
        "Execute an RX Module (Atomic Red Team technique). "
        "RX modules provide tested commands for specific ATT&CK techniques. "
        "Use this for precise exploitation with known attack patterns."
    )
    category = ToolCategory.EXPLOITATION
    risk_level = "high"
    requires_approval = True
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="module_id",
                description=(
                    "RX Module ID (e.g., 'rx-t1003_001-010'). "
                    "Get this from tactical intelligence or knowledge base."
                ),
                type="string",
                required=True
            ),
            ToolParameter(
                name="target",
                description="Target IP address or hostname",
                type="string",
                required=False
            ),
            ToolParameter(
                name="variables",
                description=(
                    "Variables to substitute in the command "
                    "(e.g., {'output_file': '/tmp/output.txt'})"
                ),
                type="object",
                required=False,
                default={}
            ),
            ToolParameter(
                name="check_prerequisites",
                description="Check prerequisites before execution",
                type="boolean",
                required=False,
                default=True
            )
        ]
    
    async def execute(
        self,
        ssh_executor: Any,
        module_id: str,
        target: Optional[str] = None,
        variables: Optional[Dict[str, str]] = None,
        check_prerequisites: bool = True,
        **kwargs
    ) -> ToolResult:
        """Execute RX Module"""
        start_time = datetime.utcnow()
        variables = variables or {}
        
        try:
            # Get knowledge base
            from ...knowledge import get_embedded_knowledge
            knowledge = get_embedded_knowledge()
            
            if not knowledge or not knowledge.is_loaded:
                return ToolResult(
                    success=False,
                    error="Knowledge base not available",
                    tool_name=self.name,
                    summary="Failed: Knowledge base not loaded"
                )
            
            # Get module
            module = knowledge.get_module(module_id)
            if not module:
                return ToolResult(
                    success=False,
                    error=f"RX Module {module_id} not found in knowledge base",
                    tool_name=self.name,
                    summary=f"Failed: Unknown module {module_id}"
                )
            
            # Extract module info
            technique_id = module.get('technique_id', 'unknown')
            technique_name = module.get('technique_name', 'Unknown')
            execution = module.get('execution', {})
            command_template = execution.get('command', '')
            platforms = execution.get('platforms', [])
            elevation_required = execution.get('elevation_required', False)
            prerequisites = module.get('prerequisites', [])
            
            self.logger.info(
                f"Executing RX Module {module_id}: {technique_name} ({technique_id})"
            )
            
            # Platform check
            if platforms and not any(p.lower() in ['linux', 'unix'] for p in platforms):
                return ToolResult(
                    success=False,
                    error=f"Module requires platform: {', '.join(platforms)}. Current: Linux",
                    tool_name=self.name,
                    summary=f"Failed: Platform mismatch"
                )
            
            # Prerequisites check
            if check_prerequisites and prerequisites:
                prereq_results = []
                for prereq in prerequisites:
                    check_cmd = prereq.get('check_command', '')
                    if check_cmd:
                        check_result = await ssh_executor.execute_command(check_cmd)
                        prereq_results.append({
                            'description': prereq.get('description', ''),
                            'check': check_cmd,
                            'passed': check_result.exit_code == 0,
                            'output': check_result.stdout[:200]
                        })
                
                failed_prereqs = [p for p in prereq_results if not p['passed']]
                if failed_prereqs:
                    return ToolResult(
                        success=False,
                        error=f"Prerequisites not met: {len(failed_prereqs)} checks failed",
                        tool_name=self.name,
                        data={'prerequisite_checks': prereq_results},
                        summary=(
                            f"Failed: {len(failed_prereqs)} prerequisite(s) not met. "
                            "Install required tools first."
                        )
                    )
            
            # Build command with variable substitution
            command = command_template
            
            # Substitute module variables
            module_vars = module.get('variables', [])
            for var_def in module_vars:
                var_name = var_def.get('name', '')
                if var_name in variables:
                    # User provided value
                    value = variables[var_name]
                else:
                    # Use default
                    value = var_def.get('default_value', '')
                
                # Replace ${var_name} and $var_name patterns
                command = command.replace(f"${{{var_name}}}", str(value))
                command = command.replace(f"${var_name}", str(value))
            
            # Replace target placeholder
            if target:
                command = command.replace("${target}", target)
                command = command.replace("$target", target)
            
            # Execute command
            self.logger.info(f"Executing command: {command}")
            
            result = await ssh_executor.execute_command(
                command,
                timeout=60  # 60 second timeout
            )
            
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            success = result.exit_code == 0
            
            return ToolResult(
                success=success,
                output=result.stdout,
                error=result.stderr if not success else None,
                tool_name=self.name,
                command=command,
                exit_code=result.exit_code,
                duration_ms=duration_ms,
                data={
                    'module_id': module_id,
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'platform': platforms,
                    'elevation_required': elevation_required
                },
                summary=(
                    f"✅ Executed {technique_name} ({technique_id})" if success
                    else f"❌ Failed to execute {technique_name} ({technique_id})"
                ),
                next_steps=[
                    "Analyze output for successful execution",
                    "Check if objectives were achieved",
                    "Execute cleanup command if needed"
                ] if success else [
                    "Review error message",
                    "Check prerequisites",
                    "Try alternative module or technique"
                ]
            )
            
        except Exception as e:
            self.logger.error(f"RX Module execution failed: {e}", exc_info=True)
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=self.name,
                summary=f"Failed: {str(e)}"
            )


class NucleiScanTool(BaseTool):
    """
    Run Nuclei vulnerability scan with specific templates
    
    Nuclei is a fast vulnerability scanner based on templates.
    Use this tool to scan targets for known CVEs, misconfigurations,
    and security issues.
    
    Example usage:
    ```
    nuclei_scan(
        target="http://10.0.0.5",
        templates=["CVE-2021-41773", "CVE-2021-42013"],
        severity="critical,high"
    )
    ```
    """
    
    name = "nuclei_scan"
    description = (
        "Run Nuclei vulnerability scan. "
        "Use specific template IDs for targeted scanning of known CVEs. "
        "Faster and more precise than full vulnerability scans."
    )
    category = ToolCategory.VULNERABILITY
    risk_level = "low"
    requires_approval = False
    
    def get_parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="target",
                description="Target URL or IP (e.g., 'http://10.0.0.5' or '10.0.0.5')",
                type="string",
                required=True
            ),
            ToolParameter(
                name="templates",
                description=(
                    "List of Nuclei template IDs to use "
                    "(e.g., ['CVE-2021-41773', 'CVE-2021-42013']). "
                    "Get these from tactical intelligence."
                ),
                type="array",
                required=False,
                default=[]
            ),
            ToolParameter(
                name="severity",
                description=(
                    "Minimum severity to scan for: "
                    "'critical', 'high', 'medium', 'low', 'info'"
                ),
                type="string",
                required=False,
                enum=["critical", "high", "medium", "low", "info"],
                default="high"
            ),
            ToolParameter(
                name="tags",
                description=(
                    "Template tags to include (e.g., ['cve', 'apache', 'rce'])"
                ),
                type="array",
                required=False,
                default=[]
            ),
            ToolParameter(
                name="timeout",
                description="Scan timeout in seconds",
                type="integer",
                required=False,
                default=60
            )
        ]
    
    async def execute(
        self,
        ssh_executor: Any,
        target: str,
        templates: Optional[List[str]] = None,
        severity: str = "high",
        tags: Optional[List[str]] = None,
        timeout: int = 60,
        **kwargs
    ) -> ToolResult:
        """Execute Nuclei scan"""
        start_time = datetime.utcnow()
        templates = templates or []
        tags = tags or []
        
        try:
            # Build nuclei command
            cmd_parts = ["nuclei", "-u", target, "-json"]
            
            # Add templates
            if templates:
                # Get template files from knowledge base
                from ...knowledge import get_embedded_knowledge
                knowledge = get_embedded_knowledge()
                
                if knowledge and knowledge.is_loaded:
                    template_paths = []
                    for template_id in templates:
                        template = knowledge.get_nuclei_template(template_id)
                        if template:
                            file_path = template.get('file_path', '')
                            if file_path:
                                template_paths.append(file_path)
                    
                    if template_paths:
                        cmd_parts.extend(["-t", ",".join(template_paths)])
                    else:
                        # Fallback: use template IDs directly
                        cmd_parts.extend(["-t", ",".join(templates)])
                else:
                    # Knowledge base not available, use template IDs
                    cmd_parts.extend(["-t", ",".join(templates)])
            
            # Add severity filter
            if severity:
                cmd_parts.extend(["-s", severity])
            
            # Add tags
            if tags:
                for tag in tags:
                    cmd_parts.extend(["-tags", tag])
            
            # Construct command
            command = " ".join(cmd_parts)
            
            self.logger.info(f"Running Nuclei scan: {command}")
            
            # Execute scan
            result = await ssh_executor.execute_command(
                command,
                timeout=timeout
            )
            
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            # Parse JSON output
            findings = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append({
                                'template_id': finding.get('template-id', 'unknown'),
                                'name': finding.get('info', {}).get('name', 'Unknown'),
                                'severity': finding.get('info', {}).get('severity', 'unknown'),
                                'matched_at': finding.get('matched-at', target),
                                'description': finding.get('info', {}).get('description', ''),
                                'cve_id': finding.get('info', {}).get('classification', {}).get('cve-id', []),
                                'cvss_score': finding.get('info', {}).get('classification', {}).get('cvss-score', 0)
                            })
                        except json.JSONDecodeError:
                            pass
            
            success = result.exit_code == 0 or len(findings) > 0
            
            # Build summary
            if findings:
                severity_counts = {}
                for f in findings:
                    sev = f['severity']
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                summary_parts = [f"Found {len(findings)} vulnerability/ies:"]
                for sev, count in sorted(severity_counts.items()):
                    summary_parts.append(f"  {sev.upper()}: {count}")
                summary = "\n".join(summary_parts)
            else:
                summary = "No vulnerabilities found"
            
            return ToolResult(
                success=success,
                output=result.stdout[:2000],  # Truncate long output
                error=result.stderr if not success and not findings else None,
                tool_name=self.name,
                command=command,
                exit_code=result.exit_code,
                duration_ms=duration_ms,
                findings=findings,
                data={
                    'target': target,
                    'templates_used': templates,
                    'severity_filter': severity,
                    'total_findings': len(findings)
                },
                summary=summary,
                next_steps=[
                    "Review findings for exploitable vulnerabilities",
                    "Cross-reference CVEs with RX modules",
                    "Plan exploitation strategy"
                ] if findings else [
                    "Try different templates or tags",
                    "Lower severity filter",
                    "Check if target is accessible"
                ]
            )
            
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}", exc_info=True)
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=self.name,
                summary=f"Failed: {str(e)}"
            )


# ═══════════════════════════════════════════════════════════════
# Tool Registry
# ═══════════════════════════════════════════════════════════════

class ToolRegistry:
    """
    Registry of available tools for agents.
    
    Provides tool lookup, schema generation for LLM function calling,
    and tool execution.
    """
    
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self.logger = logging.getLogger("raglox.tool_registry")
        
        # Register default tools
        self._register_default_tools()
    
    def _register_default_tools(self) -> None:
        """Register the default set of tools"""
        default_tools = [
            ShellCommandTool(),
            NmapScanTool(),
            FileReadTool(),
            FindFilesTool(),
            ProcessListTool(),
            NetworkInfoTool(),
            SystemInfoTool(),
            # RAGLOX Intelligence Tools
            RXModuleExecuteTool(),
            NucleiScanTool(),
        ]
        
        for tool in default_tools:
            self.register(tool)
    
    def register(self, tool: BaseTool) -> None:
        """Register a tool"""
        self._tools[tool.name] = tool
        self.logger.debug(f"Registered tool: {tool.name}")
    
    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name"""
        return self._tools.get(name)
    
    def list_tools(self, category: Optional[ToolCategory] = None) -> List[BaseTool]:
        """List tools, optionally filtered by category"""
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools
    
    def get_schemas(self) -> List[Dict[str, Any]]:
        """Get all tool schemas for LLM function calling"""
        return [tool.get_schema() for tool in self._tools.values()]
    
    def get_tool_descriptions(self) -> str:
        """Get formatted tool descriptions for LLM context"""
        lines = ["Available tools:"]
        
        for tool in self._tools.values():
            params = tool.get_parameters()
            param_str = ", ".join(
                f"{p.name}{'*' if p.required else ''}" for p in params
            )
            lines.append(f"\n{tool.name}({param_str})")
            lines.append(f"  {tool.description}")
            lines.append(f"  Risk: {tool.risk_level}, Category: {tool.category.value}")
        
        return "\n".join(lines)
    
    async def execute(
        self,
        tool_name: str,
        ssh_executor: Any,
        **kwargs
    ) -> ToolResult:
        """Execute a tool by name"""
        tool = self.get(tool_name)
        
        if not tool:
            return ToolResult(
                success=False,
                error=f"Unknown tool: {tool_name}",
                tool_name=tool_name
            )
        
        # Validate parameters
        error = tool.validate_params(**kwargs)
        if error:
            return ToolResult(
                success=False,
                error=error,
                tool_name=tool_name
            )
        
        # Execute
        try:
            return await tool.execute(ssh_executor, **kwargs)
        except Exception as e:
            self.logger.error(f"Tool {tool_name} execution failed: {e}")
            return ToolResult(
                success=False,
                error=str(e),
                tool_name=tool_name
            )


# Global registry instance
_tool_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry"""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry
