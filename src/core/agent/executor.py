# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Agent Executor
# Handles the execution of agent actions and tool calls
# ═══════════════════════════════════════════════════════════════
"""
Agent Executor Module - Orchestrates tool execution

This module provides the execution layer that:
- Manages SSH connections to target environments
- Executes tool calls from the agent
- Handles streaming of execution results
- Provides retry and error handling
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import uuid4

from .tools import BaseTool, ToolResult, ToolRegistry, get_tool_registry


@dataclass
class SSHConfig:
    """SSH connection configuration"""
    host: str
    port: int = 22
    username: str = "root"
    password: Optional[str] = None
    private_key: Optional[str] = None
    timeout: int = 30


@dataclass
class ExecutionResult:
    """Result from a command execution"""
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 0
    command: str = ""


class SSHCommandExecutor:
    """
    Executes commands via SSH on remote environments.
    
    This is the low-level execution layer that handles:
    - SSH connection management
    - Command execution with timeout
    - Output streaming
    """
    
    def __init__(
        self,
        config: SSHConfig,
        logger: Optional[logging.Logger] = None
    ):
        self.config = config
        self.logger = logger or logging.getLogger("raglox.executor.ssh")
        self._connected = False
        self._client = None
    
    async def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            import asyncssh
            
            # Build connection options
            connect_options = {
                "host": self.config.host,
                "port": self.config.port,
                "username": self.config.username,
                "known_hosts": None,  # Disable host key checking for now
                "connect_timeout": self.config.timeout,
            }
            
            if self.config.password:
                connect_options["password"] = self.config.password
            elif self.config.private_key:
                connect_options["client_keys"] = [self.config.private_key]
            
            self._client = await asyncssh.connect(**connect_options)
            self._connected = True
            self.logger.info(f"SSH connected to {self.config.host}:{self.config.port}")
            return True
            
        except ImportError:
            # asyncssh not installed - try paramiko
            import paramiko
            
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                if self.config.password:
                    self._client.connect(
                        hostname=self.config.host,
                        port=self.config.port,
                        username=self.config.username,
                        password=self.config.password,
                        timeout=self.config.timeout
                    )
                elif self.config.private_key:
                    self._client.connect(
                        hostname=self.config.host,
                        port=self.config.port,
                        username=self.config.username,
                        key_filename=self.config.private_key,
                        timeout=self.config.timeout
                    )
                
                self._connected = True
                self.logger.info(f"SSH connected to {self.config.host}:{self.config.port}")
                return True
            except Exception as e:
                self.logger.error(f"SSH connection failed: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Close SSH connection"""
        if self._client:
            try:
                if hasattr(self._client, 'close'):
                    self._client.close()
                    if hasattr(self._client, 'wait_closed'):
                        await self._client.wait_closed()
            except Exception as e:
                self.logger.warning(f"Error closing SSH: {e}")
            finally:
                self._client = None
                self._connected = False
    
    async def execute(
        self,
        command: str,
        timeout: int = 60
    ) -> ExecutionResult:
        """
        Execute a command on the remote system.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            ExecutionResult with stdout, stderr, and exit code
        """
        if not self._connected or not self._client:
            return ExecutionResult(
                success=False,
                stderr="Not connected",
                exit_code=-1,
                command=command
            )
        
        start_time = datetime.utcnow()
        
        try:
            # Check if using asyncssh or paramiko
            if hasattr(self._client, 'run'):
                # asyncssh
                result = await asyncio.wait_for(
                    self._client.run(command),
                    timeout=timeout
                )
                
                duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                
                return ExecutionResult(
                    success=result.exit_status == 0,
                    stdout=result.stdout or "",
                    stderr=result.stderr or "",
                    exit_code=result.exit_status or 0,
                    duration_ms=duration,
                    command=command
                )
            else:
                # paramiko
                stdin, stdout, stderr = self._client.exec_command(
                    command,
                    timeout=timeout
                )
                
                stdout_text = stdout.read().decode('utf-8', errors='replace')
                stderr_text = stderr.read().decode('utf-8', errors='replace')
                exit_code = stdout.channel.recv_exit_status()
                
                duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                
                return ExecutionResult(
                    success=exit_code == 0,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    exit_code=exit_code,
                    duration_ms=duration,
                    command=command
                )
                
        except asyncio.TimeoutError:
            return ExecutionResult(
                success=False,
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                command=command
            )
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return ExecutionResult(
                success=False,
                stderr=str(e),
                exit_code=-1,
                command=command
            )
    
    async def execute_stream(
        self,
        command: str,
        timeout: int = 60
    ) -> AsyncIterator[str]:
        """
        Execute a command and stream output line by line.
        
        Yields:
            Lines of output as they arrive
        """
        if not self._connected or not self._client:
            yield "Error: Not connected to target"
            return
        
        try:
            if hasattr(self._client, 'create_process'):
                # asyncssh
                async with self._client.create_process(command) as process:
                    async for line in process.stdout:
                        yield line.rstrip('\n')
            else:
                # paramiko - limited streaming support
                stdin, stdout, stderr = self._client.exec_command(
                    command,
                    timeout=timeout
                )
                
                for line in stdout:
                    yield line.rstrip('\n')
                    
        except Exception as e:
            yield f"Error: {e}"
    
    @property
    def is_connected(self) -> bool:
        """Check if connected"""
        return self._connected and self._client is not None


class AgentExecutor:
    """
    High-level executor for agent actions.
    
    Manages:
    - Tool execution
    - SSH connection lifecycle
    - Result formatting for agent consumption
    """
    
    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.tool_registry = tool_registry or get_tool_registry()
        self.logger = logger or logging.getLogger("raglox.executor")
        self._ssh_executor: Optional[SSHCommandExecutor] = None
    
    async def setup_environment(
        self,
        ssh_config: SSHConfig
    ) -> bool:
        """
        Set up execution environment with SSH connection.
        
        Args:
            ssh_config: SSH configuration
            
        Returns:
            True if connection successful
        """
        self._ssh_executor = SSHCommandExecutor(ssh_config, self.logger)
        connected = await self._ssh_executor.connect()
        
        if connected:
            self.logger.info("Execution environment ready")
        else:
            self.logger.error("Failed to set up execution environment")
        
        return connected
    
    async def teardown_environment(self) -> None:
        """Tear down execution environment"""
        if self._ssh_executor:
            await self._ssh_executor.disconnect()
            self._ssh_executor = None
    
    async def execute_tool(
        self,
        tool_name: str,
        **kwargs
    ) -> ToolResult:
        """
        Execute a tool by name.
        
        Args:
            tool_name: Name of the tool to execute
            **kwargs: Tool parameters
            
        Returns:
            ToolResult with execution results
        """
        if not self._ssh_executor or not self._ssh_executor.is_connected:
            return ToolResult(
                success=False,
                error="No execution environment available. Please ensure VM is ready.",
                tool_name=tool_name
            )
        
        return await self.tool_registry.execute(
            tool_name,
            self._ssh_executor,
            **kwargs
        )
    
    async def execute_command(
        self,
        command: str,
        timeout: int = 60
    ) -> ExecutionResult:
        """
        Execute a raw command.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            ExecutionResult
        """
        if not self._ssh_executor or not self._ssh_executor.is_connected:
            return ExecutionResult(
                success=False,
                stderr="No execution environment available",
                exit_code=-1,
                command=command
            )
        
        return await self._ssh_executor.execute(command, timeout)
    
    async def stream_command(
        self,
        command: str,
        timeout: int = 60
    ) -> AsyncIterator[str]:
        """
        Execute a command with streaming output.
        
        Yields:
            Lines of output
        """
        if not self._ssh_executor or not self._ssh_executor.is_connected:
            yield "Error: No execution environment available"
            return
        
        async for line in self._ssh_executor.execute_stream(command, timeout):
            yield line
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools with their schemas"""
        return self.tool_registry.get_schemas()
    
    def get_tools_description(self) -> str:
        """Get formatted description of available tools"""
        return self.tool_registry.get_tool_descriptions()
    
    @property
    def is_ready(self) -> bool:
        """Check if executor is ready for execution"""
        return self._ssh_executor is not None and self._ssh_executor.is_connected


# Global executor instance for the application
_agent_executor: Optional[AgentExecutor] = None


def get_agent_executor() -> AgentExecutor:
    """Get the global agent executor"""
    global _agent_executor
    if _agent_executor is None:
        _agent_executor = AgentExecutor()
    return _agent_executor
