# RAGLOX v3.0 - Chat System Implementation Plan
## Enterprise-Grade Solutions for Identified Gaps

**Date:** 2026-01-09  
**Priority:** Critical  
**Est. Completion:** 4 weeks  
**Based on:** COMPREHENSIVE_CHAT_ANALYSIS_AR.md

---

## Executive Summary

This document outlines the implementation plan to address the critical gaps identified in the comprehensive chat system analysis. The plan is divided into 4 sprints focusing on: Critical Fixes, UX Enhancement, Advanced Features, and Polish & Production.

---

## Sprint 1: Critical Foundation (Week 1)

### Day 1-2: Terminal Streaming Implementation

**Objective:** Enable real-time terminal output broadcasting via WebSocket

#### Backend Changes

**File:** `src/controller/mission.py`

```python
# Add streaming support to _execute_shell_command

async def _execute_shell_command(self, mission_id: str, command: str) -> str:
    """Execute command with real-time streaming to browser."""
    
    # Broadcast command start
    await self._broadcast_terminal_event(
        mission_id=mission_id,
        event_type="terminal_command_start",
        data={"command": command}
    )
    
    output_lines = []
    
    try:
        # Check for real execution environment
        env = await self._get_execution_environment(mission_id)
        
        if env and env.status == "connected":
            # Real execution with streaming
            async for line in self._execute_ssh_streaming(env, command):
                output_lines.append(line)
                # Broadcast each line in real-time
                await self._broadcast_terminal_event(
                    mission_id=mission_id,
                    event_type="terminal_output",
                    data={"line": line, "timestamp": datetime.utcnow().isoformat()}
                )
        else:
            # Simulation mode with clear indication
            output_lines = self._simulate_command_output(command)
            for line in output_lines:
                await self._broadcast_terminal_event(
                    mission_id=mission_id,
                    event_type="terminal_output",
                    data={
                        "line": line,
                        "simulation": True,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
        
        # Broadcast completion
        await self._broadcast_terminal_event(
            mission_id=mission_id,
            event_type="terminal_command_complete",
            data={"exit_code": 0, "command": command}
        )
        
        return "\n".join(output_lines)
        
    except Exception as e:
        logger.error(f"Command execution failed: {e}", exc_info=True)
        await self._broadcast_terminal_event(
            mission_id=mission_id,
            event_type="terminal_command_error",
            data={"error": str(e), "command": command}
        )
        raise


async def _broadcast_terminal_event(
    self,
    mission_id: str,
    event_type: str,
    data: Dict[str, Any]
) -> None:
    """Safely broadcast terminal events with fallback."""
    try:
        from ..api.websocket import broadcast_message
        
        await broadcast_message(
            mission_id=mission_id,
            event_type=event_type,
            data=data
        )
    except Exception as e:
        logger.error(f"WebSocket broadcast failed: {e}")
        # Store event in Redis for polling clients
        await self._store_event_for_polling(mission_id, event_type, data)


async def _store_event_for_polling(
    self,
    mission_id: str,
    event_type: str,
    data: Dict[str, Any]
) -> None:
    """Store events in Redis for clients using polling fallback."""
    key = f"mission:{mission_id}:terminal_events"
    event = {
        "type": event_type,
        "data": data,
        "timestamp": datetime.utcnow().isoformat()
    }
    await self.blackboard.redis_client.lpush(key, json.dumps(event))
    await self.blackboard.redis_client.ltrim(key, 0, 99)  # Keep last 100 events
    await self.blackboard.redis_client.expire(key, 3600)  # 1 hour TTL
```

#### Frontend Changes

**File:** `webapp/frontend/client/src/hooks/useWebSocket.ts`

```typescript
// Add terminal event handlers

case "terminal_command_start":
  setTerminalOutput((prev) => [
    ...prev,
    `$ ${(data as { command: string }).command}`
  ]);
  break;

case "terminal_output":
  {
    const { line, simulation } = data as { line: string; simulation?: boolean };
    const prefix = simulation ? "[SIM] " : "";
    setTerminalOutput((prev) => [...prev, `${prefix}${line}`]);
  }
  break;

case "terminal_command_complete":
  {
    const { exit_code } = data as { exit_code: number };
    setTerminalOutput((prev) => [
      ...prev,
      `Command completed with exit code ${exit_code}`
    ]);
  }
  break;

case "terminal_command_error":
  {
    const { error } = data as { error: string };
    setTerminalOutput((prev) => [
      ...prev,
      `Error: ${error}`
    ]);
  }
  break;
```

### Day 3-4: Capability Level UI

**Objective:** Clear visual indicators for execution mode

#### New Component

**File:** `webapp/frontend/client/src/components/manus/CapabilityIndicator.tsx`

```typescript
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, Cloud, Activity, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

export type CapabilityLevel = 0 | 1 | 2 | 3;

export interface VMStatus {
  status: "not_created" | "creating" | "ready" | "error";
  progress?: number;
  message?: string;
}

interface CapabilityIndicatorProps {
  level: CapabilityLevel;
  vmStatus?: VMStatus;
  className?: string;
}

const LEVEL_CONFIG = {
  0: {
    label: "Offline",
    description: "No backend connection",
    icon: Shield,
    color: "text-gray-500"
  },
  1: {
    label: "Connected",
    description: "Backend API connected",
    icon: Cloud,
    color: "text-blue-500"
  },
  2: {
    label: "Simulation",
    description: "Commands run in simulation mode",
    icon: Activity,
    color: "text-yellow-500"
  },
  3: {
    label: "Real Execution",
    description: "Commands execute on live environment",
    icon: Zap,
    color: "text-green-500"
  }
};

export function CapabilityIndicator({
  level,
  vmStatus,
  className
}: CapabilityIndicatorProps) {
  const config = LEVEL_CONFIG[level];
  const Icon = config.icon;

  return (
    <div className={cn("flex items-center gap-3", className)}>
      {/* Level dots */}
      <div className="flex items-center gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={cn(
              "w-2 h-2 rounded-full transition-all",
              i <= level
                ? "bg-current opacity-100"
                : "bg-current opacity-20"
            )}
            style={{ color: config.color.replace("text-", "") }}
          />
        ))}
      </div>

      {/* Level label */}
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className={cn("gap-1.5", config.color)}
          >
            <Icon className="w-3 h-3" />
            <span>Level {level}: {config.label}</span>
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <p>{config.description}</p>
        </TooltipContent>
      </Tooltip>

      {/* VM provisioning progress */}
      {level === 2 && vmStatus?.status === "creating" && (
        <div className="flex items-center gap-2">
          <Progress value={vmStatus.progress || 0} className="w-24" />
          <span className="text-xs text-muted-foreground">
            {vmStatus.progress || 0}%
          </span>
        </div>
      )}
    </div>
  );
}
```

#### Integrate into Operations Page

**File:** `webapp/frontend/client/src/pages/Operations.tsx`

```typescript
// Add state for capability level
const [capabilityLevel, setCapabilityLevel] = useState<CapabilityLevel>(1);
const [vmStatus, setVMStatus] = useState<VMStatus | undefined>();

// Calculate capability level based on mission and VM status
useEffect(() => {
  const calculateLevel = async () => {
    if (!isConnected) {
      setCapabilityLevel(0);
      return;
    }
    
    if (!mission) {
      setCapabilityLevel(1);
      return;
    }
    
    // Check VM status
    try {
      const status = await checkVMStatus(missionId);
      setVMStatus(status);
      
      if (status.status === "ready") {
        setCapabilityLevel(3);
      } else {
        setCapabilityLevel(2);
      }
    } catch (error) {
      setCapabilityLevel(2);
    }
  };
  
  calculateLevel();
}, [isConnected, mission, missionId]);

// Add to header
<header className="...">
  {/* Existing content */}
  
  <CapabilityIndicator
    level={capabilityLevel}
    vmStatus={vmStatus}
  />
</header>
```

### Day 5: Security Fixes

#### Fix 1: Move Token to Authorization Header

**File:** `webapp/frontend/client/src/lib/websocket.ts`

```typescript
export class WebSocketClient {
  connect(): void {
    const token = getAuthToken();
    
    // Use subprotocol for authentication
    const ws = new WebSocket(this.url, ['access_token', token]);
    
    // OR use custom header if server supports it
    // Note: Browser WebSocket API doesn't support custom headers
    // So we need to use query param OR subprotocol OR upgrade to SSE
  }
}
```

**Alternative Solution:** Use Server-Sent Events (SSE) for one-way streaming

**File:** `webapp/frontend/client/src/hooks/useServerSentEvents.ts`

```typescript
export function useServerSentEvents(missionId: string) {
  useEffect(() => {
    const token = getAuthToken();
    
    const eventSource = new EventSource(
      `/api/v1/missions/${missionId}/events`,
      {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      }
    );
    
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      handleEvent(data);
    };
    
    return () => eventSource.close();
  }, [missionId]);
}
```

#### Fix 2: Rate Limiting

**File:** `webapp/src/api/routes.py`

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@router.post("/missions/{mission_id}/chat")
@limiter.limit("20/minute")  # 20 messages per minute
async def send_chat_message(...):
    # Existing implementation
```

#### Fix 3: Command Validation

**File:** `webapp/src/api/terminal_routes.py`

```python
import shlex
from typing import List

ALLOWED_COMMANDS = {
    'nmap', 'ping', 'traceroute', 'dig', 'nslookup',
    'ls', 'cat', 'grep', 'find', 'ps', 'netstat',
    # Add more as needed
}

def validate_command(command: str) -> tuple[bool, str]:
    """Validate command using whitelist approach."""
    try:
        # Parse command safely
        parts = shlex.split(command)
        if not parts:
            return False, "Empty command"
        
        base_command = parts[0].split('/')[-1]  # Handle full paths
        
        # Check if base command is allowed
        if base_command not in ALLOWED_COMMANDS:
            return False, f"Command '{base_command}' is not allowed"
        
        # Check for command chaining
        if any(char in command for char in [';', '&&', '||', '|', '`']):
            return False, "Command chaining is not allowed"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            'rm -rf /',
            '> /dev/',
            'dd if=',
            'mkfs',
            'format'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Invalid command syntax: {str(e)}"
```

---

## Sprint 2: UX Enhancement (Week 2)

### Day 1-3: AI Response Streaming

**Backend:** Implement SSE endpoint for streaming

**File:** `webapp/src/api/routes.py`

```python
from fastapi.responses import StreamingResponse
import asyncio

@router.post("/missions/{mission_id}/chat/stream")
async def stream_chat_response(
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """Stream AI response token by token."""
    
    async def generate():
        try:
            # Send start event
            msg_id = str(uuid.uuid4())
            yield f"data: {json.dumps({'type': 'start', 'id': msg_id})}\n\n"
            
            # Get streaming response from LLM
            async for chunk in controller.get_streaming_response(
                mission_id=mission_id,
                content=request_data.content,
                user_id=user.get("id")
            ):
                # Send token chunk
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
                await asyncio.sleep(0)  # Allow other tasks to run
            
            # Send end event
            yield f"data: {json.dumps({'type': 'end', 'id': msg_id})}\n\n"
            
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )
```

**Frontend:** Use EventSource for streaming

**File:** `webapp/frontend/client/src/hooks/useStreamingChat.ts`

```typescript
export function useStreamingChat(missionId: string) {
  const [streamingMessage, setStreamingMessage] = useState<string>("");
  const [isStreaming, setIsStreaming] = useState(false);
  
  const sendStreamingMessage = useCallback(async (content: string) => {
    setIsStreaming(true);
    setStreamingMessage("");
    
    const response = await fetch(
      `/api/v1/missions/${missionId}/chat/stream`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders()
        },
        body: JSON.stringify({ content })
      }
    );
    
    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    
    while (true) {
      const { done, value } = await reader!.read();
      if (done) break;
      
      const chunk = decoder.decode(value);
      const lines = chunk.split("\n\n");
      
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = JSON.parse(line.slice(6));
          
          if (data.type === "chunk") {
            setStreamingMessage((prev) => prev + data.content);
          } else if (data.type === "end") {
            setIsStreaming(false);
          } else if (data.type === "error") {
            toast.error(data.message);
            setIsStreaming(false);
          }
        }
      }
    }
  }, [missionId]);
  
  return { sendStreamingMessage, streamingMessage, isStreaming };
}
```

### Day 4-5: Enhanced Error Handling

**Create Error Display Component**

**File:** `webapp/frontend/client/src/components/manus/ErrorDisplay.tsx`

```typescript
interface ErrorDisplayProps {
  error: {
    code: string;
    message: string;
    details?: string;
    suggestions?: string[];
  };
  onRetry?: () => void;
  onDismiss?: () => void;
}

export function ErrorDisplay({ error, onRetry, onDismiss }: ErrorDisplayProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="error-card"
    >
      <div className="flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-red-500" />
        <div className="flex-1">
          <h4 className="font-medium text-red-500">{error.message}</h4>
          {error.details && (
            <p className="text-sm text-muted-foreground mt-1">
              {error.details}
            </p>
          )}
          
          {error.suggestions && error.suggestions.length > 0 && (
            <div className="mt-3">
              <p className="text-sm font-medium">Suggestions:</p>
              <ul className="list-disc list-inside text-sm text-muted-foreground">
                {error.suggestions.map((suggestion, i) => (
                  <li key={i}>{suggestion}</li>
                ))}
              </ul>
            </div>
          )}
          
          <div className="flex gap-2 mt-3">
            {onRetry && (
              <Button size="sm" onClick={onRetry}>
                Retry
              </Button>
            )}
            {onDismiss && (
              <Button size="sm" variant="ghost" onClick={onDismiss}>
                Dismiss
              </Button>
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
```

---

## Sprint 3: Advanced Features (Weeks 3-4)

### Command Queue System
### Context-Aware Intelligence
### Proactive Recommendations
### Performance Optimization

---

## Testing Strategy

### Unit Tests
- Terminal streaming functions
- Command validation
- Error handling logic

### Integration Tests
- WebSocket → Frontend flow
- SSE streaming
- Rate limiting

### E2E Tests
- Complete chat flow
- Terminal execution
- Error scenarios

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Terminal streaming working | 0% | 100% |
| Clear capability indicators | 0% | 100% |
| AI response streaming | 0% | 100% |
| Security issues resolved | 60% | 100% |
| User satisfaction (subjective) | 7/10 | 9/10 |

---

**End of Implementation Plan**
