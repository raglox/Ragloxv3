# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - WebSocket Handler
# Real-time updates for mission events
# Secure token transmission via subprotocol (GAP-002 fix)
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import logging
from typing import Any, Dict, List, Set, Optional, Tuple
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status
from starlette.websockets import WebSocketState


logger = logging.getLogger("raglox.websocket")


websocket_router = APIRouter()


class ConnectionManager:
    """
    WebSocket connection manager.
    
    Manages active WebSocket connections and broadcasts events.
    """
    
    def __init__(self):
        # Map: mission_id -> set of websockets
        self._active_connections: Dict[str, Set[WebSocket]] = {}
        # All global connections
        self._global_connections: Set[WebSocket] = set()
    
    async def connect(
        self,
        websocket: WebSocket,
        mission_id: str = None,
        already_accepted: bool = False
    ) -> None:
        """Add a WebSocket connection to the manager.
        
        Args:
            websocket: The WebSocket connection
            mission_id: Optional mission ID to scope the connection
            already_accepted: If True, don't call accept() (already done)
        """
        if not already_accepted:
            await websocket.accept()
        
        if mission_id:
            if mission_id not in self._active_connections:
                self._active_connections[mission_id] = set()
            self._active_connections[mission_id].add(websocket)
        else:
            self._global_connections.add(websocket)
    
    def disconnect(
        self,
        websocket: WebSocket,
        mission_id: str = None
    ) -> None:
        """Remove a WebSocket connection."""
        if mission_id and mission_id in self._active_connections:
            self._active_connections[mission_id].discard(websocket)
            if not self._active_connections[mission_id]:
                del self._active_connections[mission_id]
        else:
            self._global_connections.discard(websocket)
    
    async def broadcast_to_mission(
        self,
        mission_id: str,
        message: Dict[str, Any]
    ) -> None:
        """Broadcast a message to all connections for a mission."""
        if mission_id not in self._active_connections:
            return
        
        disconnected = set()
        
        for websocket in self._active_connections[mission_id]:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected
        for ws in disconnected:
            self._active_connections[mission_id].discard(ws)
    
    async def broadcast_global(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all global connections."""
        disconnected = set()
        
        for websocket in self._global_connections:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected
        for ws in disconnected:
            self._global_connections.discard(ws)
    
    def get_connection_count(self, mission_id: str = None) -> int:
        """Get the number of active connections."""
        if mission_id:
            return len(self._active_connections.get(mission_id, set()))
        return len(self._global_connections)


# Global manager instance
manager = ConnectionManager()


# ═══════════════════════════════════════════════════════════════
# WebSocket Authentication (GAP-002: Token via Subprotocol)
# ═══════════════════════════════════════════════════════════════

async def verify_websocket_token(websocket: WebSocket) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Verify WebSocket authentication token.
    
    Token transmission methods (in priority order):
    1. Subprotocol: 'access_token.{JWT}' (RECOMMENDED - secure)
    2. Query string: '?token={JWT}' (DEPRECATED - for backward compatibility)
    
    Returns:
        Tuple of (is_valid, user_dict, selected_subprotocol)
    """
    from .auth_routes import decode_token, get_token_store
    
    token: Optional[str] = None
    selected_subprotocol: Optional[str] = None
    
    # Method 1: Check subprotocols for token (SECURE)
    # Client sends: new WebSocket(url, ['access_token.{JWT}'])
    subprotocols = websocket.scope.get("subprotocols", [])
    for protocol in subprotocols:
        if protocol.startswith("access_token."):
            token = protocol.replace("access_token.", "", 1)
            selected_subprotocol = protocol
            logger.debug("Token received via subprotocol (secure)")
            break
    
    # Method 2: Fallback to query string (DEPRECATED)
    # For backward compatibility during migration
    if not token:
        query_params = dict(websocket.query_params)
        if "token" in query_params:
            token = query_params["token"]
            logger.warning("Token received via query string (deprecated - please migrate to subprotocol)")
    
    # No token found - allow anonymous connection for public endpoints
    if not token:
        logger.debug("No token provided - anonymous WebSocket connection")
        return True, None, None
    
    # Validate token
    try:
        # Decode JWT
        payload = decode_token(token, raise_on_error=False)
        if not payload:
            logger.warning("Invalid or expired WebSocket token")
            return False, None, selected_subprotocol
        
        # Validate token in Redis store (check if revoked)
        token_store = get_token_store()
        if token_store:
            stored_user_id = await token_store.validate_token(token)
            if not stored_user_id:
                logger.warning("WebSocket token has been revoked")
                return False, None, selected_subprotocol
        
        # Build user dict
        user = {
            "id": payload.get("sub"),
            "organization_id": payload.get("org"),
            "token_exp": payload.get("exp"),
        }
        
        logger.info(f"WebSocket authenticated for user {user['id']}")
        return True, user, selected_subprotocol
        
    except Exception as e:
        logger.error(f"WebSocket token verification failed: {e}")
        return False, None, selected_subprotocol


async def accept_websocket_with_auth(
    websocket: WebSocket,
    require_auth: bool = False
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Accept WebSocket connection with optional authentication.
    
    Per RFC 6455, we MUST accept the WebSocket connection first (with the
    requested subprotocol) before we can send any messages or close codes.
    Otherwise, browsers won't receive the Sec-WebSocket-Protocol header.
    
    Args:
        websocket: The WebSocket connection
        require_auth: If True, reject unauthenticated connections
        
    Returns:
        Tuple of (success, user_dict)
    """
    # Log incoming subprotocols for debugging
    client_subprotocols = websocket.scope.get("subprotocols", [])
    logger.info(f"WebSocket connection attempt - client subprotocols: {len(client_subprotocols)} protocols")
    
    is_valid, user, selected_subprotocol = await verify_websocket_token(websocket)
    
    logger.info(f"Token verification result: is_valid={is_valid}, user_exists={user is not None}, subprotocol_selected={selected_subprotocol is not None}")
    
    # ALWAYS accept first with the selected subprotocol (if any)
    # This ensures the Sec-WebSocket-Protocol header is sent to the client
    try:
        if selected_subprotocol:
            logger.info(f"Accepting WebSocket with subprotocol: {selected_subprotocol[:50]}...")
            await websocket.accept(subprotocol=selected_subprotocol)
        else:
            logger.debug("Accepting WebSocket without subprotocol")
            await websocket.accept()
    except Exception as e:
        logger.error(f"Failed to accept WebSocket: {e}")
        return False, None
    
    # Now check authentication after accepting
    if not is_valid:
        # Send error message before closing
        logger.warning("WebSocket auth failed - sending error and closing with 4001")
        try:
            await websocket.send_json({
                "type": "error",
                "code": 4001,
                "message": "Authentication failed: Invalid or expired token",
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception:
            pass
        await websocket.close(code=4001, reason="Authentication failed")
        return False, None
    
    if require_auth and not user:
        # Send error message before closing
        logger.warning("WebSocket auth required but no user - sending error and closing with 4003")
        try:
            await websocket.send_json({
                "type": "error",
                "code": 4003,
                "message": "Authentication required: Please provide a valid token",
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception:
            pass
        await websocket.close(code=4003, reason="Authentication required")
        return False, None
    
    logger.info("WebSocket accepted and authenticated successfully")
    return True, user


@websocket_router.websocket("/ws")
async def global_websocket(websocket: WebSocket):
    """
    Global WebSocket endpoint for all events.
    
    Receives all mission events.
    
    Authentication:
    - Optional for global endpoint
    - Token via subprotocol: new WebSocket(url, ['access_token.{JWT}'])
    """
    # Authenticate (optional for global endpoint)
    success, user = await accept_websocket_with_auth(websocket, require_auth=False)
    if not success:
        return
    
    # Connection already accepted by accept_websocket_with_auth
    await manager.connect(websocket, already_accepted=True)
    
    try:
        # Send welcome message with auth status
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to RAGLOX v3.0",
            "authenticated": user is not None,
            "user_id": user["id"] if user else None,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        while True:
            # Keep connection alive, wait for client messages
            data = await websocket.receive_text()
            
            # Echo back or handle commands
            try:
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@websocket_router.websocket("/ws/missions/{mission_id}")
async def mission_websocket(
    websocket: WebSocket,
    mission_id: str
):
    """
    Mission-specific WebSocket endpoint.
    
    Receives events only for the specified mission.
    
    Authentication:
    - REQUIRED for mission-specific endpoint
    - Token via subprotocol: new WebSocket(url, ['access_token.{JWT}'])
    
    Events:
    - new_target: New target discovered
    - new_vuln: New vulnerability found
    - new_cred: New credential harvested
    - new_session: New session established
    - goal_achieved: Mission goal achieved
    - status_change: Mission status changed
    - statistics: Stats update
    - terminal_command_start: Command execution started
    - terminal_output_line: Real-time output line
    - terminal_command_complete: Command execution completed
    - terminal_command_error: Command execution error
    """
    # Authenticate (REQUIRED for mission endpoint)
    success, user = await accept_websocket_with_auth(websocket, require_auth=True)
    if not success:
        return
    
    # TODO: Verify user has access to this mission
    # This would require checking mission ownership in the database
    # For now, authentication is sufficient
    
    # Connection already accepted by accept_websocket_with_auth
    await manager.connect(websocket, mission_id, already_accepted=True)
    
    try:
        # Send welcome message with auth info
        await websocket.send_json({
            "type": "connected",
            "mission_id": mission_id,
            "message": f"Connected to mission {mission_id}",
            "authenticated": True,
            "user_id": user["id"] if user else None,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        while True:
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "mission_id": mission_id,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif message.get("type") == "subscribe":
                    # Client can subscribe to specific event types
                    event_types = message.get("events", [])
                    await websocket.send_json({
                        "type": "subscribed",
                        "events": event_types,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, mission_id)


# ═══════════════════════════════════════════════════════════════
# Event Broadcasting Functions
# ═══════════════════════════════════════════════════════════════

async def broadcast_new_target(
    mission_id: str,
    target_id: str,
    ip: str,
    hostname: str = None
) -> None:
    """Broadcast new target event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_target",
        "mission_id": mission_id,
        "data": {
            "target_id": target_id,
            "ip": ip,
            "hostname": hostname
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_vuln(
    mission_id: str,
    vuln_id: str,
    target_id: str,
    severity: str,
    vuln_type: str
) -> None:
    """Broadcast new vulnerability event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_vuln",
        "mission_id": mission_id,
        "data": {
            "vuln_id": vuln_id,
            "target_id": target_id,
            "severity": severity,
            "type": vuln_type
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_cred(
    mission_id: str,
    cred_id: str,
    target_id: str,
    username: str,
    privilege_level: str
) -> None:
    """Broadcast new credential event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_cred",
        "mission_id": mission_id,
        "data": {
            "cred_id": cred_id,
            "target_id": target_id,
            "username": username,
            "privilege_level": privilege_level
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_session(
    mission_id: str,
    session_id: str,
    target_id: str,
    session_type: str,
    privilege: str
) -> None:
    """Broadcast new session event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_session",
        "mission_id": mission_id,
        "data": {
            "session_id": session_id,
            "target_id": target_id,
            "type": session_type,
            "privilege": privilege
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_goal_achieved(
    mission_id: str,
    goal: str
) -> None:
    """Broadcast goal achieved event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "goal_achieved",
        "mission_id": mission_id,
        "data": {
            "goal": goal
        },
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Also broadcast globally
    await manager.broadcast_global({
        "type": "goal_achieved",
        "mission_id": mission_id,
        "data": {
            "goal": goal
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_status_change(
    mission_id: str,
    old_status: str,
    new_status: str
) -> None:
    """Broadcast mission status change."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "status_change",
        "mission_id": mission_id,
        "data": {
            "old_status": old_status,
            "new_status": new_status
        },
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Also broadcast globally
    await manager.broadcast_global({
        "type": "status_change",
        "mission_id": mission_id,
        "data": {
            "old_status": old_status,
            "new_status": new_status
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_statistics(
    mission_id: str,
    stats: Dict[str, Any]
) -> None:
    """Broadcast statistics update."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "statistics",
        "mission_id": mission_id,
        "data": stats,
        "timestamp": datetime.utcnow().isoformat()
    })


# ═══════════════════════════════════════════════════════════════
# HITL (Human-in-the-Loop) Event Broadcasting
# ═══════════════════════════════════════════════════════════════

async def broadcast_approval_request(
    mission_id: str,
    action_id: str,
    action_type: str,
    action_description: str,
    target_ip: str = None,
    target_hostname: str = None,
    risk_level: str = "medium",
    risk_reasons: list = None,
    potential_impact: str = None,
    command_preview: str = None,
    expires_at: str = None
) -> None:
    """
    Broadcast approval request event to frontend.
    
    This notifies connected clients that user approval is required
    for a high-risk action.
    """
    await manager.broadcast_to_mission(mission_id, {
        "type": "approval_request",
        "mission_id": mission_id,
        "data": {
            "action_id": action_id,
            "action_type": action_type,
            "action_description": action_description,
            "target_ip": target_ip,
            "target_hostname": target_hostname,
            "risk_level": risk_level,
            "risk_reasons": risk_reasons or [],
            "potential_impact": potential_impact,
            "command_preview": command_preview,
            "expires_at": expires_at
        },
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Also broadcast globally for dashboard notifications
    await manager.broadcast_global({
        "type": "approval_request",
        "mission_id": mission_id,
        "data": {
            "action_id": action_id,
            "action_type": action_type,
            "action_description": action_description,
            "risk_level": risk_level
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_approval_response(
    mission_id: str,
    action_id: str,
    approved: bool,
    rejection_reason: str = None,
    user_comment: str = None
) -> None:
    """
    Broadcast approval response event.
    
    Notifies clients that an approval decision has been made.
    """
    await manager.broadcast_to_mission(mission_id, {
        "type": "approval_response",
        "mission_id": mission_id,
        "data": {
            "action_id": action_id,
            "approved": approved,
            "rejection_reason": rejection_reason,
            "user_comment": user_comment
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_chat_message(
    mission_id: str,
    message_id: str,
    role: str,
    content: str,
    related_task_id: str = None,
    related_action_id: str = None
) -> None:
    """
    Broadcast chat message event.
    
    Used for human-system interactive communication.
    """
    await manager.broadcast_to_mission(mission_id, {
        "type": "chat_message",
        "mission_id": mission_id,
        "data": {
            "message_id": message_id,
            "role": role,
            "content": content,
            "related_task_id": related_task_id,
            "related_action_id": related_action_id
        },
        "timestamp": datetime.utcnow().isoformat()
    })


# ═══════════════════════════════════════════════════════════════
# AI Plan & Terminal Output Broadcasting
# ═══════════════════════════════════════════════════════════════

async def broadcast_ai_plan(
    mission_id: str,
    tasks: List[Dict[str, Any]],
    message: str = None,
    reasoning: str = None
) -> None:
    """
    Broadcast AI plan event to frontend.
    
    This is used when the AI agent creates or updates a task plan.
    
    Args:
        mission_id: Mission ID
        tasks: List of task objects with id, title, description, status, order
        message: Optional message about the plan
        reasoning: Optional reasoning for the plan
    """
    await manager.broadcast_to_mission(mission_id, {
        "type": "ai_plan",
        "mission_id": mission_id,
        "data": {
            "tasks": tasks,
            "message": message,
            "reasoning": reasoning
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_terminal_output(
    mission_id: str,
    command: str = None,
    output: str = None,
    exit_code: int = None,
    status: str = "running"
) -> None:
    """
    Broadcast terminal output event to frontend.
    
    This is used when commands are executed on the target VM.
    
    Args:
        mission_id: Mission ID
        command: The command being executed
        output: Output text from the command
        exit_code: Exit code if command completed
        status: Command status (running, completed, error)
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        await manager.broadcast_to_mission(mission_id, {
            "type": "terminal_output",
            "mission_id": mission_id,
            "data": {
                "command": command,
                "output": output,
                "exit_code": exit_code,
                "status": status
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to broadcast terminal_output: {e}")
        # Store event for polling clients as fallback
        await _store_terminal_event_for_polling(mission_id, command, output, exit_code, status)


async def broadcast_terminal_command_start(
    mission_id: str,
    command: str,
    command_id: str = None
) -> None:
    """
    Broadcast terminal command start event.
    
    Called when a command begins execution to show the user
    that their command has been received and is starting.
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        await manager.broadcast_to_mission(mission_id, {
            "type": "terminal_command_start",
            "mission_id": mission_id,
            "data": {
                "command": command,
                "command_id": command_id
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to broadcast terminal_command_start: {e}")


async def broadcast_terminal_output_line(
    mission_id: str,
    line: str,
    command_id: str = None,
    is_simulation: bool = False
) -> None:
    """
    Broadcast a single line of terminal output in real-time.
    
    This enables streaming output - each line is sent as soon as
    it's available, giving users immediate feedback.
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        await manager.broadcast_to_mission(mission_id, {
            "type": "terminal_output_line",
            "mission_id": mission_id,
            "data": {
                "line": line,
                "command_id": command_id,
                "simulation": is_simulation
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to broadcast terminal_output_line: {e}")


async def broadcast_terminal_command_complete(
    mission_id: str,
    command: str,
    exit_code: int,
    command_id: str = None,
    duration_ms: int = None
) -> None:
    """
    Broadcast terminal command completion event.
    
    Called when a command finishes execution (success or failure).
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        await manager.broadcast_to_mission(mission_id, {
            "type": "terminal_command_complete",
            "mission_id": mission_id,
            "data": {
                "command": command,
                "command_id": command_id,
                "exit_code": exit_code,
                "duration_ms": duration_ms
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to broadcast terminal_command_complete: {e}")


async def broadcast_terminal_command_error(
    mission_id: str,
    command: str,
    error: str,
    command_id: str = None
) -> None:
    """
    Broadcast terminal command error event.
    
    Called when a command fails due to an error.
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        await manager.broadcast_to_mission(mission_id, {
            "type": "terminal_command_error",
            "mission_id": mission_id,
            "data": {
                "command": command,
                "command_id": command_id,
                "error": error
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to broadcast terminal_command_error: {e}")


async def _store_terminal_event_for_polling(
    mission_id: str,
    command: str = None,
    output: str = None,
    exit_code: int = None,
    status: str = None
) -> None:
    """
    Store terminal event in Redis for polling clients.
    
    This is a fallback mechanism when WebSocket broadcast fails.
    Polling clients can retrieve these events via HTTP endpoint.
    """
    import logging
    logger = logging.getLogger("raglox.websocket")
    
    try:
        # Lazy import to avoid circular dependency
        from ..core.blackboard import get_blackboard
        import json
        
        blackboard = await get_blackboard()
        if blackboard and hasattr(blackboard, 'redis_client'):
            key = f"mission:{mission_id}:terminal_events"
            event = {
                "type": "terminal_output",
                "command": command,
                "output": output,
                "exit_code": exit_code,
                "status": status,
                "timestamp": datetime.utcnow().isoformat()
            }
            await blackboard.redis_client.lpush(key, json.dumps(event))
            await blackboard.redis_client.ltrim(key, 0, 99)  # Keep last 100 events
            await blackboard.redis_client.expire(key, 3600)  # 1 hour TTL
            logger.debug(f"Stored terminal event for polling: {mission_id}")
    except Exception as e:
        logger.warning(f"Failed to store terminal event for polling: {e}")


# ═══════════════════════════════════════════════════════════════
# INTEGRATION: Real-Time Statistics Streaming
# ═══════════════════════════════════════════════════════════════

@websocket_router.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    """
    Real-time statistics WebSocket endpoint.
    
    Streams system-wide metrics and statistics in real-time.
    
    Updates every 1 second with:
    - Mission statistics
    - System metrics
    - Retry policy metrics
    - Circuit breaker states
    - Session health
    - Performance metrics
    """
    from ..core.stats_manager import get_stats_manager
    from ..core.retry_policy import get_retry_manager
    from ..core.session_manager import get_session_manager
    
    await websocket.accept()
    
    try:
        # Get manager instances
        stats_manager = get_stats_manager()
        retry_manager = get_retry_manager()
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to RAGLOX Stats Stream",
            "timestamp": datetime.utcnow().isoformat(),
            "stream_interval_ms": 1000
        })
        
        # Start streaming
        while True:
            try:
                # Collect all stats
                stats = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": "stats_update"
                }
                
                # System metrics from StatsManager
                if stats_manager:
                    system_stats = await stats_manager.get_all_metrics()
                    stats["system"] = system_stats
                
                # Retry policy metrics
                if retry_manager:
                    retry_stats = {}
                    for policy_name, policy in retry_manager._policies.items():
                        circuit_state = policy.circuit_breaker.state.value
                        retry_stats[policy_name] = {
                            "circuit_state": circuit_state,
                            "failure_count": policy.circuit_breaker.failure_count,
                            "success_count": policy.circuit_breaker.success_count,
                            "total_attempts": policy.metrics.total_attempts,
                            "total_successes": policy.metrics.successful_attempts,
                            "total_failures": policy.metrics.failed_attempts,
                            "avg_latency_ms": policy.metrics.average_latency_ms
                        }
                    stats["retry_policies"] = retry_stats
                
                # Send update
                await websocket.send_json(stats)
                
                # Wait before next update
                await asyncio.sleep(1.0)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                # Log error but continue streaming
                await websocket.send_json({
                    "type": "error",
                    "message": f"Stats collection error: {str(e)}",
                    "timestamp": datetime.utcnow().isoformat()
                })
                await asyncio.sleep(1.0)
                
    except WebSocketDisconnect:
        pass


@websocket_router.websocket("/ws/circuit-breakers")
async def circuit_breakers_websocket(websocket: WebSocket):
    """
    Circuit Breaker monitoring WebSocket endpoint.
    
    Real-time monitoring of all circuit breaker states with alerts.
    
    Sends alerts when:
    - Circuit breaker opens (system protection activated)
    - Circuit breaker half-opens (attempting recovery)
    - Circuit breaker closes (system recovered)
    - High failure rates detected
    """
    from ..core.retry_policy import get_retry_manager, CircuitState
    
    await websocket.accept()
    
    try:
        retry_manager = get_retry_manager()
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to Circuit Breaker Monitor",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Track previous states to detect changes
        previous_states = {}
        
        while True:
            try:
                alerts = []
                current_states = {}
                
                # Check all circuit breakers
                for policy_name, policy in retry_manager._policies.items():
                    cb = policy.circuit_breaker
                    current_state = cb.state
                    current_states[policy_name] = current_state
                    
                    # Detect state changes
                    previous_state = previous_states.get(policy_name)
                    if previous_state != current_state:
                        alert = {
                            "type": "state_change",
                            "policy": policy_name,
                            "old_state": previous_state.value if previous_state else "unknown",
                            "new_state": current_state.value,
                            "failure_count": cb.failure_count,
                            "success_count": cb.success_count,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        # Add severity
                        if current_state == CircuitState.OPEN:
                            alert["severity"] = "critical"
                            alert["message"] = f"🔴 Circuit breaker '{policy_name}' OPENED - System protection activated"
                        elif current_state == CircuitState.HALF_OPEN:
                            alert["severity"] = "warning"
                            alert["message"] = f"🟡 Circuit breaker '{policy_name}' HALF-OPEN - Attempting recovery"
                        elif current_state == CircuitState.CLOSED:
                            alert["severity"] = "info"
                            alert["message"] = f"🟢 Circuit breaker '{policy_name}' CLOSED - System recovered"
                        
                        alerts.append(alert)
                
                # Send alerts if any state changed
                if alerts:
                    await websocket.send_json({
                        "type": "alerts",
                        "alerts": alerts,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                # Send periodic status update (every 5 seconds)
                status = {
                    "type": "status",
                    "circuit_breakers": {}
                }
                
                for policy_name, policy in retry_manager._policies.items():
                    cb = policy.circuit_breaker
                    status["circuit_breakers"][policy_name] = {
                        "state": cb.state.value,
                        "failure_count": cb.failure_count,
                        "success_count": cb.success_count,
                        "failure_threshold": cb.failure_threshold,
                        "health_percentage": (
                            cb.success_count / (cb.success_count + cb.failure_count) * 100
                            if (cb.success_count + cb.failure_count) > 0 else 100.0
                        )
                    }
                
                await websocket.send_json(status)
                
                # Update previous states
                previous_states = current_states
                
                # Wait 5 seconds
                await asyncio.sleep(5.0)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Circuit breaker monitoring error: {str(e)}",
                    "timestamp": datetime.utcnow().isoformat()
                })
                await asyncio.sleep(5.0)
                
    except WebSocketDisconnect:
        pass
