# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - API Routes (SaaS Edition)
# REST API endpoints for mission management with multi-tenant isolation
# ═══════════════════════════════════════════════════════════════
"""
Mission API routes with organization-level data isolation.

Security Features:
- All endpoints require authentication
- Missions are scoped to organization_id
- Users can only access their organization's missions
- Organization limits enforced (max missions/month, concurrent missions)
"""

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import asyncio
import json

from ..core.models import (
    MissionCreate, MissionStatus, MissionStats, Mission,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType,
    Session, SessionStatus,
    # HITL Models
    ApprovalAction, ApprovalStatus, RiskLevel, ActionType
)
from ..core.validators import validate_uuid
from ..core.exceptions import InvalidUUIDError
from ..controller.mission import MissionController
from .auth_routes import get_current_user


logger = logging.getLogger("raglox.api.routes")
router = APIRouter(tags=["Missions"])


# ═══════════════════════════════════════════════════════════════
# Rate Limiting Implementation
# ═══════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Simple in-memory rate limiter for API endpoints.
    
    Implements a sliding window rate limiting strategy.
    Configured per endpoint with customizable limits.
    """
    
    def __init__(self):
        # user_id -> list of timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)
        # Cleanup old entries periodically
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # seconds
    
    def _cleanup_old_entries(self, window_seconds: int = 60):
        """Remove old entries to prevent memory growth."""
        current_time = time.time()
        
        # Only cleanup periodically
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        cutoff = current_time - window_seconds
        keys_to_delete = []
        
        for key, timestamps in self._requests.items():
            # Filter out old timestamps
            self._requests[key] = [ts for ts in timestamps if ts > cutoff]
            if not self._requests[key]:
                keys_to_delete.append(key)
        
        # Delete empty keys
        for key in keys_to_delete:
            del self._requests[key]
        
        self._last_cleanup = current_time
    
    def check_rate_limit(
        self,
        user_id: str,
        max_requests: int = 20,
        window_seconds: int = 60
    ) -> Tuple[bool, int]:
        """
        Check if user has exceeded rate limit.
        
        Args:
            user_id: Unique identifier for the user
            max_requests: Maximum allowed requests in window
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        self._cleanup_old_entries(window_seconds)
        
        current_time = time.time()
        cutoff = current_time - window_seconds
        
        # Get recent requests for this user
        user_requests = self._requests[user_id]
        
        # Filter to only include requests within window
        recent_requests = [ts for ts in user_requests if ts > cutoff]
        self._requests[user_id] = recent_requests
        
        # Check if limit exceeded
        request_count = len(recent_requests)
        remaining = max(0, max_requests - request_count)
        
        if request_count >= max_requests:
            return False, 0
        
        # Record this request
        self._requests[user_id].append(current_time)
        
        return True, remaining - 1


# Global rate limiter instance
_rate_limiter = RateLimiter()


# Rate limit configurations per endpoint
RATE_LIMITS = {
    "chat": {"max_requests": 20, "window_seconds": 60},  # 20 messages per minute
    "execute": {"max_requests": 10, "window_seconds": 60},  # 10 commands per minute
    "approval": {"max_requests": 30, "window_seconds": 60},  # 30 approval actions per minute
}


async def check_rate_limit(
    user_id: str,
    endpoint: str = "default",
    custom_max: int = None,
    custom_window: int = None
):
    """
    Check rate limit for a user on a specific endpoint.
    
    Raises HTTPException 429 if rate limit exceeded.
    """
    config = RATE_LIMITS.get(endpoint, {"max_requests": 60, "window_seconds": 60})
    
    max_requests = custom_max or config["max_requests"]
    window_seconds = custom_window or config["window_seconds"]
    
    is_allowed, remaining = _rate_limiter.check_rate_limit(
        user_id=f"{user_id}:{endpoint}",
        max_requests=max_requests,
        window_seconds=window_seconds
    )
    
    if not is_allowed:
        logger.warning(
            f"Rate limit exceeded for user {user_id} on endpoint {endpoint}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} requests per {window_seconds} seconds. "
                   f"Please wait before making more requests.",
            headers={
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + window_seconds)
            }
        )
    
    return remaining


# ═══════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════

async def get_controller(request: Request) -> MissionController:
    """Get the mission controller from app state."""
    if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Controller not initialized"
        )
    return request.app.state.controller


async def verify_mission_ownership(
    mission_id: str,
    organization_id: str,
    controller: MissionController
) -> Dict[str, Any]:
    """
    Verify that the mission belongs to the user's organization.
    
    Args:
        mission_id: Mission ID to verify
        organization_id: User's organization ID
        controller: Mission controller
        
    Returns:
        Mission data if ownership verified
        
    Raises:
        HTTPException 404: Mission not found or doesn't belong to organization
    """
    mission_data = await controller.get_mission_status(mission_id)
    
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    # Verify organization ownership
    mission_org_id = mission_data.get("organization_id")
    if mission_org_id and str(mission_org_id) != str(organization_id):
        logger.warning(
            f"Organization isolation violation: User from org {organization_id} "
            f"attempted to access mission {mission_id} from org {mission_org_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return mission_data


async def get_org_repo(request: Request):
    """Get organization repository from app state."""
    org_repo = getattr(request.app.state, 'org_repo', None)
    if not org_repo:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Organization service unavailable"
        )
    return org_repo


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class MissionResponse(BaseModel):
    """Mission response model."""
    mission_id: str
    name: str
    status: str
    message: str


class MissionStatusResponse(BaseModel):
    """Comprehensive mission status response."""
    mission_id: str
    name: Optional[str] = None
    status: Optional[str] = None
    scope: Optional[List[str]] = None
    goals: Optional[Dict[str, str]] = None
    statistics: Optional[Dict[str, int]] = None
    target_count: int = 0
    vuln_count: int = 0
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class TargetResponse(BaseModel):
    """Target response model."""
    target_id: str
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    status: str
    priority: str
    risk_score: Optional[float] = None
    ports: Dict[str, str] = {}


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model."""
    vuln_id: str
    target_id: str
    type: str
    name: Optional[str] = None
    severity: str
    cvss: Optional[float] = None
    status: str
    exploit_available: bool = False


class CredentialResponse(BaseModel):
    """Credential response model."""
    cred_id: str
    target_id: str
    type: str
    username: str
    domain: Optional[str] = None
    privilege_level: str
    source: Optional[str] = None
    verified: bool = False
    created_at: Optional[str] = None


class SessionResponse(BaseModel):
    """Session response model."""
    session_id: str
    target_id: str
    type: str
    user: str
    privilege: str
    status: str
    established_at: Optional[str] = None
    last_activity: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# HITL Request/Response Models
# ═══════════════════════════════════════════════════════════════

class ApprovalRequest(BaseModel):
    """Request model for approving/rejecting actions."""
    user_comment: Optional[str] = Field(None, description="Optional user comment")


class RejectionRequest(BaseModel):
    """Request model for rejecting actions."""
    rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
    user_comment: Optional[str] = Field(None, description="Optional user comment")


class ChatRequest(BaseModel):
    """Request model for chat messages."""
    content: str = Field(..., min_length=1, max_length=4096, description="Message content")
    related_task_id: Optional[str] = Field(None, description="Related task ID")
    related_action_id: Optional[str] = Field(None, description="Related approval action ID")


class StreamingChatRequest(BaseModel):
    """Request model for streaming chat messages."""
    content: str = Field(..., min_length=1, max_length=4096, description="Message content")
    related_task_id: Optional[str] = Field(None, description="Related task ID")
    related_action_id: Optional[str] = Field(None, description="Related approval action ID")


class ApprovalResponse(BaseModel):
    """Response model for approval operations."""
    success: bool
    message: str
    action_id: str
    mission_status: str


class PendingApprovalResponse(BaseModel):
    """Response model for pending approvals."""
    action_id: str
    action_type: str
    action_description: str
    target_ip: Optional[str] = None
    risk_level: str
    risk_reasons: List[str] = []
    potential_impact: Optional[str] = None
    command_preview: Optional[str] = None
    requested_at: str
    expires_at: Optional[str] = None


class ChatMessageResponse(BaseModel):
    """Response model for chat messages."""
    id: str
    role: str
    content: str
    timestamp: str
    related_task_id: Optional[str] = None
    related_action_id: Optional[str] = None
    # Command field for terminal integration
    command: Optional[str] = None
    output: Optional[List[str]] = None


# ═══════════════════════════════════════════════════════════════
# Mission Endpoints
# ═══════════════════════════════════════════════════════════════

@router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
async def create_mission(
    request: Request,
    mission_data: MissionCreate,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionResponse:
    """
    Create a new mission.
    
    Requires authentication. Mission will be associated with user's organization.
    
    - **name**: Mission name
    - **description**: Optional description
    - **scope**: List of target ranges (CIDRs, IPs, domains)
    - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
    - **constraints**: Optional constraints (e.g., {"stealth": true})
    """
    organization_id = current_user.get("organization_id")
    user_id = current_user.get("id")
    
    # Check organization limits
    org_repo = await get_org_repo(request)
    org_uuid = UUID(organization_id)
    
    # Verify can create mission (monthly limit)
    can_create = await org_repo.can_create_mission(org_uuid)
    if not can_create:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Monthly mission limit reached. Please upgrade your plan."
        )
    
    # Check concurrent mission limit
    current_missions = await org_repo.get_current_mission_count(org_uuid)
    org_data = await org_repo.get_by_id(org_uuid)
    if org_data and current_missions >= org_data.max_concurrent_missions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Concurrent mission limit ({org_data.max_concurrent_missions}) reached. "
                   f"Please wait for a mission to complete or upgrade your plan."
        )
    
    try:
        # Pass organization_id and user_id to controller
        mission_id = await controller.create_mission(
            mission_data,
            organization_id=organization_id,
            created_by=user_id
        )
        
        # Increment organization mission count
        await org_repo.increment_mission_count(org_uuid)
        
        logger.info(
            f"Mission {mission_id} created by user {user_id} "
            f"for organization {organization_id}"
        )
        
        return MissionResponse(
            mission_id=mission_id,
            name=mission_data.name,
            status="created",
            message="Mission created successfully"
        )
    except Exception as e:
        logger.error(f"Failed to create mission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create mission: {str(e)}"
        )


@router.get("/missions", response_model=List[str])
async def list_missions(
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[str]:
    """
    List all active mission IDs for the current user's organization.
    
    Requires authentication. Only returns missions belonging to user's organization.
    """
    organization_id = current_user.get("organization_id")
    return await controller.get_active_missions(organization_id=organization_id)


@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionStatusResponse:
    """
    Get mission status and details.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership and get data
    status_data = await verify_mission_ownership(mission_id, organization_id, controller)
    
    return MissionStatusResponse(**status_data)


@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionResponse:
    """
    Start a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    logger.info(f"Mission {mission_id} started by user {current_user.get('id')}")
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )


@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionResponse:
    """
    Pause a running mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    logger.info(f"Mission {mission_id} paused by user {current_user.get('id')}")
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )


@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionResponse:
    """
    Resume a paused mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    logger.info(f"Mission {mission_id} resumed by user {current_user.get('id')}")
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )


@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> MissionResponse:
    """
    Stop a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    # Stop the mission
    try:
        result = await controller.stop_mission(mission_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )

        logger.info(f"Mission {mission_id} stopped by user {current_user.get('id')}")

        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="stopped",
            message="Mission stopped successfully"
        )
    except HTTPException:
        # Re-raise HTTP exceptions (like 404, 400)
        raise
    except Exception as e:
        logger.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )


# ═══════════════════════════════════════════════════════════════
# Target Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[TargetResponse]:
    """
    List all targets for a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets


@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> TargetResponse:
    """
    Get a specific target.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )


# ═══════════════════════════════════════════════════════════════
# Vulnerability Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[VulnerabilityResponse]:
    """
    List all vulnerabilities for a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns


# ═══════════════════════════════════════════════════════════════
# Statistics Endpoint
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# Credential Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[CredentialResponse]:
    """
    List all credentials for a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds


# ═══════════════════════════════════════════════════════════════
# Session Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[SessionResponse]:
    """
    List all active sessions for a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions


# ═══════════════════════════════════════════════════════════════
# Statistics Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get mission statistics.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }


# ═══════════════════════════════════════════════════════════════
# HITL (Human-in-the-Loop) Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
async def list_pending_approvals(
    mission_id: str,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[PendingApprovalResponse]:
    """
    List all pending approval requests for a mission.
    
    These are high-risk actions waiting for user consent.
    Requires authentication. Only accessible if mission belongs to user's organization.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    pending = await controller.get_pending_approvals(mission_id)
    return [PendingApprovalResponse(**p) for p in pending]


@router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
async def approve_action(
    mission_id: str,
    action_id: str,
    request_data: ApprovalRequest = None,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> ApprovalResponse:
    """
    Approve a pending action.
    
    This allows the action to proceed and resumes mission execution.
    Requires authentication. Only accessible if mission belongs to user's organization.
    
    - **action_id**: ID of the action to approve
    - **user_comment**: Optional comment explaining the approval
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    mission_data = await verify_mission_ownership(mission_id, organization_id, controller)
    
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.approve_action(
        mission_id=mission_id,
        action_id=action_id,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    logger.info(f"Action {action_id} approved by user {current_user.get('id')}")
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action approved successfully. Mission execution resumed.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
async def reject_action(
    mission_id: str,
    action_id: str,
    request_data: RejectionRequest = None,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> ApprovalResponse:
    """
    Reject a pending action.
    
    The system will attempt to find an alternative approach.
    Requires authentication. Only accessible if mission belongs to user's organization.
    
    - **action_id**: ID of the action to reject
    - **rejection_reason**: Reason for rejection
    - **user_comment**: Optional additional comment
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    mission_data = await verify_mission_ownership(mission_id, organization_id, controller)
    
    rejection_reason = request_data.rejection_reason if request_data else None
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.reject_action(
        mission_id=mission_id,
        action_id=action_id,
        rejection_reason=rejection_reason,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    logger.info(f"Action {action_id} rejected by user {current_user.get('id')}")
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action rejected. System will seek alternatives.",
        action_id=action_id,
        mission_status=current_status
    )


@router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
async def send_chat_message(
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> ChatMessageResponse:
    """
    Send a chat message to interact with the mission.
    
    This allows users to:
    - Ask about mission status
    - Give instructions (pause, resume)
    - Query pending approvals
    - Execute commands on target environment
    
    Rate limited to 20 messages per minute.
    Requires authentication. Only accessible if mission belongs to user's organization.
    
    - **content**: Message content
    - **related_task_id**: Optional related task
    - **related_action_id**: Optional related approval action
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Rate limiting - 20 messages per minute
    user_id = current_user.get("id")
    remaining = await check_rate_limit(user_id, "chat")
    logger.debug(f"Chat rate limit check: user {user_id}, remaining {remaining}")
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    try:
        message = await controller.send_chat_message(
            mission_id=mission_id,
            content=request_data.content,
            related_task_id=request_data.related_task_id,
            related_action_id=request_data.related_action_id
        )
        
        return ChatMessageResponse(
            id=str(message.id),
            role=message.role,
            content=message.content,
            timestamp=message.timestamp.isoformat(),
            related_task_id=str(message.related_task_id) if message.related_task_id else None,
            related_action_id=str(message.related_action_id) if message.related_action_id else None,
            command=message.command,
            output=message.output
        )
    except Exception as e:
        logger.error(f"Chat message error for mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat message: {str(e)}"
        )


@router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
async def get_chat_history(
    mission_id: str,
    limit: int = 50,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[ChatMessageResponse]:
    """
    Get chat history for a mission.
    
    Requires authentication. Only accessible if mission belongs to user's organization.
    
    - **limit**: Maximum number of messages to return (default 50, must be > 0)
    """
    # Validate limit parameter - must be a positive integer
    if limit <= 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be a positive integer greater than 0"
        )
    
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    history = await controller.get_chat_history(mission_id, limit)
    return [ChatMessageResponse(**msg) for msg in history]


# ═══════════════════════════════════════════════════════════════
# AI Response Streaming (SSE)
# ═══════════════════════════════════════════════════════════════

@router.post("/missions/{mission_id}/chat/stream")
async def stream_chat_response(
    mission_id: str,
    request_data: StreamingChatRequest,
    request: Request,
    controller: MissionController = Depends(get_controller),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Stream AI response using Server-Sent Events (SSE).
    
    This endpoint provides real-time streaming of AI responses,
    similar to ChatGPT's typing effect. Each token/chunk is sent
    as soon as it's generated, providing immediate feedback.
    
    Rate limited to 20 messages per minute.
    Requires authentication. Only accessible if mission belongs to user's organization.
    
    SSE Event Types:
    - start: Response generation started (includes message_id)
    - chunk: A piece of the response text
    - command: A command to be executed (if applicable)
    - terminal_start: Terminal command execution started
    - terminal_output: Terminal output line
    - terminal_complete: Terminal command completed
    - end: Response generation complete
    - error: An error occurred
    
    Example client usage (JavaScript):
    ```javascript
    const response = await fetch('/api/v1/missions/{id}/chat/stream', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {token}'
        },
        body: JSON.stringify({ content: 'run nmap scan' })
    });
    
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\\n\\n');
        
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                const data = JSON.parse(line.slice(6));
                // Handle data.type: 'start', 'chunk', 'end', 'error'
            }
        }
    }
    ```
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Rate limiting - 20 messages per minute
    user_id = current_user.get("id")
    remaining = await check_rate_limit(user_id, "chat")
    logger.debug(f"Streaming chat rate limit check: user {user_id}, remaining {remaining}")
    
    organization_id = current_user.get("organization_id")
    
    # Verify ownership
    await verify_mission_ownership(mission_id, organization_id, controller)
    
    async def generate_sse_stream():
        """
        Generate Server-Sent Events stream.
        
        Yields SSE-formatted events for real-time AI response streaming.
        """
        import uuid
        from datetime import datetime
        
        message_id = str(uuid.uuid4())
        
        try:
            # Send start event
            yield f"data: {json.dumps({'type': 'start', 'message_id': message_id, 'timestamp': datetime.utcnow().isoformat()})}\n\n"
            
            # Check if controller supports streaming
            if hasattr(controller, 'stream_chat_response'):
                # Use streaming method if available
                async for chunk in controller.stream_chat_response(
                    mission_id=mission_id,
                    content=request_data.content,
                    user_id=user_id,
                    related_task_id=request_data.related_task_id,
                    related_action_id=request_data.related_action_id
                ):
                    # Chunk can be:
                    # - {"type": "text", "content": "..."} - AI text response
                    # - {"type": "command", "command": "..."} - Command to execute
                    # - {"type": "terminal_start", "command": "..."} - Terminal execution starting
                    # - {"type": "terminal_output", "line": "..."} - Terminal output
                    # - {"type": "terminal_complete", "exit_code": 0} - Terminal done
                    yield f"data: {json.dumps(chunk)}\n\n"
                    await asyncio.sleep(0)  # Allow other tasks to run
            else:
                # Fallback: Non-streaming response with simulated streaming
                logger.info("Controller does not support streaming, using fallback")
                
                # Get full response
                message = await controller.send_chat_message(
                    mission_id=mission_id,
                    content=request_data.content,
                    related_task_id=request_data.related_task_id,
                    related_action_id=request_data.related_action_id
                )
                
                # Stream the response word by word for typing effect
                content = message.content
                words = content.split(' ')
                
                for i, word in enumerate(words):
                    chunk_text = word + (' ' if i < len(words) - 1 else '')
                    yield f"data: {json.dumps({'type': 'chunk', 'content': chunk_text})}\n\n"
                    await asyncio.sleep(0.02)  # 20ms delay between words
                
                # If there's terminal output, stream it
                if message.command:
                    yield f"data: {json.dumps({'type': 'command', 'command': message.command})}\n\n"
                    
                    if message.output:
                        yield f"data: {json.dumps({'type': 'terminal_start', 'command': message.command})}\n\n"
                        for line in message.output:
                            yield f"data: {json.dumps({'type': 'terminal_output', 'line': line})}\n\n"
                            await asyncio.sleep(0.01)  # Small delay between lines
                        yield f"data: {json.dumps({'type': 'terminal_complete', 'exit_code': 0})}\n\n"
            
            # Send end event
            yield f"data: {json.dumps({'type': 'end', 'message_id': message_id, 'timestamp': datetime.utcnow().isoformat()})}\n\n"
            
        except asyncio.CancelledError:
            # Client disconnected
            logger.info(f"SSE stream cancelled for mission {mission_id}")
            yield f"data: {json.dumps({'type': 'cancelled', 'message_id': message_id})}\n\n"
        except Exception as e:
            logger.error(f"SSE streaming error for mission {mission_id}: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e), 'message_id': message_id})}\n\n"
    
    return StreamingResponse(
        generate_sse_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "X-RateLimit-Limit": str(RATE_LIMITS["chat"]["max_requests"]),
            "X-RateLimit-Remaining": str(remaining)
        }
    )


# ═══════════════════════════════════════════════════════════════
# INTEGRATION: Real-Time Statistics & Monitoring Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/stats/system")
async def get_system_stats() -> Dict[str, Any]:
    """
    Get current system-wide statistics.
    
    Returns metrics for:
    - Active missions
    - Total tasks processed
    - System health
    - Performance metrics
    """
    from ..core.stats_manager import get_stats_manager
    
    stats_manager = get_stats_manager()
    stats = await stats_manager.get_all_metrics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": stats.get("timestamp")
    }


@router.get("/stats/retry-policies")
async def get_retry_policy_stats() -> Dict[str, Any]:
    """
    Get statistics for all retry policies.
    
    Returns:
    - Success/failure rates
    - Circuit breaker states
    - Average latencies
    - Retry attempts
    """
    from ..core.retry_policy import get_retry_manager
    
    retry_manager = get_retry_manager()
    
    policies_stats = {}
    for policy_name, policy in retry_manager._policies.items():
        cb = policy.circuit_breaker
        metrics = policy.metrics
        
        policies_stats[policy_name] = {
            "circuit_breaker": {
                "state": cb.state.value,
                "failure_count": cb.failure_count,
                "success_count": cb.success_count,
                "failure_threshold": cb.failure_threshold,
                "health_percentage": (
                    cb.success_count / (cb.success_count + cb.failure_count) * 100
                    if (cb.success_count + cb.failure_count) > 0 else 100.0
                )
            },
            "metrics": {
                "total_attempts": metrics.total_attempts,
                "successful_attempts": metrics.successful_attempts,
                "failed_attempts": metrics.failed_attempts,
                "avg_latency_ms": metrics.average_latency_ms,
                "success_rate": (
                    metrics.successful_attempts / metrics.total_attempts * 100
                    if metrics.total_attempts > 0 else 0.0
                )
            },
            "policy_config": {
                "max_retries": policy.max_retries,
                "base_delay": policy.base_delay,
                "max_delay": policy.max_delay,
                "strategy": policy.backoff_strategy.value
            }
        }
    
    return {
        "status": "success",
        "data": policies_stats
    }


@router.get("/stats/sessions")
async def get_session_stats() -> Dict[str, Any]:
    """
    Get statistics for active sessions.
    
    Returns:
    - Total active sessions
    - Session health scores
    - Timeout status
    - Recent activity
    """
    from ..core.session_manager import get_session_manager
    from ..core.config import get_settings
    
    settings = get_settings()
    
    # Get session manager (requires blackboard)
    # Note: This requires access to blackboard from app state
    try:
        session_manager = get_session_manager(
            blackboard=None,  # Will use cached instance if available
            settings=settings
        )
        
        stats = await session_manager.get_statistics()
        
        return {
            "status": "success",
            "data": stats
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve session stats: {str(e)}",
            "data": {}
        }


@router.get("/stats/circuit-breakers")
async def get_circuit_breaker_states() -> Dict[str, Any]:
    """
    Get current states of all circuit breakers.
    
    Quick endpoint for monitoring circuit breaker health.
    """
    from ..core.retry_policy import get_retry_manager, CircuitState
    
    retry_manager = get_retry_manager()
    
    states = {}
    alerts = []
    
    for policy_name, policy in retry_manager._policies.items():
        cb = policy.circuit_breaker
        state = cb.state
        
        states[policy_name] = {
            "state": state.value,
            "healthy": state == CircuitState.CLOSED,
            "failure_count": cb.failure_count,
            "success_count": cb.success_count
        }
        
        # Generate alerts for open circuits
        if state == CircuitState.OPEN:
            alerts.append({
                "severity": "critical",
                "policy": policy_name,
                "message": f"Circuit breaker '{policy_name}' is OPEN - System protection active"
            })
        elif state == CircuitState.HALF_OPEN:
            alerts.append({
                "severity": "warning",
                "policy": policy_name,
                "message": f"Circuit breaker '{policy_name}' is HALF-OPEN - Recovery attempt in progress"
            })
    
    return {
        "status": "success",
        "data": {
            "circuit_breakers": states,
            "alerts": alerts,
            "healthy_count": sum(1 for s in states.values() if s["healthy"]),
            "total_count": len(states)
        }
    }
