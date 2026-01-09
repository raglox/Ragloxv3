# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Tactical Reasoning Engine
# Advanced multi-phase reasoning for hacker AI
# ═══════════════════════════════════════════════════════════════

"""
Tactical Reasoning Engine for Advanced Hacker AI

This engine implements multi-layered reasoning that mimics
how professional Red Team operators think and make decisions.

Reasoning Layers:
1. Situational Awareness (الوعي بالموقف)
2. Threat Modeling (نموذج التهديدات)
3. Attack Surface Analysis (تحليل سطح الهجوم)
4. Evasion Strategy (استراتيجية التهرب)
5. Tactical Decision (القرار التكتيكي)
6. Contingency Planning (التخطيط للطوارئ)

Philosophy:
- Think like an APT operator
- Consider all defenses before acting
- Always have a backup plan
- Learn from past operations
- Prioritize stealth and effectiveness

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..llm.deepseek_provider import DeepSeekProvider
    from ..blackboard import Blackboard
    from ..strategic_scorer import StrategicScorer
    from ..operational_memory import OperationalMemory
    from ..knowledge import EmbeddedKnowledge
    from ..models import Mission, Target, Vulnerability, Session, Credential


class ReasoningPhase(Enum):
    """Phases of tactical reasoning"""
    SITUATIONAL_AWARENESS = "situational_awareness"
    THREAT_MODELING = "threat_modeling"
    ATTACK_SURFACE_ANALYSIS = "attack_surface_analysis"
    EVASION_PLANNING = "evasion_planning"
    TACTICAL_DECISION = "tactical_decision"
    CONTINGENCY_PLANNING = "contingency_planning"


class MissionPhase(Enum):
    """Current phase of mission"""
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    INITIAL_ACCESS = "initial_access"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    MISSION_COMPLETE = "mission_complete"
    STALLED = "stalled"


@dataclass
class TacticalContext:
    """
    Comprehensive tactical context for reasoning
    
    This aggregates all intelligence from Blackboard and other sources
    to provide a complete operational picture for the AI.
    """
    # Mission State
    mission_id: str
    mission_phase: MissionPhase
    mission_goals: List[Dict]
    goals_achieved: List[str] = field(default_factory=list)
    progress_percentage: float = 0.0
    
    # Target Intelligence
    targets: List[Dict] = field(default_factory=list)
    compromised_targets: List[str] = field(default_factory=list)
    active_sessions: List[Dict] = field(default_factory=list)
    
    # Discovered Intelligence
    vulnerabilities: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    network_topology: Dict = field(default_factory=dict)
    
    # Defense Intelligence
    detected_defenses: List[Dict] = field(default_factory=list)
    blocked_techniques: List[str] = field(default_factory=list)
    high_risk_indicators: List[str] = field(default_factory=list)
    
    # Operational Memory (lessons learned)
    successful_techniques: List[str] = field(default_factory=list)
    failed_attempts: List[Dict] = field(default_factory=list)
    learned_patterns: List[Dict] = field(default_factory=list)
    
    # Constraints
    stealth_level: str = "normal"  # low, normal, high, extreme
    time_remaining: Optional[int] = None
    budget_tokens: Optional[int] = None
    
    # Available Resources
    available_tools: List[str] = field(default_factory=list)
    available_specialists: List[str] = field(default_factory=list)
    
    # VM Environment Status
    vm_status: str = "not_created"
    vm_ip: Optional[str] = None
    ssh_connected: bool = False
    
    # ═══════════════════════════════════════════════════════════
    # Knowledge Base Intelligence (RX Modules + Nuclei Templates)
    # ═══════════════════════════════════════════════════════════
    
    # RX Modules Intelligence (Atomic Red Team)
    available_rx_modules: List[Dict] = field(default_factory=list)
    rx_modules_for_vulns: Dict[str, List[Dict]] = field(default_factory=dict)
    rx_modules_by_platform: Dict[str, List[Dict]] = field(default_factory=dict)
    rx_modules_by_technique: Dict[str, List[Dict]] = field(default_factory=dict)
    recommended_rx_modules: List[Dict] = field(default_factory=list)
    
    # Nuclei Templates Intelligence
    available_nuclei_templates: List[Dict] = field(default_factory=list)
    nuclei_templates_by_cve: Dict[str, Dict] = field(default_factory=dict)
    nuclei_templates_by_severity: Dict[str, List[Dict]] = field(default_factory=dict)
    suggested_scan_templates: List[Dict] = field(default_factory=list)
    nuclei_critical_findings: List[Dict] = field(default_factory=list)
    
    # MITRE ATT&CK Intelligence
    relevant_techniques: List[Dict] = field(default_factory=list)
    relevant_tactics: List[Dict] = field(default_factory=list)
    technique_to_rx_mapping: Dict[str, List[str]] = field(default_factory=dict)
    
    # Knowledge Statistics
    total_rx_modules_available: int = 0
    total_nuclei_templates_available: int = 0
    knowledge_loaded: bool = False


@dataclass
class ReasoningStep:
    """Single step in the reasoning process"""
    phase: ReasoningPhase
    content: str
    insights: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    confidence: float = 0.8
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TacticalReasoning:
    """
    Result of tactical reasoning process
    
    This contains the complete output of the multi-phase reasoning,
    including situational assessment, threat analysis, and tactical decisions.
    """
    # Situational Assessment
    situation_summary: str
    current_phase: MissionPhase
    progress_percentage: float
    
    # Threat Modeling
    identified_defenses: List[Dict] = field(default_factory=list)
    defense_bypass_strategies: List[Dict] = field(default_factory=list)
    risk_assessment: Dict = field(default_factory=dict)
    
    # Attack Surface Analysis
    available_attack_vectors: List[Dict] = field(default_factory=list)
    prioritized_targets: List[Dict] = field(default_factory=list)
    attack_graph: Dict = field(default_factory=dict)
    
    # Evasion Strategy
    evasion_techniques: List[str] = field(default_factory=list)
    stealth_recommendations: Dict = field(default_factory=dict)
    timing_recommendations: Dict = field(default_factory=dict)
    
    # Tactical Decision
    recommended_action: Dict = field(default_factory=dict)
    alternative_actions: List[Dict] = field(default_factory=list)
    expected_outcome: Dict = field(default_factory=dict)
    
    # Contingency Planning
    fallback_plans: List[Dict] = field(default_factory=list)
    risk_mitigation: List[Dict] = field(default_factory=list)
    abort_conditions: List[str] = field(default_factory=list)
    
    # Reasoning Chain
    reasoning_steps: List[ReasoningStep] = field(default_factory=list)
    confidence_score: float = 0.0
    
    # Tool Calls
    planned_tool_calls: List[Dict] = field(default_factory=list)
    
    # Response to User
    response_text: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "situation_summary": self.situation_summary,
            "current_phase": self.current_phase.value if isinstance(self.current_phase, MissionPhase) else self.current_phase,
            "progress_percentage": self.progress_percentage,
            "identified_defenses": self.identified_defenses,
            "defense_bypass_strategies": self.defense_bypass_strategies,
            "risk_assessment": self.risk_assessment,
            "available_attack_vectors": self.available_attack_vectors,
            "prioritized_targets": self.prioritized_targets,
            "attack_graph": self.attack_graph,
            "evasion_techniques": self.evasion_techniques,
            "stealth_recommendations": self.stealth_recommendations,
            "timing_recommendations": self.timing_recommendations,
            "recommended_action": self.recommended_action,
            "alternative_actions": self.alternative_actions,
            "expected_outcome": self.expected_outcome,
            "fallback_plans": self.fallback_plans,
            "risk_mitigation": self.risk_mitigation,
            "abort_conditions": self.abort_conditions,
            "reasoning_steps": [
                {
                    "phase": step.phase.value if isinstance(step.phase, ReasoningPhase) else step.phase,
                    "content": step.content,
                    "insights": step.insights,
                    "decisions": step.decisions,
                    "confidence": step.confidence,
                    "timestamp": step.timestamp
                }
                for step in self.reasoning_steps
            ],
            "confidence_score": self.confidence_score,
            "planned_tool_calls": self.planned_tool_calls,
            "response_text": self.response_text
        }


class TacticalReasoningEngine:
    """
    Advanced reasoning engine for hacker AI
    
    This engine processes the mission state through multiple
    reasoning phases to produce tactical decisions that mirror
    how expert Red Team operators think.
    
    Architecture:
    - Uses DeepSeek R1 for deep reasoning
    - Integrates with Blackboard for state
    - Uses Strategic Scorer for prioritization
    - Uses Operational Memory for learning
    - Outputs structured tactical decisions
    """
    
    def __init__(
        self,
        llm_provider: 'DeepSeekProvider',
        blackboard: 'Blackboard',
        strategic_scorer: Optional['StrategicScorer'] = None,
        operational_memory: Optional['OperationalMemory'] = None,
        knowledge: Optional['EmbeddedKnowledge'] = None
    ):
        """
        Initialize tactical reasoning engine
        
        Args:
            llm_provider: DeepSeek provider for reasoning
            blackboard: Blackboard for state access
            strategic_scorer: Strategic scorer for prioritization
            operational_memory: Operational memory for learning
            knowledge: Knowledge base for tools/exploits
        """
        self.llm = llm_provider
        self.blackboard = blackboard
        self.scorer = strategic_scorer
        self.memory = operational_memory
        self.knowledge = knowledge
        self.logger = logging.getLogger("raglox.reasoning.tactical")
        
        # ═══════════════════════════════════════════════════════════
        # Phase 3.5: RAG Vector Integration - Hybrid Knowledge Retrieval
        # ═══════════════════════════════════════════════════════════
        self._hybrid_retriever = None
        self._vector_store = None
        self._use_hybrid = False
        
        # Initialize hybrid retrieval (graceful degradation)
        try:
            from ..vector_knowledge import VectorKnowledgeStore
            from ..hybrid_retriever import HybridKnowledgeRetriever
            
            # Try to initialize vector store
            self._vector_store = VectorKnowledgeStore()
            
            # Create hybrid retriever if we have both components
            if self.knowledge and self._vector_store:
                self._hybrid_retriever = HybridKnowledgeRetriever(
                    base_knowledge=self.knowledge,
                    vector_store=self._vector_store
                )
                self._use_hybrid = True
                self.logger.info("✅ Hybrid knowledge retrieval (TIER 1 + TIER 2) enabled")
            else:
                self.logger.warning("⚠️ Missing components for hybrid retrieval, using base knowledge only")
                
        except ImportError as e:
            self.logger.warning(f"⚠️ Vector dependencies not installed, using TIER 1 only: {e}")
        except Exception as e:
            self.logger.warning(f"⚠️ Failed to initialize hybrid retrieval, using TIER 1 only: {e}")
    
    async def reason(
        self,
        mission_id: str,
        user_message: str,
        chat_history: List[Dict],
        force_reasoning: bool = False
    ) -> TacticalReasoning:
        """
        Perform multi-phase tactical reasoning
        
        Args:
            mission_id: Current mission ID
            user_message: User's request/question
            chat_history: Previous chat messages
            force_reasoning: Force deep reasoning even for simple queries
        
        Returns:
            TacticalReasoning with complete analysis and plan
        """
        
        try:
            # 1. Build comprehensive tactical context
            self.logger.info(f"Building tactical context for mission {mission_id}")
            context = await self._build_tactical_context(mission_id)
            
            # 2. Determine if deep reasoning is needed
            needs_reasoning = force_reasoning or self._should_use_deep_reasoning(
                user_message, context
            )
            
            if not needs_reasoning:
                # Simple query - use fast path
                return await self._simple_response(
                    context, user_message, chat_history
                )
            
            # 3. Generate reasoning through DeepSeek R1
            self.logger.info("Performing deep tactical reasoning")
            reasoning_result = await self._perform_deep_reasoning(
                context=context,
                user_message=user_message,
                chat_history=chat_history
            )
            
            # 4. Parse and structure reasoning output
            tactical_reasoning = self._parse_reasoning_output(
                reasoning_result,
                context
            )
            
            # 5. Enrich with tactical data from other systems
            tactical_reasoning = await self._enrich_tactical_reasoning(
                tactical_reasoning,
                context
            )
            
            self.logger.info(
                f"Tactical reasoning complete: {len(tactical_reasoning.reasoning_steps)} phases, "
                f"confidence {tactical_reasoning.confidence_score:.2f}"
            )
            
            return tactical_reasoning
            
        except Exception as e:
            self.logger.error(f"Error in tactical reasoning: {e}", exc_info=True)
            # Return fallback reasoning
            return self._create_fallback_reasoning(context, str(e))
    
    async def _build_tactical_context(
        self,
        mission_id: str
    ) -> TacticalContext:
        """
        Build comprehensive tactical context from Blackboard
        
        This method gathers all available intelligence to provide
        a complete operational picture for reasoning.
        """
        
        # Get mission
        mission = await self.blackboard.get_mission(mission_id)
        if not mission:
            raise ValueError(f"Mission {mission_id} not found")
        
        # Gather all intelligence from Blackboard
        targets = await self.blackboard.list_targets(mission_id)
        vulnerabilities = await self.blackboard.list_vulnerabilities(mission_id)
        credentials = await self.blackboard.list_credentials(mission_id)
        sessions = await self.blackboard.list_sessions(mission_id)
        
        # Determine compromised targets (have active sessions)
        compromised = [
            s.target_id 
            for s in sessions 
            if s.status.value == "active"
        ]
        
        # Identify detected defenses from failed tasks
        detected_defenses = []
        blocked_techniques = []
        
        tasks = await self.blackboard.list_tasks(mission_id)
        for task in tasks:
            if task.error_context and task.error_context.detected_defenses:
                for defense in task.error_context.detected_defenses:
                    if defense not in detected_defenses:
                        detected_defenses.append({
                            "type": defense,
                            "detected_on": task.target_id,
                            "technique_blocked": task.metadata.get("technique_id", "unknown")
                        })
                        blocked_techniques.append(task.metadata.get("technique_id", "unknown"))
        
        # Get historical data from Operational Memory if available
        successful_techniques = []
        failed_attempts = []
        
        if self.memory:
            similar_ops = await self.memory.get_similar_operations(
                mission_type=mission.mission_type if hasattr(mission, 'mission_type') else "pentest",
                limit=5
            )
            
            for op in similar_ops:
                if op.get("outcome") == "success":
                    tech = op.get("technique_id")
                    if tech and tech not in successful_techniques:
                        successful_techniques.append(tech)
                elif op.get("outcome") == "failure":
                    failed_attempts.append({
                        "technique": op.get("technique_id"),
                        "reason": op.get("failure_reason", "unknown")
                    })
        
        # Determine mission phase
        phase = self._determine_mission_phase(
            targets=targets,
            vulnerabilities=vulnerabilities,
            sessions=sessions,
            goals=mission.goals if hasattr(mission, 'goals') else []
        )
        
        # Calculate progress
        goals = mission.goals if hasattr(mission, 'goals') else []
        achieved = sum(1 for g in goals if g.get("status") == "achieved")
        progress = (achieved / len(goals) * 100) if goals else 0.0
        
        # Get available tools
        available_tools = []
        if self.knowledge:
            modules = self.knowledge.list_rx_modules()
            available_tools = list(modules.keys())[:30]  # Limit for context
        
        # Get VM status from mission metadata
        vm_status = mission.metadata.get("vm_status", "not_created") if hasattr(mission, 'metadata') else "not_created"
        vm_ip = mission.metadata.get("vm_ip") if hasattr(mission, 'metadata') else None
        ssh_connected = mission.metadata.get("ssh_connected", False) if hasattr(mission, 'metadata') else False
        
        # Build initial context
        context = TacticalContext(
            mission_id=mission_id,
            mission_phase=phase,
            mission_goals=goals,
            goals_achieved=[g["id"] for g in goals if g.get("status") == "achieved"],
            progress_percentage=progress,
            targets=[self._target_to_dict(t) for t in targets],
            compromised_targets=compromised,
            active_sessions=[self._session_to_dict(s) for s in sessions if s.status.value == "active"],
            vulnerabilities=[self._vuln_to_dict(v) for v in vulnerabilities],
            credentials=[self._cred_to_dict(c) for c in credentials],
            detected_defenses=detected_defenses,
            blocked_techniques=blocked_techniques,
            successful_techniques=successful_techniques,
            failed_attempts=failed_attempts,
            stealth_level=mission.metadata.get("stealth_level", "normal") if hasattr(mission, 'metadata') else "normal",
            available_tools=available_tools,
            available_specialists=["recon", "attack", "analysis"],
            vm_status=vm_status,
            vm_ip=vm_ip,
            ssh_connected=ssh_connected
        )
    
    def _determine_mission_phase(
        self,
        targets: List,
        vulnerabilities: List,
        sessions: List,
        goals: List[Dict]
    ) -> MissionPhase:
        """
        Determine current mission phase based on operational state
        
        Phase logic:
        - reconnaissance: No targets discovered
        - discovery: Targets found, no vulnerabilities
        - initial_access: Vulnerabilities found, no sessions
        - post_exploitation: One session active
        - lateral_movement: Multiple sessions
        - mission_complete: All goals achieved
        - stalled: No progress in significant time
        """
        
        if not targets or len(targets) == 0:
            return MissionPhase.RECONNAISSANCE
        
        if not vulnerabilities or len(vulnerabilities) == 0:
            return MissionPhase.DISCOVERY
        
        active_sessions = [s for s in sessions if hasattr(s, 'status') and s.status.value == "active"]
        
        if not active_sessions:
            return MissionPhase.INITIAL_ACCESS
        
        if len(active_sessions) == 1:
            return MissionPhase.POST_EXPLOITATION
        
        if len(active_sessions) > 1:
            return MissionPhase.LATERAL_MOVEMENT
        
        # Check if all goals achieved
        if goals:
            achieved = sum(1 for g in goals if g.get("status") == "achieved")
            if achieved == len(goals):
                return MissionPhase.MISSION_COMPLETE
        
        return MissionPhase.POST_EXPLOITATION
    
    def _should_use_deep_reasoning(
        self,
        user_message: str,
        context: TacticalContext
    ) -> bool:
        """
        Determine if deep reasoning is needed for this query
        
        Use deep reasoning for:
        - Complex tactical questions
        - Exploitation planning
        - When defenses are detected
        - When previous attempts failed
        - When mission is stalled
        
        Skip deep reasoning for:
        - Simple status queries
        - Basic information requests
        - VM preparation requests
        """
        
        # Keywords that indicate need for tactical reasoning
        tactical_keywords = [
            "exploit", "attack", "hack", "compromise", "penetrate",
            "bypass", "evade", "escalate", "lateral", "pivot",
            "استغلال", "اختراق", "هجوم", "تجاوز"
        ]
        
        # Keywords for simple queries
        simple_keywords = [
            "status", "what", "show", "list", "display",
            "الحالة", "اعرض", "ما هو"
        ]
        
        msg_lower = user_message.lower()
        
        # Check for tactical keywords
        has_tactical = any(kw in msg_lower for kw in tactical_keywords)
        
        # Check for simple keywords
        has_simple = any(kw in msg_lower for kw in simple_keywords)
        
        # Use reasoning if:
        # 1. Tactical keywords present
        # 2. Defenses detected
        # 3. Previous failures
        # 4. Mission stalled
        
        if has_tactical:
            return True
        
        if context.detected_defenses:
            return True
        
        if context.failed_attempts:
            return True
        
        if context.mission_phase == MissionPhase.STALLED:
            return True
        
        # Don't use reasoning for simple queries
        if has_simple and not has_tactical:
            return False
        
        # Default: use reasoning for non-trivial missions
        return context.progress_percentage > 0 or len(context.vulnerabilities) > 0
    
    async def _simple_response(
        self,
        context: TacticalContext,
        user_message: str,
        chat_history: List[Dict]
    ) -> TacticalReasoning:
        """
        Generate simple response without deep reasoning
        
        Used for status queries and simple informational requests
        """
        
        # Generate simple status response
        response = self._generate_status_response(context)
        
        return TacticalReasoning(
            situation_summary=response,
            current_phase=context.mission_phase,
            progress_percentage=context.progress_percentage,
            confidence_score=0.9,
            response_text=response
        )
    
    def _generate_status_response(self, context: TacticalContext) -> str:
        """Generate a status response"""
        
        lines = []
        lines.append(f"📊 **Mission Status**: {context.mission_phase.value}")
        lines.append(f"📈 **Progress**: {context.progress_percentage:.0f}%")
        lines.append(f"🎯 **Goals**: {len(context.goals_achieved)}/{len(context.mission_goals)} achieved")
        lines.append(f"🖥️ **Targets**: {len(context.targets)} discovered, {len(context.compromised_targets)} compromised")
        lines.append(f"🔓 **Vulnerabilities**: {len(context.vulnerabilities)} found")
        lines.append(f"🔑 **Credentials**: {len(context.credentials)} acquired")
        lines.append(f"💻 **Sessions**: {len(context.active_sessions)} active")
        
        if context.detected_defenses:
            lines.append(f"🛡️ **Defenses Detected**: {', '.join(d['type'] for d in context.detected_defenses[:3])}")
        
        return "\n".join(lines)
    
    def _target_to_dict(self, target) -> Dict:
        """Convert target model to dict"""
        return {
            "id": str(target.id),
            "ip": target.ip,
            "hostname": target.hostname,
            "os": target.os,
            "status": target.status.value if hasattr(target.status, 'value') else str(target.status),
            "ports": [{"number": p.number, "service": p.service} for p in (target.ports or [])]
        }
    
    def _session_to_dict(self, session) -> Dict:
        """Convert session model to dict"""
        return {
            "id": str(session.id),
            "target_id": str(session.target_id),
            "target_ip": getattr(session, 'target_ip', 'unknown'),
            "username": session.username,
            "privilege_level": session.privilege_level.value if hasattr(session.privilege_level, 'value') else str(session.privilege_level),
            "session_type": session.session_type.value if hasattr(session.session_type, 'value') else str(session.session_type)
        }
    
    def _vuln_to_dict(self, vuln) -> Dict:
        """Convert vulnerability model to dict"""
        return {
            "id": str(vuln.id),
            "target_id": str(vuln.target_id),
            "target_ip": getattr(vuln, 'target_ip', 'unknown'),
            "vuln_type": vuln.vuln_type,
            "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
            "port": vuln.port,
            "cve_id": vuln.cve_id,
            "description": vuln.description[:200] if vuln.description else ""
        }
    
    def _cred_to_dict(self, cred) -> Dict:
        """Convert credential model to dict"""
        return {
            "id": str(cred.id),
            "username": cred.username,
            "credential_type": cred.credential_type.value if hasattr(cred.credential_type, 'value') else str(cred.credential_type),
            "source": getattr(cred, 'source', 'unknown')
        }
    
    async def _perform_deep_reasoning(
        self,
        context: TacticalContext,
        user_message: str,
        chat_history: List[Dict]
    ) -> Dict:
        """
        Use DeepSeek R1 to perform deep tactical reasoning
        
        This is the core of the tactical reasoning - it sends
        the complete tactical context to DeepSeek with a structured
        prompt that guides it through multi-phase reasoning.
        """
        
        # Build advanced reasoning prompt
        prompt = self._build_tactical_reasoning_prompt(
            context=context,
            user_message=user_message,
            chat_history=chat_history
        )
        
        try:
            # Call DeepSeek with reasoning mode
            # Use deepseek-reasoner for deep reasoning
            response = await self.llm.generate(
                messages=[
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user", "content": prompt["user"]}
                ],
                model="deepseek-reasoner",
                temperature=0.7,
                max_tokens=8000
            )
            
            # Extract reasoning if present
            reasoning_text = ""
            if hasattr(response, 'reasoning') and response.reasoning:
                reasoning_text = response.reasoning
            elif hasattr(response, 'raw_response') and response.raw_response:
                # Try to extract from raw response
                reasoning_text = self._extract_reasoning_from_response(
                    response.raw_response
                )
            
            return {
                "content": response.content if hasattr(response, 'content') else str(response),
                "reasoning": reasoning_text,
                "model": response.model_used if hasattr(response, 'model_used') else "deepseek-reasoner",
                "tokens": response.tokens_used if hasattr(response, 'tokens_used') else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error calling DeepSeek: {e}")
            # Fallback to regular chat model
            try:
                response = await self.llm.generate(
                    messages=[
                        {"role": "system", "content": prompt["system"]},
                        {"role": "user", "content": prompt["user"]}
                    ],
                    model="deepseek-chat",
                    temperature=0.7,
                    max_tokens=4000
                )
                
                return {
                    "content": response.content if hasattr(response, 'content') else str(response),
                    "reasoning": "",
                    "model": "deepseek-chat",
                    "tokens": response.tokens_used if hasattr(response, 'tokens_used') else 0
                }
            except Exception as e2:
                self.logger.error(f"Fallback also failed: {e2}")
                raise
    
    def _extract_reasoning_from_response(self, raw_response: Any) -> str:
        """Extract reasoning text from raw response"""
        
        if isinstance(raw_response, dict):
            # Look for reasoning_content field
            if "reasoning_content" in raw_response:
                return raw_response["reasoning_content"]
            
            # Look in choices
            if "choices" in raw_response and raw_response["choices"]:
                choice = raw_response["choices"][0]
                if "message" in choice:
                    msg = choice["message"]
                    if "reasoning_content" in msg:
                        return msg["reasoning_content"]
        
        return ""
    
    def _build_tactical_reasoning_prompt(
        self,
        context: TacticalContext,
        user_message: str,
        chat_history: List[Dict]
    ) -> Dict[str, str]:
        """
        Build comprehensive tactical reasoning prompt
        
        This prompt guides DeepSeek through the 6-phase reasoning process:
        1. Situational Awareness
        2. Threat Modeling
        3. Attack Surface Analysis
        4. Evasion Strategy
        5. Tactical Decision
        6. Contingency Planning
        """
        
        # Format goals
        goals_text = self._format_goals(context.mission_goals, context.goals_achieved)
        
        # Format compromised assets
        assets_text = self._format_compromised_assets(context.active_sessions)
        
        # Format vulnerabilities
        vulns_text = self._format_vulnerabilities(context.vulnerabilities[:10])
        
        # Format defenses
        defenses_text = ', '.join(d['type'] for d in context.detected_defenses[:5]) if context.detected_defenses else 'None detected yet'
        
        system_prompt = f"""You are RAGLOX - an elite AI-powered penetration testing system with the mindset of an advanced Red Team operator.

OPERATIONAL CONTEXT:
═══════════════════
Mission ID: {context.mission_id}
Current Phase: {context.mission_phase.value}
Progress: {len(context.goals_achieved)}/{len(context.mission_goals)} goals achieved ({context.progress_percentage:.0f}%)
Stealth Level: {context.stealth_level}

INTELLIGENCE BRIEF:
══════════════════
Targets Discovered: {len(context.targets)}
Compromised Systems: {len(context.compromised_targets)}
Active Sessions: {len(context.active_sessions)}
Vulnerabilities Found: {len(context.vulnerabilities)}
Credentials Acquired: {len(context.credentials)}
Detected Defenses: {defenses_text}

MISSION GOALS:
═════════════
{goals_text}

COMPROMISED ASSETS:
═══════════════════
{assets_text}

KNOWN VULNERABILITIES:
══════════════════════
{vulns_text}

OPERATIONAL MEMORY:
═══════════════════
Successful Techniques (use these): {', '.join(context.successful_techniques[:5]) if context.successful_techniques else 'No data yet'}
Failed Attempts (avoid these): {', '.join(f"{f['technique']} ({f['reason']})" for f in context.failed_attempts[:3]) if context.failed_attempts else 'No failures yet'}

AVAILABLE TOOLS:
════════════════
{', '.join(context.available_tools[:20]) if context.available_tools else 'Loading...'}

ENVIRONMENT STATUS:
═══════════════════
VM Status: {context.vm_status}
VM IP: {context.vm_ip or 'Not assigned'}
SSH Connected: {'Yes' if context.ssh_connected else 'No'}

═══════════════════════════════════════════════════════════════

YOUR TACTICAL REASONING FRAMEWORK:

Phase 1: SITUATIONAL AWARENESS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Assess the current operational state:
- What progress have we made? ({context.progress_percentage:.0f}% complete)
- What intelligence do we have?
- What are our current capabilities?
- What constraints are we operating under?
- Is our attack environment ready? (VM status: {context.vm_status})

Phase 2: THREAT MODELING
━━━━━━━━━━━━━━━━━━━━━━━
Identify defensive measures:
- What defenses are present? (AV/EDR, Firewall, IDS/IPS, WAF, etc.)
- Which have we detected? {defenses_text}
- What techniques were blocked? {', '.join(context.blocked_techniques[:3]) if context.blocked_techniques else 'None so far'}
- How can we evade each defense?
- What is the detection risk level?

Phase 3: ATTACK SURFACE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Map all possible attack vectors:
- Vulnerabilities: Which are exploitable? Which align with goals?
- Credentials: Can we use them for access instead of exploits?
- Sessions: Can we pivot from compromised systems?
- Network Topology: What paths exist for lateral movement?
- Prioritization: What's the highest-value target?

Phase 4: EVASION STRATEGY
━━━━━━━━━━━━━━━━━━━━━━━━
Plan stealth and evasion:
- Stealth Level: {context.stealth_level} (adapt tactics accordingly)
- Timing: When to strike? (business hours vs. off-hours)
- Noise Level: How much detection risk is acceptable?
- Attribution: How to avoid leaving forensic traces?
- Evasion Techniques: Which to employ?

Phase 5: TACTICAL DECISION
━━━━━━━━━━━━━━━━━━━━━━━━
Make the tactical call:
- Primary Action: What's the best next move?
- Tool Selection: Which tool/module to use?
- Parameters: What configuration for success?
- Expected Outcome: What do we expect to happen?
- Success Criteria: How do we know if it worked?

Phase 6: CONTINGENCY PLANNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Prepare for failure:
- Alternative #1: If primary fails, what's next?
- Alternative #2: If that fails, what else?
- Abort Conditions: When to stop and reassess?
- Fallback Strategy: How to maintain access if detected?
- Risk Mitigation: How to minimize damage if caught?

═══════════════════════════════════════════════════════════════

RESPONSE FORMAT:

Provide your tactical reasoning following the 6 phases above.
Think like an advanced Red Team operator - strategic, stealthy, and effective.
Consider all defenses, plan evasion, and always have backups.

Then provide a clear response to the user's request with actionable recommendations.
"""

        user_prompt = f"""USER REQUEST:
{user_message}

Apply the Tactical Reasoning Framework to respond to this request.
Be thorough, tactical, and security-conscious.
"""

        return {
            "system": system_prompt,
            "user": user_prompt
        }
    
    def _format_goals(self, goals: List[Dict], achieved: List[str]) -> str:
        """Format mission goals for display"""
        if not goals:
            return "No specific goals set"
        
        lines = []
        for g in goals:
            status = "✓ ACHIEVED" if g.get("id") in achieved else "⏳ IN PROGRESS"
            lines.append(f"- {g.get('description', 'Unknown goal')} [{status}]")
        return "\n".join(lines)
    
    def _format_compromised_assets(self, sessions: List[Dict]) -> str:
        """Format compromised assets for display"""
        if not sessions:
            return "None yet - we need initial access"
        
        lines = []
        for s in sessions[:5]:
            privilege = s.get("privilege_level", "user")
            lines.append(
                f"- {s.get('target_ip', 'unknown')} "
                f"(User: {s.get('username', 'unknown')}, "
                f"Privilege: {privilege})"
            )
        
        if len(sessions) > 5:
            lines.append(f"... and {len(sessions) - 5} more")
        
        return "\n".join(lines)
    
    def _format_vulnerabilities(self, vulns: List[Dict]) -> str:
        """Format vulnerabilities for display"""
        if not vulns:
            return "None discovered yet - need vulnerability scanning"
        
        lines = []
        for v in vulns:
            severity = v.get("severity", "unknown")
            cve = v.get("cve_id", "")
            cve_text = f" ({cve})" if cve else ""
            lines.append(
                f"- {v.get('vuln_type', 'unknown')}{cve_text} on "
                f"{v.get('target_ip', 'unknown')}:{v.get('port', 'N/A')} "
                f"[{severity.upper()}]"
            )
        return "\n".join(lines)
    
    def _parse_reasoning_output(
        self,
        reasoning_result: Dict,
        context: TacticalContext
    ) -> TacticalReasoning:
        """
        Parse DeepSeek reasoning output into structured format
        
        Extracts phases, insights, decisions, and tool calls
        from the LLM's response.
        """
        
        reasoning_text = reasoning_result.get("reasoning", "")
        content_text = reasoning_result.get("content", "")
        
        # Parse reasoning phases
        phases = self._extract_reasoning_phases(reasoning_text + "\n" + content_text)
        
        # Build reasoning steps
        reasoning_steps = []
        for phase_name, phase_content in phases.items():
            try:
                phase_enum = ReasoningPhase(phase_name)
            except ValueError:
                continue
            
            step = ReasoningStep(
                phase=phase_enum,
                content=phase_content[:500],  # Truncate for storage
                insights=self._extract_insights(phase_content),
                decisions=self._extract_decisions(phase_content)
            )
            reasoning_steps.append(step)
        
        # Extract tool calls
        tool_calls = self._extract_tool_calls(content_text)
        
        # Build primary action
        recommended_action = self._parse_primary_action(
            phases.get("tactical_decision", content_text)
        )
        
        # Calculate confidence
        confidence = self._calculate_confidence(reasoning_steps, context)
        
        return TacticalReasoning(
            situation_summary=phases.get("situational_awareness", "")[:300],
            current_phase=context.mission_phase,
            progress_percentage=context.progress_percentage,
            reasoning_steps=reasoning_steps,
            recommended_action=recommended_action,
            planned_tool_calls=tool_calls,
            confidence_score=confidence,
            response_text=content_text
        )
    
    def _extract_reasoning_phases(self, text: str) -> Dict[str, str]:
        """Extract each reasoning phase from text"""
        
        phases = {}
        phase_patterns = {
            "situational_awareness": r"Phase 1.*?Situational Awareness(.*?)(?=Phase 2|Phase 3|$)",
            "threat_modeling": r"Phase 2.*?Threat Modeling(.*?)(?=Phase 3|Phase 4|$)",
            "attack_surface_analysis": r"Phase 3.*?Attack Surface Analysis(.*?)(?=Phase 4|Phase 5|$)",
            "evasion_planning": r"Phase 4.*?Evasion Strategy(.*?)(?=Phase 5|Phase 6|$)",
            "tactical_decision": r"Phase 5.*?Tactical Decision(.*?)(?=Phase 6|$)",
            "contingency_planning": r"Phase 6.*?Contingency Planning(.*?)$"
        }
        
        for phase_name, pattern in phase_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                phases[phase_name] = match.group(1).strip()
        
        return phases
    
    def _extract_insights(self, text: str) -> List[str]:
        """Extract key insights from phase text"""
        
        insights = []
        
        # Look for bullet points or numbered insights
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('- ') or line.startswith('* ') or re.match(r'^\d+\.', line):
                insight = re.sub(r'^[-*\d.]\s*', '', line).strip()
                if len(insight) > 20 and len(insight) < 200:
                    insights.append(insight)
        
        return insights[:5]  # Limit to top 5
    
    def _extract_decisions(self, text: str) -> List[str]:
        """Extract tactical decisions from phase text"""
        
        decisions = []
        
        # Look for decision keywords
        decision_keywords = [
            "will", "should", "must", "need to", "recommend",
            "plan to", "going to", "يجب", "سوف", "نوصي"
        ]
        
        lines = text.split('\n')
        for line in lines:
            line_lower = line.lower()
            if any(kw in line_lower for kw in decision_keywords):
                decision = line.strip()
                if len(decision) > 20 and len(decision) < 200:
                    decisions.append(decision)
        
        return decisions[:3]  # Limit to top 3
    
    def _extract_tool_calls(self, text: str) -> List[Dict]:
        """Extract tool calls from text"""
        
        tool_calls = []
        
        # Look for JSON tool call format
        json_pattern = r'\{[^{}]*"tool"[^{}]*"args"[^{}]*\}'
        matches = re.finditer(json_pattern, text, re.DOTALL)
        
        for match in matches:
            try:
                tool_call = json.loads(match.group(0))
                if "tool" in tool_call and "args" in tool_call:
                    tool_calls.append(tool_call)
            except json.JSONDecodeError:
                continue
        
        return tool_calls
    
    def _parse_primary_action(self, text: str) -> Dict:
        """Parse primary action from tactical decision phase"""
        
        # Extract action, tool, and parameters
        action = {
            "type": "execute",
            "description": "",
            "tool": None,
            "parameters": {}
        }
        
        # Look for tool mentions
        tools_pattern = r"(?:use|using|execute|run)\s+([a-z_]+)"
        match = re.search(tools_pattern, text, re.IGNORECASE)
        if match:
            action["tool"] = match.group(1)
        
        # Extract first meaningful sentence as description
        sentences = text.split('.')
        for sent in sentences:
            sent = sent.strip()
            if len(sent) > 30:
                action["description"] = sent
                break
        
        return action
    
    def _calculate_confidence(
        self,
        reasoning_steps: List[ReasoningStep],
        context: TacticalContext
    ) -> float:
        """Calculate overall confidence score"""
        
        base_confidence = 0.7
        
        # Boost if all phases present
        if len(reasoning_steps) >= 5:
            base_confidence += 0.1
        
        # Boost if we have good intel
        if len(context.vulnerabilities) > 0:
            base_confidence += 0.05
        
        if len(context.credentials) > 0:
            base_confidence += 0.05
        
        # Reduce if defenses detected
        if context.detected_defenses:
            base_confidence -= 0.1
        
        # Reduce if previous failures
        if context.failed_attempts:
            base_confidence -= 0.05
        
        return max(0.3, min(0.95, base_confidence))
    
    async def _enrich_context_with_knowledge(
        self,
        context: TacticalContext
    ) -> TacticalContext:
        """
        إثراء السياق التكتيكي بمعلومات قاعدة المعرفة
        
        Steps:
        1. Enrich with RX Modules intelligence
        2. Enrich with Nuclei Templates intelligence
        3. Map MITRE ATT&CK techniques
        4. Build recommendations
        """
        
        if not self.knowledge or not self.knowledge.is_loaded():
            self.logger.warning("Knowledge base not loaded, skipping enrichment")
            context.knowledge_loaded = False
            return context
        
        context.knowledge_loaded = True
        
        try:
            # ═══════════════════════════════════════════════════════════
            # Phase 3.5: Enhanced Knowledge Retrieval with Hybrid RAG
            # ═══════════════════════════════════════════════════════════
            
            # Try hybrid retrieval first (TIER 1 + TIER 2)
            if self._use_hybrid and self._hybrid_retriever:
                self.logger.info("Using hybrid knowledge retrieval (TIER 1 + TIER 2)")
                context = await self._enrich_with_hybrid_retrieval(context)
            else:
                # Fallback to base knowledge only (TIER 1)
                self.logger.info("Using base knowledge retrieval (TIER 1 only)")
                # 1. Enrich with RX Modules
                context = await self._enrich_with_rx_modules(context)
                
                # 2. Enrich with Nuclei Templates
                context = await self._enrich_with_nuclei_intelligence(context)
            
            # 3. Map MITRE ATT&CK (always run)
            context = await self._enrich_with_mitre_attack(context)
            
            # 4. Update statistics
            stats = self.knowledge.get_stats()
            if stats:
                context.total_rx_modules_available = stats.total_rx_modules
                context.total_nuclei_templates_available = stats.total_nuclei_templates
            
            self.logger.info(
                f"Knowledge enrichment complete: "
                f"{len(context.available_rx_modules)} RX modules, "
                f"{len(context.suggested_scan_templates)} Nuclei templates"
            )
            
        except Exception as e:
            self.logger.error(f"Error enriching context with knowledge: {e}", exc_info=True)
        
        return context
    
    async def _enrich_with_hybrid_retrieval(
        self,
        context: TacticalContext
    ) -> TacticalContext:
        """
        Enhanced knowledge enrichment using Hybrid RAG (TIER 1 + TIER 2).
        
        Phase 3.5: This method combines fast base knowledge retrieval
        with semantic vector search for optimal accuracy and speed.
        
        Strategy:
        1. Use hybrid retriever for vulnerability-specific knowledge
        2. Semantic search for complex multi-constraint queries
        3. Fallback to base knowledge if vector search fails
        
        Returns:
            Enriched context with knowledge from both tiers
        """
        
        if not self._hybrid_retriever:
            # Fallback to base enrichment
            return await self._enrich_with_rx_modules(context)
        
        try:
            self.logger.debug("Starting hybrid knowledge retrieval...")
            
            # 1. Build query from tactical context
            query = self._build_knowledge_query(context)
            
            # 2. Retrieve relevant knowledge via hybrid retrieval
            retrieval_result = await self._hybrid_retriever.retrieve(
                query=query,
                context={
                    'platform': self._get_primary_platform(context),
                    'phase': context.mission_phase.value,
                    'vulnerabilities': [v.get('vuln_type') for v in context.vulnerabilities],
                    'blocked_techniques': context.blocked_techniques
                },
                limit=30  # Enough for context, not overwhelming
            )
            
            # 3. Process retrieved knowledge
            available_modules = []
            suggested_nuclei = []
            
            for result in retrieval_result.results:
                # Categorize by type
                doc_type = result.get('type', result.get('metadata', {}).get('type'))
                
                if doc_type == 'rx_module':
                    # RX Module result
                    available_modules.append({
                        'rx_module_id': result.get('rx_module_id', result.get('id')),
                        'technique_id': result.get('technique_id'),
                        'technique_name': result.get('technique_name'),
                        'description': result.get('description', result.get('content')),
                        'platforms': result.get('platforms', result.get('metadata', {}).get('platforms', [])),
                        'relevance_score': result.get('score', result.get('_hybrid_score', 0.0)),
                        'source': 'hybrid_rag'
                    })
                    
                elif doc_type == 'nuclei_template':
                    # Nuclei Template result
                    suggested_nuclei.append({
                        'template_id': result.get('template_id', result.get('id')),
                        'name': result.get('name'),
                        'severity': result.get('severity'),
                        'description': result.get('description', result.get('content')),
                        'cve_id': result.get('cve_id', []),
                        'relevance_score': result.get('score', result.get('_hybrid_score', 0.0)),
                        'source': 'hybrid_rag'
                    })
            
            # 4. Update context with retrieved knowledge
            context.available_rx_modules = available_modules
            context.suggested_scan_templates = suggested_nuclei
            
            # 5. Map modules to vulnerabilities (semantic matching)
            for vuln in context.vulnerabilities:
                vuln_query = self._build_vulnerability_query(vuln)
                
                # Quick semantic search for this specific vulnerability
                vuln_results = await self._hybrid_retriever.retrieve(
                    query=vuln_query,
                    context={'type': 'rx_module'},
                    limit=3  # Top 3 most relevant
                )
                
                # Add to vulnerability
                vuln['recommended_rx_modules'] = [
                    r.get('rx_module_id', r.get('id'))
                    for r in vuln_results.results
                    if r.get('type') == 'rx_module'
                ]
            
            # 6. Log performance metrics
            self.logger.info(
                f"Hybrid retrieval complete: "
                f"{len(available_modules)} RX modules, "
                f"{len(suggested_nuclei)} Nuclei templates "
                f"via {retrieval_result.retrieval_path.value} "
                f"in {retrieval_result.latency_ms:.1f}ms"
            )
            
            return context
            
        except Exception as e:
            self.logger.error(f"Hybrid retrieval failed, falling back to base knowledge: {e}")
            # Graceful fallback
            context = await self._enrich_with_rx_modules(context)
            context = await self._enrich_with_nuclei_intelligence(context)
            return context
    
    def _build_knowledge_query(self, context: TacticalContext) -> str:
        """
        Build a semantic query from tactical context.
        
        This creates a natural language query that captures the
        operational situation for semantic search.
        """
        query_parts = []
        
        # Phase-based query
        phase_queries = {
            MissionPhase.RECONNAISSANCE: "reconnaissance techniques for network discovery",
            MissionPhase.DISCOVERY: "vulnerability scanning and service enumeration",
            MissionPhase.INITIAL_ACCESS: "initial access and exploitation techniques",
            MissionPhase.POST_EXPLOITATION: "post-exploitation and privilege escalation",
            MissionPhase.LATERAL_MOVEMENT: "lateral movement and pivoting techniques",
        }
        
        if context.mission_phase in phase_queries:
            query_parts.append(phase_queries[context.mission_phase])
        
        # Add platform context
        platform = self._get_primary_platform(context)
        if platform:
            query_parts.append(f"for {platform}")
        
        # Add specific vulnerabilities
        if context.vulnerabilities:
            vuln_types = [v.get('vuln_type', '') for v in context.vulnerabilities[:3]]
            if vuln_types:
                query_parts.append(f"vulnerabilities: {', '.join(vuln_types)}")
        
        # Add defense context
        if context.detected_defenses:
            query_parts.append("with defense evasion")
        
        return " ".join(query_parts)
    
    def _build_vulnerability_query(self, vuln: Dict[str, Any]) -> str:
        """Build a query for a specific vulnerability."""
        parts = []
        
        if vuln.get('vuln_type'):
            parts.append(vuln['vuln_type'])
        
        if vuln.get('service'):
            parts.append(f"{vuln['service']} service")
        
        if vuln.get('platform'):
            parts.append(f"on {vuln['platform']}")
        
        parts.append("exploitation techniques")
        
        return " ".join(parts)
    
    def _get_primary_platform(self, context: TacticalContext) -> Optional[str]:
        """Get the primary platform from context."""
        if not context.targets:
            return None
        
        # Count platforms
        platform_counts = {}
        for target in context.targets:
            platform = target.get('platform', target.get('os', 'unknown')).lower()
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
        
        # Return most common
        if platform_counts:
            return max(platform_counts, key=platform_counts.get)
        
        return None
    
    async def _enrich_with_rx_modules(
        self,
        context: TacticalContext
    ) -> TacticalContext:
        """
        إثراء السياق بمعلومات RX Modules (Atomic Red Team)
        
        Logic:
        1. Map RX modules to discovered vulnerabilities
        2. Find modules by platform
        3. Build technique-to-module mappings
        4. Generate recommendations
        """
        
        # 1. Map RX modules to vulnerabilities
        for vuln in context.vulnerabilities:
            vuln_id = vuln.get("id")
            vuln_type = vuln.get("vuln_type", "")
            technique_id = vuln.get("technique_id")
            platform = vuln.get("platform", "windows")
            
            modules_for_vuln = []
            
            # Try CVE-based lookup
            if vuln_type.startswith("CVE-"):
                rx_id = f"rx-{vuln_type.lower().replace('-', '_')}"
                module = self.knowledge.get_module(rx_id)
                if module:
                    modules_for_vuln.append(module)
                    self.logger.debug(f"Found RX module {rx_id} for {vuln_type}")
            
            # Try technique-based lookup
            if technique_id:
                modules = self.knowledge.get_modules_for_technique(
                    technique_id,
                    platform=platform
                )
                if modules:
                    modules_for_vuln.extend(modules[:3])  # Top 3
                    self.logger.debug(f"Found {len(modules)} modules for {technique_id}")
            
            # Try search-based lookup
            if not modules_for_vuln and vuln_type:
                modules = self.knowledge.search_modules(
                    query=vuln_type,
                    platform=platform,
                    limit=3
                )
                if modules:
                    modules_for_vuln.extend(modules)
                    self.logger.debug(f"Found {len(modules)} modules via search for {vuln_type}")
            
            if modules_for_vuln:
                context.rx_modules_for_vulns[vuln_id] = modules_for_vuln
        
        # 2. Get RX modules by platform (for general availability)
        for platform in ["windows", "linux", "macos"]:
            modules = self.knowledge.get_modules_for_platform(
                platform,
                limit=20
            )
            if modules:
                context.rx_modules_by_platform[platform] = modules
        
        # 3. Build technique-to-module mapping
        for technique in context.relevant_techniques:
            technique_id = technique.get("id")
            if technique_id:
                modules = self.knowledge.get_modules_for_technique(technique_id)
                if modules:
                    context.technique_to_rx_mapping[technique_id] = [
                        m.get("rx_module_id") for m in modules
                    ]
        
        # 4. Build recommendations based on mission phase
        if context.mission_phase == MissionPhase.INITIAL_ACCESS:
            # Recommend exploitation modules
            for vuln_id, modules in context.rx_modules_for_vulns.items():
                if modules:
                    context.recommended_rx_modules.extend(modules[:1])  # Top 1 per vuln
        
        elif context.mission_phase == MissionPhase.POST_EXPLOITATION:
            # Recommend privilege escalation and persistence
            privesc_modules = self.knowledge.search_modules(
                query="privilege escalation",
                limit=5
            )
            context.recommended_rx_modules.extend(privesc_modules)
        
        elif context.mission_phase == MissionPhase.LATERAL_MOVEMENT:
            # Recommend lateral movement modules
            lateral_modules = self.knowledge.search_modules(
                query="lateral movement",
                limit=5
            )
            context.recommended_rx_modules.extend(lateral_modules)
        
        # Collect all unique available modules
        all_modules = []
        for modules_list in context.rx_modules_for_vulns.values():
            all_modules.extend(modules_list)
        for modules_list in context.rx_modules_by_platform.values():
            all_modules.extend(modules_list)
        
        # Deduplicate
        seen = set()
        unique_modules = []
        for m in all_modules:
            mid = m.get("rx_module_id")
            if mid and mid not in seen:
                seen.add(mid)
                unique_modules.append(m)
        
        context.available_rx_modules = unique_modules[:50]  # Limit for context size
        
        return context
    
    async def _enrich_with_nuclei_intelligence(
        self,
        context: TacticalContext
    ) -> TacticalContext:
        """
        إثراء السياق بمعلومات Nuclei Templates
        
        Logic:
        1. Map Nuclei templates to CVEs
        2. Find templates by severity
        3. Suggest scans based on discovered services
        4. Identify critical findings
        """
        
        # 1. Map Nuclei templates to CVEs
        for vuln in context.vulnerabilities:
            cve_id = vuln.get("cve_id")
            if cve_id:
                template = self.knowledge.get_nuclei_template_by_cve(cve_id)
                if template:
                    context.nuclei_templates_by_cve[cve_id] = template
                    self.logger.debug(f"Found Nuclei template for {cve_id}")
        
        # 2. Get templates by severity
        for severity in ["critical", "high", "medium"]:
            templates = self.knowledge.get_nuclei_templates_by_severity(
                severity=severity,
                limit=10
            )
            if templates:
                context.nuclei_templates_by_severity[severity] = templates
        
        # 3. Suggest scan templates based on discovered services
        for target in context.targets:
            # Extract services
            services = set()
            for port in target.get("ports", []):
                service = port.get("service")
                if service:
                    services.add(service.lower())
            
            # Find templates for each service
            for service in list(services)[:5]:  # Limit to 5 services
                # Critical templates
                critical_templates = self.knowledge.search_nuclei_templates(
                    query=service,
                    severity="critical",
                    limit=3
                )
                context.suggested_scan_templates.extend(critical_templates)
                
                # High templates
                high_templates = self.knowledge.search_nuclei_templates(
                    query=service,
                    severity="high",
                    limit=3
                )
                context.suggested_scan_templates.extend(high_templates)
        
        # 4. Identify critical findings from existing vulnerabilities
        for vuln in context.vulnerabilities:
            if vuln.get("severity", "").lower() in ["critical", "high"]:
                # Check if we have a Nuclei template for this
                vuln_type = vuln.get("vuln_type", "")
                if vuln_type:
                    templates = self.knowledge.search_nuclei_templates(
                        query=vuln_type,
                        limit=1
                    )
                    if templates:
                        context.nuclei_critical_findings.extend(templates)
        
        # Deduplicate suggested templates
        seen = set()
        unique_templates = []
        for t in context.suggested_scan_templates:
            tid = t.get("template_id")
            if tid and tid not in seen:
                seen.add(tid)
                unique_templates.append(t)
        
        context.suggested_scan_templates = unique_templates[:20]  # Limit
        
        # Collect all unique templates
        all_templates = []
        all_templates.extend(context.nuclei_templates_by_cve.values())
        for templates_list in context.nuclei_templates_by_severity.values():
            all_templates.extend(templates_list)
        
        # Deduplicate
        seen = set()
        unique = []
        for t in all_templates:
            tid = t.get("template_id")
            if tid and tid not in seen:
                seen.add(tid)
                unique.append(t)
        
        context.available_nuclei_templates = unique[:50]  # Limit
        
        return context
    
    async def _enrich_with_mitre_attack(
        self,
        context: TacticalContext
    ) -> TacticalContext:
        """
        إثراء السياق بمعلومات MITRE ATT&CK
        
        Logic:
        1. Extract techniques from vulnerabilities
        2. Map techniques to tactics
        3. Build technique coverage map
        """
        
        # 1. Extract unique techniques
        technique_ids = set()
        for vuln in context.vulnerabilities:
            technique_id = vuln.get("technique_id")
            if technique_id:
                technique_ids.add(technique_id)
        
        # Also from successful attempts
        for tech in context.successful_techniques:
            if tech:
                technique_ids.add(tech)
        
        # Get technique details
        for tech_id in technique_ids:
            technique = self.knowledge.get_technique(tech_id)
            if technique:
                context.relevant_techniques.append(technique)
        
        # 2. Extract tactics from techniques
        tactic_ids = set()
        for technique in context.relevant_techniques:
            # Tactics would be in technique metadata
            # For now, we'll extract from technique ID patterns
            # T1003 → TA0006 (Credential Access)
            pass  # TODO: Implement tactic mapping if available
        
        return context
    
    async def _enrich_tactical_reasoning(
        self,
        reasoning: TacticalReasoning,
        context: TacticalContext
    ) -> TacticalReasoning:
        """
        Enrich reasoning with data from other systems
        
        Adds strategic scoring, operational memory insights,
        and other tactical data.
        """
        
        # Use Strategic Scorer to prioritize targets
        if self.scorer and context.vulnerabilities:
            scored_vulns = []
            for vuln in context.vulnerabilities[:10]:  # Limit for performance
                try:
                    score = await self.scorer.score_vulnerability(
                        vuln_id=vuln["id"],
                        vuln_type=vuln["vuln_type"],
                        target_id=vuln["target_id"],
                        mission_id=context.mission_id
                    )
                    
                    scored_vulns.append({
                        "vulnerability": vuln,
                        "score": score.composite_score,
                        "risk_level": score.risk_level.value,
                        "recommended_modules": score.recommended_modules
                    })
                except Exception as e:
                    self.logger.warning(f"Failed to score vulnerability {vuln['id']}: {e}")
            
            # Sort by score
            scored_vulns.sort(key=lambda x: x["score"], reverse=True)
            reasoning.prioritized_targets = scored_vulns
        
        return reasoning
    
    def _create_fallback_reasoning(
        self,
        context: TacticalContext,
        error: str
    ) -> TacticalReasoning:
        """Create fallback reasoning when LLM fails"""
        
        return TacticalReasoning(
            situation_summary=f"Mission at {context.progress_percentage:.0f}% progress. {len(context.compromised_targets)} systems compromised.",
            current_phase=context.mission_phase,
            progress_percentage=context.progress_percentage,
            confidence_score=0.5,
            response_text=f"I encountered an error in tactical reasoning: {error}. Please try rephrasing your request or check system status."
        )
