# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Advanced Risk Assessment Engine
# Phase 5.0: Advanced Features
# ═══════════════════════════════════════════════════════════════

"""
Advanced Risk Assessment Engine for RAGLOX v3.0

Provides comprehensive risk analysis for missions, targets, and actions
using multi-factor risk scoring, threat modeling, and defense detection.

Key Features:
- Multi-factor risk scoring
- Defense capability assessment
- Attack surface risk analysis
- Action risk evaluation
- Real-time risk updates

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..reasoning.mission_intelligence import MissionIntelligence, TargetIntel

logger = logging.getLogger("raglox.core.risk_assessment")


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class RiskLevel(Enum):
    """Risk level classifications."""
    MINIMAL = "minimal"      # 0-2
    LOW = "low"              # 2-4
    MEDIUM = "medium"        # 4-6
    HIGH = "high"            # 6-8
    CRITICAL = "critical"    # 8-10
    EXTREME = "extreme"      # 10+


class DefenseLevel(Enum):
    """Defense sophistication levels."""
    NONE = "none"
    BASIC = "basic"
    MODERATE = "moderate"
    ADVANCED = "advanced"
    MILITARY_GRADE = "military_grade"


class ThreatActor(Enum):
    """Threat actor classifications."""
    SCRIPT_KIDDIE = "script_kiddie"
    HACKTIVIST = "hacktivist"
    CYBERCRIMINAL = "cybercriminal"
    APT = "apt"
    NATION_STATE = "nation_state"


# ═══════════════════════════════════════════════════════════════
# Risk Models
# ═══════════════════════════════════════════════════════════════

@dataclass
class RiskFactor:
    """Individual risk factor."""
    name: str
    weight: float  # 0.0-1.0
    score: float   # 0.0-10.0
    description: str = ""
    mitigation: str = ""


@dataclass
class DefenseCapability:
    """Defense capability assessment."""
    defense_type: str  # EDR, IDS, WAF, etc.
    sophistication: DefenseLevel
    coverage: float  # 0.0-1.0 (percentage of attack surface covered)
    evasion_difficulty: float  # 0.0-10.0
    detection_probability: float  # 0.0-1.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment."""
    assessment_id: str
    target_id: Optional[str] = None
    mission_id: Optional[str] = None
    
    # Overall risk
    overall_risk_score: float = 0.0  # 0.0-10.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Risk factors
    factors: List[RiskFactor] = field(default_factory=list)
    
    # Defense assessment
    detected_defenses: List[DefenseCapability] = field(default_factory=list)
    defense_score: float = 0.0  # 0.0-10.0
    
    # Attack surface
    attack_surface_score: float = 0.0  # 0.0-10.0
    entry_points_count: int = 0
    critical_vulnerabilities: int = 0
    
    # Operational risk
    stealth_impact: float = 5.0  # 0.0-10.0 (higher = noisier)
    time_risk: float = 5.0  # 0.0-10.0 (longer operations = higher risk)
    
    # Recommendations
    risk_mitigation_steps: List[str] = field(default_factory=list)
    proceed_recommended: bool = True
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    confidence: float = 0.8  # 0.0-1.0


@dataclass
class ActionRiskProfile:
    """Risk profile for a specific action."""
    action_type: str  # exploit, scan, lateral_move, etc.
    target_id: str
    
    # Pre-action risk
    pre_action_risk: float = 5.0
    
    # Action-specific risks
    detection_risk: float = 5.0  # Likelihood of detection
    failure_risk: float = 5.0    # Likelihood of failure
    collateral_risk: float = 5.0  # Risk of unintended consequences
    attribution_risk: float = 5.0  # Risk of attribution
    
    # Combined risk
    total_risk: float = 5.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Recommendations
    recommended: bool = True
    alternative_actions: List[str] = field(default_factory=list)
    risk_reduction_steps: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Advanced Risk Assessment Engine
# ═══════════════════════════════════════════════════════════════

class AdvancedRiskAssessmentEngine:
    """
    Advanced Risk Assessment Engine.
    
    Provides comprehensive risk analysis for missions, targets, and actions.
    
    Usage:
        engine = AdvancedRiskAssessmentEngine(
            mission_intelligence=intel
        )
        
        # Assess target risk
        risk = await engine.assess_target_risk(target_id="target-123")
        print(f"Risk: {risk.risk_level.value}, Score: {risk.overall_risk_score}")
        
        # Assess action risk
        action_risk = await engine.assess_action_risk(
            action_type="exploit",
            target_id="target-123"
        )
        print(f"Action risk: {action_risk.total_risk}")
    """
    
    def __init__(
        self,
        mission_intelligence: Optional["MissionIntelligence"] = None,
        threat_actor_profile: ThreatActor = ThreatActor.CYBERCRIMINAL,
    ):
        """
        Initialize Risk Assessment Engine.
        
        Args:
            mission_intelligence: MissionIntelligence instance
            threat_actor_profile: Threat actor profile for context
        """
        self.mission_intelligence = mission_intelligence
        self.threat_actor_profile = threat_actor_profile
        
        # Risk calculation weights
        self._weights = {
            "defense_sophistication": 0.25,
            "attack_surface": 0.20,
            "vulnerability_severity": 0.20,
            "operational_time": 0.15,
            "stealth_requirements": 0.10,
            "target_value": 0.10,
        }
        
        logger.info(f"Initialized AdvancedRiskAssessmentEngine with profile: {threat_actor_profile.value}")
    
    # ═══════════════════════════════════════════════════════════════
    # Target Risk Assessment
    # ═══════════════════════════════════════════════════════════════
    
    async def assess_target_risk(
        self,
        target_id: str,
        include_defenses: bool = True
    ) -> RiskAssessment:
        """
        Assess risk for a specific target.
        
        Args:
            target_id: Target ID
            include_defenses: Include defense capability assessment
            
        Returns:
            RiskAssessment
        """
        logger.debug(f"Assessing risk for target {target_id}")
        
        assessment = RiskAssessment(
            assessment_id=f"risk-{target_id}",
            target_id=target_id,
            mission_id=self.mission_intelligence.mission_id if self.mission_intelligence else None,
        )
        
        if not self.mission_intelligence:
            logger.warning("No mission intelligence available, using default risk")
            assessment.overall_risk_score = 5.0
            assessment.risk_level = RiskLevel.MEDIUM
            return assessment
        
        # Get target intelligence
        target = self.mission_intelligence.get_target(target_id)
        if not target:
            logger.warning(f"Target {target_id} not found in intelligence")
            assessment.overall_risk_score = 5.0
            assessment.risk_level = RiskLevel.MEDIUM
            return assessment
        
        # Calculate risk factors
        factors = []
        
        # 1. Defense sophistication
        defense_factor = await self._assess_defense_factor(target)
        factors.append(defense_factor)
        
        # 2. Vulnerability landscape
        vuln_factor = await self._assess_vulnerability_factor(target)
        factors.append(vuln_factor)
        
        # 3. Attack surface
        surface_factor = await self._assess_attack_surface_factor(target)
        factors.append(surface_factor)
        
        # 4. Target hardening
        hardening_factor = await self._assess_hardening_factor(target)
        factors.append(hardening_factor)
        
        # 5. Network exposure
        exposure_factor = await self._assess_exposure_factor(target)
        factors.append(exposure_factor)
        
        assessment.factors = factors
        
        # Calculate weighted overall risk
        total_weighted_risk = sum(
            f.weight * f.score for f in factors
        )
        
        assessment.overall_risk_score = min(total_weighted_risk, 10.0)
        assessment.risk_level = self._score_to_risk_level(assessment.overall_risk_score)
        
        # Defense assessment
        if include_defenses:
            assessment.detected_defenses = await self._assess_defenses(target)
            assessment.defense_score = self._calculate_defense_score(assessment.detected_defenses)
        
        # Get vulnerabilities for this target
        target_vulns = self.mission_intelligence.get_vulnerabilities_by_target(target_id)
        assessment.critical_vulnerabilities = len([v for v in target_vulns if v.severity == "critical"])
        
        # Attack surface
        if self.mission_intelligence.attack_surface:
            entry_points = [ep for ep in self.mission_intelligence.attack_surface.entry_points 
                          if ep.get("target_id") == target_id]
            assessment.entry_points_count = len(entry_points)
        
        # Generate risk mitigation recommendations
        assessment.risk_mitigation_steps = self._generate_mitigation_steps(assessment)
        
        # Recommend proceed or not
        assessment.proceed_recommended = assessment.overall_risk_score < 8.0
        
        logger.info(f"Target {target_id} risk assessment: {assessment.risk_level.value} "
                   f"(score: {assessment.overall_risk_score:.2f})")
        
        return assessment
    
    async def _assess_defense_factor(self, target: "TargetIntel") -> RiskFactor:
        """Assess defense sophistication factor."""
        # Check for security products
        security_products = [p.lower() for p in target.security_products]
        
        score = 3.0  # Base score
        
        # Increase risk based on detected defenses
        if any("edr" in p or "endpoint" in p for p in security_products):
            score += 3.0
        if any("av" in p or "antivirus" in p for p in security_products):
            score += 1.0
        if any("firewall" in p for p in security_products):
            score += 1.0
        if any("ids" in p or "ips" in p for p in security_products):
            score += 2.0
        
        # Hardening level
        if target.hardening_level == "high":
            score += 2.0
        elif target.hardening_level == "medium":
            score += 1.0
        
        return RiskFactor(
            name="defense_sophistication",
            weight=self._weights["defense_sophistication"],
            score=min(score, 10.0),
            description=f"Defense products detected: {len(security_products)}",
            mitigation="Use stealthy techniques, avoid signature-based detection",
        )
    
    async def _assess_vulnerability_factor(self, target: "TargetIntel") -> RiskFactor:
        """Assess vulnerability landscape factor."""
        # Get vulnerabilities for this target
        target_vulns = self.mission_intelligence.get_vulnerabilities_by_target(target.target_id)
        
        if not target_vulns:
            return RiskFactor(
                name="vulnerability_severity",
                weight=self._weights["vulnerability_severity"],
                score=8.0,  # High risk - no known vulns
                description="No known vulnerabilities",
                mitigation="Perform thorough vulnerability assessment",
            )
        
        # Calculate average severity
        severity_scores = {"critical": 10, "high": 7, "medium": 5, "low": 3, "info": 1}
        avg_severity = sum(severity_scores.get(v.severity, 5) for v in target_vulns) / len(target_vulns)
        
        # Exploitable vulnerabilities reduce risk (for attacker)
        exploitable_count = len([v for v in target_vulns if v.is_exploitable])
        exploitable_factor = max(0, 10 - exploitable_count * 2)  # More exploitable = lower risk
        
        score = (avg_severity + exploitable_factor) / 2
        
        return RiskFactor(
            name="vulnerability_severity",
            weight=self._weights["vulnerability_severity"],
            score=score,
            description=f"{len(target_vulns)} vulnerabilities, {exploitable_count} exploitable",
            mitigation="Prioritize low-complexity exploits",
        )
    
    async def _assess_attack_surface_factor(self, target: "TargetIntel") -> RiskFactor:
        """Assess attack surface factor."""
        # More open ports = larger attack surface = lower risk (for attacker)
        open_ports_count = len(target.open_ports)
        
        # Inverse relationship: more ports = lower risk for attacker
        score = max(2.0, 10.0 - (open_ports_count * 0.5))
        
        return RiskFactor(
            name="attack_surface",
            weight=self._weights["attack_surface"],
            score=score,
            description=f"{open_ports_count} open ports, {len(target.services)} services",
            mitigation="Target exposed services, avoid noisy scans",
        )
    
    async def _assess_hardening_factor(self, target: "TargetIntel") -> RiskFactor:
        """Assess target hardening factor."""
        hardening_scores = {"low": 3, "medium": 6, "high": 9, "unknown": 5}
        score = hardening_scores.get(target.hardening_level, 5)
        
        return RiskFactor(
            name="target_hardening",
            weight=0.15,
            score=score,
            description=f"Hardening level: {target.hardening_level}",
            mitigation="Use advanced exploitation techniques",
        )
    
    async def _assess_exposure_factor(self, target: "TargetIntel") -> RiskFactor:
        """Assess network exposure factor."""
        # Check if target is in DMZ or internal network
        is_dmz = target.subnet and ("dmz" in target.subnet.lower() or 
                                     target.subnet.startswith("10.") or
                                     target.subnet.startswith("172.") or
                                     target.subnet.startswith("192.168."))
        
        score = 4.0 if is_dmz else 6.0  # Internal = higher risk of detection
        
        return RiskFactor(
            name="network_exposure",
            weight=0.10,
            score=score,
            description="Network location: " + ("Internal" if is_dmz else "DMZ/External"),
            mitigation="Establish C2 quickly, minimize dwell time",
        )
    
    async def _assess_defenses(self, target: "TargetIntel") -> List[DefenseCapability]:
        """Assess defense capabilities."""
        defenses = []
        
        for product in target.security_products:
            product_lower = product.lower()
            
            if "edr" in product_lower or "endpoint" in product_lower:
                defenses.append(DefenseCapability(
                    defense_type="EDR",
                    sophistication=DefenseLevel.ADVANCED,
                    coverage=0.9,
                    evasion_difficulty=8.0,
                    detection_probability=0.7,
                    details={"product": product},
                ))
            elif "av" in product_lower or "antivirus" in product_lower:
                defenses.append(DefenseCapability(
                    defense_type="Antivirus",
                    sophistication=DefenseLevel.MODERATE,
                    coverage=0.7,
                    evasion_difficulty=5.0,
                    detection_probability=0.4,
                    details={"product": product},
                ))
            elif "firewall" in product_lower:
                defenses.append(DefenseCapability(
                    defense_type="Firewall",
                    sophistication=DefenseLevel.BASIC,
                    coverage=0.5,
                    evasion_difficulty=4.0,
                    detection_probability=0.3,
                    details={"product": product},
                ))
        
        return defenses
    
    def _calculate_defense_score(self, defenses: List[DefenseCapability]) -> float:
        """Calculate overall defense score."""
        if not defenses:
            return 2.0  # Low defense
        
        # Average evasion difficulty
        avg_difficulty = sum(d.evasion_difficulty for d in defenses) / len(defenses)
        return min(avg_difficulty, 10.0)
    
    # ═══════════════════════════════════════════════════════════════
    # Action Risk Assessment
    # ═══════════════════════════════════════════════════════════════
    
    async def assess_action_risk(
        self,
        action_type: str,
        target_id: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> ActionRiskProfile:
        """
        Assess risk for a specific action.
        
        Args:
            action_type: Type of action (exploit, scan, etc.)
            target_id: Target ID
            parameters: Action parameters
            
        Returns:
            ActionRiskProfile
        """
        logger.debug(f"Assessing risk for action {action_type} on target {target_id}")
        
        # Get target risk first
        target_risk = await self.assess_target_risk(target_id)
        
        profile = ActionRiskProfile(
            action_type=action_type,
            target_id=target_id,
            pre_action_risk=target_risk.overall_risk_score,
        )
        
        # Action-specific risk calculation
        if action_type in ["exploit", "attack"]:
            profile.detection_risk = min(target_risk.defense_score + 2.0, 10.0)
            profile.failure_risk = 6.0 - (2.0 if target_risk.critical_vulnerabilities > 0 else 0)
            profile.collateral_risk = 5.0
            profile.attribution_risk = 4.0
        
        elif action_type in ["scan", "port_scan", "vuln_scan"]:
            profile.detection_risk = 4.0  # Scans are noisy
            profile.failure_risk = 2.0  # Low failure risk
            profile.collateral_risk = 2.0
            profile.attribution_risk = 6.0  # Easy to attribute
        
        elif action_type in ["lateral_move", "lateral"]:
            profile.detection_risk = min(target_risk.defense_score + 1.0, 10.0)
            profile.failure_risk = 5.0
            profile.collateral_risk = 6.0  # Can affect other systems
            profile.attribution_risk = 5.0
        
        elif action_type in ["privilege_escalation", "privesc"]:
            profile.detection_risk = min(target_risk.defense_score + 3.0, 10.0)
            profile.failure_risk = 7.0  # High failure risk
            profile.collateral_risk = 4.0
            profile.attribution_risk = 3.0
        
        else:
            # Generic action
            profile.detection_risk = 5.0
            profile.failure_risk = 5.0
            profile.collateral_risk = 5.0
            profile.attribution_risk = 5.0
        
        # Calculate total risk
        profile.total_risk = (
            profile.pre_action_risk * 0.3 +
            profile.detection_risk * 0.3 +
            profile.failure_risk * 0.2 +
            profile.collateral_risk * 0.1 +
            profile.attribution_risk * 0.1
        )
        
        profile.risk_level = self._score_to_risk_level(profile.total_risk)
        profile.recommended = profile.total_risk < 7.5
        
        # Generate recommendations
        if profile.detection_risk > 6.0:
            profile.risk_reduction_steps.append("Use stealthy techniques")
            profile.risk_reduction_steps.append("Disable EDR/AV if possible")
        
        if profile.failure_risk > 6.0:
            profile.risk_reduction_steps.append("Verify prerequisites")
            profile.risk_reduction_steps.append("Test exploit in lab first")
        
        if not profile.recommended:
            profile.alternative_actions.append(f"Consider different approach to {target_id}")
            profile.alternative_actions.append("Wait for better opportunity")
        
        logger.info(f"Action {action_type} risk: {profile.risk_level.value} "
                   f"(total: {profile.total_risk:.2f})")
        
        return profile
    
    # ═══════════════════════════════════════════════════════════════
    # Mission-Level Risk Assessment
    # ═══════════════════════════════════════════════════════════════
    
    async def assess_mission_risk(self) -> RiskAssessment:
        """
        Assess overall mission risk.
        
        Returns:
            RiskAssessment for entire mission
        """
        logger.debug("Assessing overall mission risk")
        
        if not self.mission_intelligence:
            return RiskAssessment(
                assessment_id="mission-risk",
                overall_risk_score=5.0,
                risk_level=RiskLevel.MEDIUM,
            )
        
        assessment = RiskAssessment(
            assessment_id="mission-risk",
            mission_id=self.mission_intelligence.mission_id,
        )
        
        # Assess all targets
        targets = self.mission_intelligence.get_all_targets()
        target_risks = []
        
        for target in targets[:10]:  # Limit to 10 for performance
            target_risk = await self.assess_target_risk(target.target_id, include_defenses=False)
            target_risks.append(target_risk.overall_risk_score)
        
        # Calculate mission risk as weighted average
        if target_risks:
            # Higher weight for compromised targets
            compromised_count = self.mission_intelligence.compromised_targets
            total_count = self.mission_intelligence.total_targets
            
            compromise_factor = compromised_count / max(total_count, 1)
            avg_target_risk = sum(target_risks) / len(target_risks)
            
            # Compromised targets increase overall risk (detection risk)
            assessment.overall_risk_score = avg_target_risk * (1 + compromise_factor * 0.3)
        else:
            assessment.overall_risk_score = 5.0
        
        assessment.risk_level = self._score_to_risk_level(assessment.overall_risk_score)
        
        # Mission-specific factors
        assessment.factors = [
            RiskFactor(
                name="mission_scope",
                weight=0.2,
                score=min(len(targets) * 0.5, 10.0),
                description=f"{len(targets)} targets in scope",
            ),
            RiskFactor(
                name="compromise_rate",
                weight=0.3,
                score=compromised_count / max(total_count, 1) * 10,
                description=f"{compromised_count}/{total_count} targets compromised",
            ),
        ]
        
        # Recommendations
        if assessment.overall_risk_score > 7.0:
            assessment.risk_mitigation_steps.append("Pause and reassess strategy")
            assessment.risk_mitigation_steps.append("Increase stealth measures")
            assessment.proceed_recommended = False
        else:
            assessment.risk_mitigation_steps.append("Continue with caution")
            assessment.proceed_recommended = True
        
        logger.info(f"Mission risk assessment: {assessment.risk_level.value} "
                   f"(score: {assessment.overall_risk_score:.2f})")
        
        return assessment
    
    # ═══════════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════════
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if score < 2.0:
            return RiskLevel.MINIMAL
        elif score < 4.0:
            return RiskLevel.LOW
        elif score < 6.0:
            return RiskLevel.MEDIUM
        elif score < 8.0:
            return RiskLevel.HIGH
        elif score < 10.0:
            return RiskLevel.CRITICAL
        else:
            return RiskLevel.EXTREME
    
    def _generate_mitigation_steps(self, assessment: RiskAssessment) -> List[str]:
        """Generate risk mitigation recommendations."""
        steps = []
        
        if assessment.defense_score > 7.0:
            steps.append("Implement advanced evasion techniques")
            steps.append("Use obfuscation and anti-forensics")
        
        if assessment.critical_vulnerabilities == 0:
            steps.append("Conduct thorough vulnerability assessment")
            steps.append("Consider zero-day exploits")
        
        if assessment.overall_risk_score > 8.0:
            steps.append("Consider aborting mission - risk too high")
            steps.append("Reassess mission objectives")
        
        return steps
    
    async def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary."""
        mission_risk = await self.assess_mission_risk()
        
        return {
            "mission_risk_level": mission_risk.risk_level.value,
            "mission_risk_score": mission_risk.overall_risk_score,
            "total_targets": self.mission_intelligence.total_targets if self.mission_intelligence else 0,
            "compromised_targets": self.mission_intelligence.compromised_targets if self.mission_intelligence else 0,
            "proceed_recommended": mission_risk.proceed_recommended,
            "mitigation_steps": mission_risk.risk_mitigation_steps,
        }
