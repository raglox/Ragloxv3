"""
RAGLOX v3.0 - Advanced Risk Assessment Engine
Phase 5.0: Intelligent Risk Analysis

Real-time risk assessment based on:
- Target characteristics
- Vulnerability severity
- Detection probability
- Mission constraints
- Historical data
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio


class RiskLevel(Enum):
    """Risk level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class RiskFactor:
    """Individual risk factor"""
    name: str
    value: float  # 0.0-1.0
    weight: float  # 0.0-1.0
    description: str
    category: str = "general"  # detection, operational, etc.


@dataclass
class RiskAssessment:
    """Complete risk assessment result"""
    overall_risk: RiskLevel
    risk_score: float  # 0.0-1.0
    factors: List[RiskFactor] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.8  # 0.0-1.0


class AdvancedRiskAssessmentEngine:
    """
    Advanced Risk Assessment Engine
    
    Evaluates mission risk in real-time based on multiple factors:
    - Target security posture
    - Detection probability
    - Mission constraints
    - Attack surface analysis
    
    Usage:
        engine = AdvancedRiskAssessmentEngine(mission_id, blackboard)
        assessment = await engine.assess_current_risk()
        print(f"Risk Level: {assessment.overall_risk}")
    """
    
    def __init__(self, mission_id: str, blackboard: "Blackboard"):
        self.mission_id = mission_id
        self.blackboard = blackboard
        self._risk_history: List[RiskAssessment] = []
    
    async def _calculate_detection_risk(self) -> float:
        """
        Calculate detection risk based on recent mission actions.
        
        Returns:
            Detection risk score (0.0-1.0)
        """
        base_risk = 0.3  # Baseline detection risk
        
        # Get recent events from blackboard stream
        try:
            # Read last 50 events from mission events stream
            events_key = f"mission:{self.mission_id}:events"
            events = await self.blackboard.redis.xrevrange(
                events_key,
                count=50
            )
            
            action_count = 0
            noisy_actions = 0
            detection_alerts = 0
            
            for event_id, event_data in events:
                # event_data is dict with string keys (not bytes)
                event_type = event_data.get("type", "")
                
                if event_type == "action_taken":
                    action_count += 1
                    # Parse event data
                    import json
                    data_str = event_data.get("data", "{}")
                    data = json.loads(data_str)
                    
                    # Check if action was noisy (low stealth)
                    stealth = data.get("stealth", "medium")
                    if stealth == "low":
                        noisy_actions += 1
                
                elif event_type == "detection_alert":
                    # Detection alerts significantly increase risk
                    detection_alerts += 1
                    import json
                    data_str = event_data.get("data", "{}")
                    data = json.loads(data_str)
                    
                    # Higher severity = more risk
                    severity = data.get("severity", "low")
                    if severity in ["high", "critical"]:
                        detection_alerts += 1  # Count critical alerts twice
            
            # Increase risk based on activity
            activity_risk = min(action_count * 0.1, 0.5)
            noise_risk = min(noisy_actions * 0.3, 0.5)
            detection_risk = min(detection_alerts * 0.4, 0.6)  # Detection alerts = major risk increase
            
            total_risk = min(base_risk + activity_risk + noise_risk + detection_risk, 1.0)
            
            return total_risk
            
        except Exception as e:
            # Fallback if events not available
            return base_risk
    
    async def assess_current_risk(self) -> RiskAssessment:
        """
        Perform comprehensive risk assessment for current mission state.
        
        Returns:
            RiskAssessment object with overall risk and factors
        """
        # Get current mission data
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        # vulns = await self.blackboard.get_mission_vulns(self.mission_id)
        
        # Calculate risk factors
        factors = []
        
        # Factor 1: Target count (more targets = higher risk)
        target_count_risk = min(len(targets) / 10.0, 1.0)
        factors.append(RiskFactor(
            name="target_exposure",
            value=target_count_risk,
            weight=0.3,
            description=f"{len(targets)} targets in scope"
        ))
        
        # Factor 2: Detection probability (check recent actions)
        detection_risk = await self._calculate_detection_risk()
        factors.append(RiskFactor(
            name="detection_probability",
            value=detection_risk,
            weight=0.4,
            description="Estimated detection risk",
            category="detection"
        ))
        
        # Factor 3: Mission complexity
        complexity_risk = 0.6
        factors.append(RiskFactor(
            name="mission_complexity",
            value=complexity_risk,
            weight=0.3,
            description="Overall mission complexity"
        ))
        
        # Calculate weighted risk score
        risk_score = sum(f.value * f.weight for f in factors)
        
        # Determine risk level
        if risk_score >= 0.8:
            level = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            level = RiskLevel.HIGH
        elif risk_score >= 0.4:
            level = RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.MINIMAL
        
        # Generate recommendations
        recommendations = []
        if risk_score >= 0.6:
            recommendations.append("Consider reducing attack surface")
            recommendations.append("Implement additional stealth measures")
        if len(targets) > 5:
            recommendations.append("Prioritize high-value targets")
        
        assessment = RiskAssessment(
            overall_risk=level,
            risk_score=risk_score,
            factors=factors,
            recommendations=recommendations
        )
        
        self._risk_history.append(assessment)
        return assessment
    
    async def assess_mission_risk(self) -> Dict[str, Any]:
        """
        Perform mission risk assessment (dict format for test compatibility).
        
        Returns:
            Dictionary with risk assessment details
        """
        assessment = await self.assess_current_risk()
        
        return {
            "overall_risk": assessment.overall_risk.value,
            "risk_score": round(assessment.risk_score * 100, 1),  # Convert to 0-100
            "risk_factors": [
                {
                    "name": f.name,
                    "value": f.value,
                    "weight": f.weight,
                    "description": f.description,
                    "category": f.category
                }
                for f in assessment.factors
            ],
            "recommendations": assessment.recommendations,
            "timestamp": assessment.timestamp.isoformat()
        }
    
    async def monitor_risk_changes(self, interval_seconds: int = 30) -> None:
        """
        Continuously monitor risk changes.
        
        Args:
            interval_seconds: Check interval in seconds
        """
        while True:
            assessment = await self.assess_current_risk()
            
            # Check for significant risk increases
            if len(self._risk_history) > 1:
                prev = self._risk_history[-2]
                if assessment.risk_score > prev.risk_score + 0.2:
                    # Risk increased significantly
                    await self.blackboard.add_event(
                        mission_id=self.mission_id,
                        event_type="risk_alert",
                        data={
                            "previous_score": prev.risk_score,
                            "current_score": assessment.risk_score,
                            "level": assessment.overall_risk.value
                        }
                    )
            
            await asyncio.sleep(interval_seconds)
    
    async def get_risk_history(self) -> List[RiskAssessment]:
        """Get historical risk assessments"""
        return self._risk_history.copy()
    
    async def assess_action_risk(
        self,
        action_type: str,
        target_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Assess risk for a specific action.
        
        Args:
            action_type: Type of action (port_scan, exploit, lateral_movement, etc.)
            target_id: Target system ID
            **kwargs: Additional action parameters
            
        Returns:
            Dictionary with action risk assessment
        """
        # Risk scores for different action types (0-100 scale)
        base_risk_scores = {
            "passive_dns_query": 10,  # Very low risk, passive recon
            "port_scan": 30,          # Low risk, passive
            "service_enum": 35,       # Low-medium risk
            "vulnerability_scan": 45, # Medium risk
            "exploit": 75,            # High risk, active
            "exploit_execution": 85,  # Very high risk, active exploitation
            "lateral_movement": 85,   # Very high risk
            "privilege_escalation": 80,  # High risk
            "data_exfiltration": 90,  # Very high risk
            "persistence": 70,        # High risk
            "cleanup": 20             # Low risk
        }
        
        # Get base risk for action type
        base_score = base_risk_scores.get(action_type.lower(), 50)
        
        # Adjust based on current mission risk
        mission_risk = await self.assess_current_risk()
        risk_multiplier = 1.0 + (mission_risk.risk_score * 0.5)  # Up to 1.5x multiplier
        
        # Adjust based on target characteristics (if available)
        target_data = await self.blackboard.get_target(target_id)
        if target_data:
            # Higher value targets = higher risk
            target_value = target_data.get("params", {}).get("target_value", 50)
            if target_value > 80:
                risk_multiplier *= 1.2
        
        # Calculate final risk score
        final_score = min(base_score * risk_multiplier, 100)
        
        # Determine risk level
        if final_score >= 80:
            risk_level = "critical"
        elif final_score >= 60:
            risk_level = "high"
        elif final_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "action_type": action_type,
            "target_id": target_id,
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "base_score": base_score,
            "risk_multiplier": round(risk_multiplier, 2),
            "mission_risk": mission_risk.overall_risk.value,
            "recommended": final_score < 70  # Recommend if below threshold
        }
    
    async def should_proceed_with_action(
        self, 
        action_type: str, 
        risk_threshold: float = 0.7
    ) -> bool:
        """
        Determine if action should proceed based on current risk.
        
        Args:
            action_type: Type of action (exploit, scan, etc.)
            risk_threshold: Maximum acceptable risk (0.0-1.0)
            
        Returns:
            True if action should proceed, False if too risky
        """
        assessment = await self.assess_current_risk()
        
        # Check if current risk exceeds threshold
        if assessment.risk_score > risk_threshold:
            return False
        
        # Action-specific checks
        if action_type == "exploit" and assessment.risk_score > 0.5:
            return False
        
        return True
    
    async def get_risk_mitigation_recommendations(self) -> List[str]:
        """
        Get recommendations to mitigate current mission risks.
        
        Returns:
            List of mitigation recommendation strings
        """
        assessment = await self.assess_current_risk()
        recommendations = []
        
        # Check detection risk
        detection_factors = [f for f in assessment.factors if f.category == "detection"]
        if detection_factors and detection_factors[0].value > 0.6:
            recommendations.extend([
                "Increase stealth level for all operations",
                "Reduce scan speeds to avoid detection",
                "Use encrypted communication channels",
                "Implement anti-forensics measures"
            ])
        
        # Check operational risk
        if assessment.risk_score > 0.7:
            recommendations.extend([
                "Review mission scope and reduce attack surface",
                "Consolidate operations to fewer targets",
                "Implement additional operational security measures"
            ])
        
        # Check target exposure
        target_factors = [f for f in assessment.factors if "target" in f.name.lower()]
        if target_factors and target_factors[0].value > 0.7:
            recommendations.extend([
                "Prioritize high-value targets to reduce exposure time",
                "Implement target grouping strategies"
            ])
        
        # General recommendations if risk is elevated
        if assessment.risk_score > 0.5:
            recommendations.extend([
                "Consider pausing operations during high-risk periods",
                "Enhance monitoring and alerting mechanisms"
            ])
        
        return recommendations if recommendations else ["Current risk level acceptable - continue operations"]
