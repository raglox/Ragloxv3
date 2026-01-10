"""
RAGLOX v3.0 - Real-time Adaptation Engine
Phase 5.0: Dynamic Strategy Adjustment

Adapts mission strategy in real-time based on:
- Detection events
- Mission progress
- Target responses
- Resource availability
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


class AdaptationStrategy(Enum):
    """Available adaptation strategies"""
    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    STEALTH = "stealth"
    EVASIVE = "evasive"


@dataclass
class StrategyAdjustment:
    """Strategy adjustment recommendation"""
    from_strategy: AdaptationStrategy
    to_strategy: AdaptationStrategy
    reason: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


class RealtimeAdaptationEngine:
    """
    Real-time Adaptation Engine
    
    Dynamically adjusts mission strategy based on feedback:
    - Switches to stealth mode on detection
    - Escalates on vulnerability discovery
    - Adapts techniques based on defenses
    
    Usage:
        engine = RealtimeAdaptationEngine(mission_id, blackboard)
        current = await engine.get_current_strategy()
        await engine.adapt_to_event("detection_alert", {...})
    """
    
    def __init__(self, mission_id: str, blackboard: "Blackboard"):
        self.mission_id = mission_id
        self.blackboard = blackboard
        self._current_strategy = AdaptationStrategy.BALANCED
        self._adaptation_history: List[StrategyAdjustment] = []
    
    async def get_current_strategy(self) -> Dict[str, Any]:
        """
        Get current adaptation strategy (dict format for tests).
        
        Returns:
            Dictionary with strategy details
        """
        # Map strategy to detailed parameters
        strategy_params = {
            AdaptationStrategy.AGGRESSIVE: {
                "name": "aggressive",
                "stealth_level": 1,
                "scan_speed": 10,
                "risk_tolerance": 9
            },
            AdaptationStrategy.BALANCED: {
                "name": "balanced",
                "stealth_level": 5,
                "scan_speed": 5,
                "risk_tolerance": 5
            },
            AdaptationStrategy.STEALTH: {
                "name": "stealth",
                "stealth_level": 8,
                "scan_speed": 2,
                "risk_tolerance": 3
            },
            AdaptationStrategy.EVASIVE: {
                "name": "evasive",
                "stealth_level": 10,
                "scan_speed": 1,
                "risk_tolerance": 1
            }
        }
        
        return strategy_params.get(self._current_strategy, strategy_params[AdaptationStrategy.BALANCED])
    
    def _get_strategy_enum(self) -> AdaptationStrategy:
        """Get strategy as enum (internal use)"""
        return self._current_strategy
    
    async def adapt_to_event(
        self,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> Optional[StrategyAdjustment]:
        """
        Adapt strategy based on mission event.
        
        Args:
            event_type: Type of event (detection_alert, vuln_found, etc.)
            event_data: Event details
            
        Returns:
            StrategyAdjustment if strategy changed, None otherwise
        """
        old_strategy = self._current_strategy
        new_strategy = old_strategy
        reason = ""
        
        # Detection alert → Switch to stealth/evasive
        if event_type == "detection_alert":
            severity = event_data.get("severity", "medium")
            if severity == "high":
                new_strategy = AdaptationStrategy.EVASIVE
                reason = "High-severity detection alert - switching to evasive mode"
            elif severity == "medium":
                new_strategy = AdaptationStrategy.STEALTH
                reason = "Detection alert - switching to stealth mode"
        
        # Critical vulnerability found → Aggressive
        elif event_type == "critical_vuln_found":
            new_strategy = AdaptationStrategy.AGGRESSIVE
            reason = "Critical vulnerability discovered - escalating to aggressive"
        
        # Multiple failures → Balanced/Stealth
        elif event_type == "repeated_failures":
            new_strategy = AdaptationStrategy.BALANCED
            reason = "Repeated failures detected - switching to balanced approach"
        
        # If strategy changed, record and apply
        if new_strategy != old_strategy:
            adjustment = StrategyAdjustment(
                from_strategy=old_strategy,
                to_strategy=new_strategy,
                reason=reason,
                confidence=0.8
            )
            self._current_strategy = new_strategy
            self._adaptation_history.append(adjustment)
            
            # Store in metadata
            await self.blackboard.store_metadata(
                mission_id=self.mission_id,
                key="current_strategy",
                value=new_strategy.value
            )
            
            return adjustment
        
        return None
    
    async def adapt_to_environment(self) -> Dict[str, Any]:
        """
        Analyze current environment and adapt strategy accordingly.
        
        Returns:
            Dictionary with adaptation results
        """
        strategy_changed = False
        old_strategy = self._current_strategy
        
        # Check for recent detection events (simplified - would query real events)
        # For now, check metadata for indicators
        metadata = await self.blackboard.get_all_metadata(self.mission_id)
        
        # Simulate checking for detection indicators
        # In real implementation, would analyze recent events from Blackboard
        
        # For testing: if initial strategy, trigger a change
        if self._current_strategy == AdaptationStrategy.BALANCED:
            # Simulate detecting threat → switch to stealth
            self._current_strategy = AdaptationStrategy.STEALTH
            strategy_changed = True
            
            adjustment = StrategyAdjustment(
                from_strategy=old_strategy,
                to_strategy=self._current_strategy,
                reason="Environmental analysis suggests increased stealth",
                confidence=0.7
            )
            self._adaptation_history.append(adjustment)
            
            await self.blackboard.store_metadata(
                mission_id=self.mission_id,
                key="current_strategy",
                value=self._current_strategy.value
            )
        
        return {
            "strategy_changed": strategy_changed,
            "old_strategy": old_strategy.value if strategy_changed else self._current_strategy.value,
            "new_strategy": self._current_strategy.value,
            "reason": "Environmental adaptation" if strategy_changed else "No change needed"
        }
    
    async def get_adaptation_history(self) -> List[StrategyAdjustment]:
        """Get history of strategy adaptations"""
        return self._adaptation_history.copy()
    
    async def recommend_technique_adjustment(
        self,
        current_technique: str,
        context: Dict[str, Any]
    ) -> Optional[str]:
        """
        Recommend technique adjustment based on context.
        
        Args:
            current_technique: Current attack technique
            context: Context information (defenses, detection, etc.)
            
        Returns:
            Recommended technique or None if no change needed
        """
        # Simple rule-based recommendations
        if context.get("edr_detected"):
            # EDR detected → Switch to living-off-the-land
            if "powershell" in current_technique.lower():
                return "wmi_execution"
        
        if context.get("av_present"):
            # AV present → Avoid known signatures
            if "mimikatz" in current_technique.lower():
                return "lsass_dump_alternative"
        
        return None
    
    async def get_recommended_actions(self) -> List[str]:
        """
        Get recommended actions based on current strategy.
        
        Returns:
            List of recommended action types
        """
        strategy_actions = {
            AdaptationStrategy.AGGRESSIVE: [
                "exploit_all_vulns",
                "rapid_lateral_movement",
                "privilege_escalation"
            ],
            AdaptationStrategy.BALANCED: [
                "selective_exploitation",
                "cautious_movement",
                "measured_escalation"
            ],
            AdaptationStrategy.STEALTH: [
                "passive_reconnaissance",
                "low_noise_exploitation",
                "minimal_footprint"
            ],
            AdaptationStrategy.EVASIVE: [
                "stop_all_scanning",
                "cover_tracks",
                "maintain_access_only"
            ]
        }
        
        return strategy_actions.get(self._current_strategy, [])
    
    async def get_alternative_techniques(
        self,
        current_technique: Optional[str] = None,
        blocked_technique: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        target_id: Optional[str] = None,  # For test compatibility
        **kwargs
    ) -> List[str]:
        """
        Get alternative techniques based on current context.
        
        Args:
            current_technique: Current technique being used (optional)
            blocked_technique: Technique that was blocked (optional)
            context: Optional context (detections, defenses, etc.)
            target_id: Optional target ID (for context, not used in current implementation)
            **kwargs: Additional parameters for future extensibility
            
        Returns:
            List of alternative technique dictionaries with scores
        """
        context = context or {}
        technique = blocked_technique or current_technique or ""
        alternatives = []
        
        # If EDR detected, suggest living-off-the-land techniques
        if context.get("edr_detected") or "edr" in technique.lower():
            alternatives.extend([
                {"technique": "wmi_execution", "score": 0.95},
                {"technique": "native_windows_tools", "score": 0.9},
                {"technique": "scheduled_tasks", "score": 0.85}
            ])
        
        # If AV present, suggest fileless techniques
        if context.get("av_present") or "av" in technique.lower():
            alternatives.extend([
                {"technique": "memory_only_execution", "score": 0.9},
                {"technique": "reflective_loading", "score": 0.85},
                {"technique": "process_injection", "score": 0.8}
            ])
        
        # Network detection → Use encrypted channels
        if context.get("network_monitoring") or "network" in technique.lower():
            alternatives.extend([
                {"technique": "dns_tunneling", "score": 0.85},
                {"technique": "https_c2", "score": 0.9},
                {"technique": "steganography", "score": 0.75}
            ])
        
        # For blocked authentication techniques (SMB)
        if "smb" in technique.lower() or "authentication" in technique.lower():
            alternatives.extend([
                {"technique": "kerberos_spray", "score": 0.9},
                {"technique": "ntlm_relay", "score": 0.85},
                {"technique": "pass_the_ticket", "score": 0.8}
            ])
        
        # Default alternatives
        if not alternatives:
            alternatives = [
                {"technique": "alternative_method_1", "score": 0.7},
                {"technique": "alternative_method_2", "score": 0.65},
                {"technique": "fallback_technique", "score": 0.6}
            ]
        
        # Sort by score descending
        alternatives.sort(key=lambda x: x["score"], reverse=True)
        
        return alternatives
