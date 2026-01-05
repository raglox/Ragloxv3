"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Defense Intelligence System
═══════════════════════════════════════════════════════════════════════════════

Advanced defense detection and evasion system that automatically identifies
security controls and suggests appropriate evasion techniques.

Features:
- Real-time defense detection
- Automatic evasion technique selection
- Defense correlation analysis
- Adaptive evasion strategies
- Success rate tracking

Author: RAGLOX Team
Version: 3.0.0
"""

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("raglox.intelligence.defense")


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

class DefenseType(Enum):
    """Types of defenses."""
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    ANTIVIRUS = "antivirus"
    EDR = "edr"
    WAF = "waf"
    DLP = "dlp"
    SANDBOX = "sandbox"
    BEHAVIORAL = "behavioral"
    NETWORK_MONITORING = "network_monitoring"
    APPLICATION_CONTROL = "application_control"


class EvasionPriority(Enum):
    """Evasion technique priority levels."""
    CRITICAL = "critical"  # Must use immediately
    HIGH = "high"          # Strongly recommended
    MEDIUM = "medium"      # Consider using
    LOW = "low"            # Optional optimization


@dataclass
class DefenseSignature:
    """Signature of a defense mechanism."""
    defense_type: DefenseType
    indicators: List[str]  # Error messages, behaviors
    confidence_threshold: float = 0.7


@dataclass
class DetectedDefense:
    """A detected defense mechanism."""
    defense_type: DefenseType
    confidence: float  # 0-1
    evidence: List[str]  # What indicated this defense
    timestamp: float
    target_id: str
    impact: str  # high, medium, low
    bypass_difficulty: str  # easy, medium, hard, very_hard


@dataclass
class EvasionTechnique:
    """An evasion technique."""
    technique_id: str
    name: str
    description: str
    applicable_defenses: List[DefenseType]
    priority: EvasionPriority
    parameters: Dict[str, Any]
    success_rate: float = 0.5  # Historical success rate
    detection_risk: float = 0.3  # Risk of being detected (0-1)
    complexity: str = "medium"  # easy, medium, hard


@dataclass
class EvasionPlan:
    """A complete evasion plan."""
    plan_id: str
    target_defenses: List[DefenseType]
    techniques: List[EvasionTechnique]
    estimated_success_rate: float
    estimated_detection_risk: float
    execution_order: List[str]  # technique_ids in order
    fallback_plan: Optional['EvasionPlan'] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Defense Intelligence System
# ═══════════════════════════════════════════════════════════════════════════════

class DefenseIntelligence:
    """
    Advanced defense detection and evasion system.
    
    Core Capabilities:
    1. **Real-time Detection**: Identifies defenses from operation results
    2. **Signature Matching**: Uses patterns to detect specific defense products
    3. **Behavior Analysis**: Analyzes operation behavior to infer defenses
    4. **Evasion Selection**: Automatically selects appropriate evasion techniques
    5. **Adaptive Strategies**: Learns which evasions work best over time
    
    Detection Methods:
    - Error message analysis
    - Network behavior analysis
    - Timing analysis (rate limiting, delays)
    - Response pattern analysis
    """
    
    def __init__(self):
        """Initialize defense intelligence system."""
        # Defense signatures
        self.signatures = self._load_defense_signatures()
        
        # Evasion techniques catalog
        self.evasion_catalog = self._load_evasion_catalog()
        
        # Detection history
        self.detected_defenses: Dict[str, List[DetectedDefense]] = defaultdict(list)
        
        # Evasion success tracking
        self.evasion_success_rates: Dict[str, Dict[str, float]] = defaultdict(dict)
        
        logger.info("DefenseIntelligence initialized with "
                   f"{len(self.signatures)} signatures, "
                   f"{len(self.evasion_catalog)} evasion techniques")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Defense Detection Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def detect_defenses(
        self,
        target_id: str,
        operation_result: Dict[str, Any],
        execution_logs: List[Dict[str, Any]]
    ) -> List[DetectedDefense]:
        """
        Detect defense mechanisms from operation results.
        
        Args:
            target_id: Target identifier
            operation_result: Result of the operation
            execution_logs: Execution logs
            
        Returns:
            List of detected defenses
        """
        detected = []
        
        # Analyze error messages
        error_based = self._detect_from_errors(operation_result, execution_logs)
        detected.extend(error_based)
        
        # Analyze network behavior
        network_based = self._detect_from_network_behavior(operation_result)
        detected.extend(network_based)
        
        # Analyze timing patterns
        timing_based = self._detect_from_timing(operation_result, execution_logs)
        detected.extend(timing_based)
        
        # Analyze response patterns
        response_based = self._detect_from_responses(operation_result)
        detected.extend(response_based)
        
        # Store detections
        for defense in detected:
            defense.target_id = target_id
            defense.timestamp = time.time()
            self.detected_defenses[target_id].append(defense)
        
        if detected:
            logger.info(f"Detected {len(detected)} defenses on target {target_id}: "
                       f"{[d.defense_type.value for d in detected]}")
        
        return detected
    
    def _detect_from_errors(
        self,
        result: Dict[str, Any],
        logs: List[Dict[str, Any]]
    ) -> List[DetectedDefense]:
        """Detect defenses from error messages."""
        detected = []
        
        # Collect all text to analyze
        text_sources = []
        if result.get("error_message"):
            text_sources.append(result["error_message"])
        if result.get("stderr"):
            text_sources.append(result["stderr"])
        for log in logs:
            if log.get("message"):
                text_sources.append(log["message"])
        
        combined_text = " ".join(text_sources).lower()
        
        # Match against signatures
        for signature in self.signatures:
            matching_indicators = []
            for indicator in signature.indicators:
                if indicator.lower() in combined_text:
                    matching_indicators.append(indicator)
            
            if matching_indicators:
                confidence = len(matching_indicators) / len(signature.indicators)
                
                if confidence >= signature.confidence_threshold:
                    detected.append(DetectedDefense(
                        defense_type=signature.defense_type,
                        confidence=confidence,
                        evidence=matching_indicators,
                        timestamp=time.time(),
                        target_id="",  # Will be set by caller
                        impact=self._assess_impact(signature.defense_type),
                        bypass_difficulty=self._assess_difficulty(signature.defense_type)
                    ))
        
        return detected
    
    def _detect_from_network_behavior(
        self,
        result: Dict[str, Any]
    ) -> List[DetectedDefense]:
        """Detect defenses from network behavior."""
        detected = []
        
        # Check for port filtering
        if result.get("ports_filtered", 0) > result.get("ports_open", 0):
            detected.append(DetectedDefense(
                defense_type=DefenseType.FIREWALL,
                confidence=0.8,
                evidence=["High ratio of filtered ports"],
                timestamp=time.time(),
                target_id="",
                impact="high",
                bypass_difficulty="medium"
            ))
        
        # Check for connection patterns
        if result.get("connection_refused") or "refused" in str(result.get("error_message", "")).lower():
            detected.append(DetectedDefense(
                defense_type=DefenseType.FIREWALL,
                confidence=0.7,
                evidence=["Connection refused"],
                timestamp=time.time(),
                target_id="",
                impact="high",
                bypass_difficulty="medium"
            ))
        
        return detected
    
    def _detect_from_timing(
        self,
        result: Dict[str, Any],
        logs: List[Dict[str, Any]]
    ) -> List[DetectedDefense]:
        """Detect defenses from timing patterns."""
        detected = []
        
        # Check for rate limiting
        if "rate limit" in str(result.get("error_message", "")).lower():
            detected.append(DetectedDefense(
                defense_type=DefenseType.IDS_IPS,
                confidence=0.9,
                evidence=["Rate limiting detected"],
                timestamp=time.time(),
                target_id="",
                impact="medium",
                bypass_difficulty="easy"
            ))
        
        # Check for abnormal delays
        if result.get("duration_ms", 0) > 30000:  # > 30 seconds
            detected.append(DetectedDefense(
                defense_type=DefenseType.SANDBOX,
                confidence=0.6,
                evidence=["Unusual execution delay"],
                timestamp=time.time(),
                target_id="",
                impact="low",
                bypass_difficulty="medium"
            ))
        
        return detected
    
    def _detect_from_responses(
        self,
        result: Dict[str, Any]
    ) -> List[DetectedDefense]:
        """Detect defenses from HTTP/application responses."""
        detected = []
        
        # Check for WAF signatures
        if result.get("http_status") in [403, 406, 429]:
            headers = result.get("headers", {})
            waf_indicators = ["cloudflare", "akamai", "imperva", "modsecurity"]
            
            for key, value in headers.items():
                if any(ind in str(value).lower() for ind in waf_indicators):
                    detected.append(DetectedDefense(
                        defense_type=DefenseType.WAF,
                        confidence=0.85,
                        evidence=[f"WAF header: {key}"],
                        timestamp=time.time(),
                        target_id="",
                        impact="high",
                        bypass_difficulty="hard"
                    ))
                    break
        
        return detected
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Evasion Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def suggest_evasion_techniques(
        self,
        detected_defenses: List[DetectedDefense],
        operation_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[EvasionTechnique]:
        """
        Suggest evasion techniques for detected defenses.
        
        Args:
            detected_defenses: List of detected defenses
            operation_type: Type of operation (scan, exploit, etc.)
            context: Additional context
            
        Returns:
            Ordered list of recommended evasion techniques
        """
        if not detected_defenses:
            return []
        
        # Get applicable techniques
        applicable_techniques = []
        defense_types = set(d.defense_type for d in detected_defenses)
        
        for technique in self.evasion_catalog:
            # Check if technique applies to any detected defense
            if any(dt in technique.applicable_defenses for dt in defense_types):
                # Adjust success rate based on history
                technique_copy = EvasionTechnique(**asdict(technique))
                technique_copy.success_rate = self._get_adjusted_success_rate(
                    technique.technique_id,
                    defense_types
                )
                applicable_techniques.append(technique_copy)
        
        # Sort by priority and success rate
        applicable_techniques.sort(
            key=lambda t: (
                ["critical", "high", "medium", "low"].index(t.priority.value),
                -t.success_rate,
                t.detection_risk
            )
        )
        
        # Apply context filters
        if context:
            applicable_techniques = self._filter_by_context(
                applicable_techniques,
                context
            )
        
        logger.info(f"Suggested {len(applicable_techniques)} evasion techniques "
                   f"for {len(defense_types)} defenses")
        
        return applicable_techniques
    
    def create_evasion_plan(
        self,
        detected_defenses: List[DetectedDefense],
        operation_type: str,
        max_techniques: int = 5
    ) -> EvasionPlan:
        """
        Create a comprehensive evasion plan.
        
        Args:
            detected_defenses: Detected defenses
            operation_type: Operation type
            max_techniques: Maximum techniques to include
            
        Returns:
            Complete evasion plan
        """
        techniques = self.suggest_evasion_techniques(
            detected_defenses,
            operation_type
        )
        
        # Select top techniques
        selected = techniques[:max_techniques]
        
        # Determine execution order (critical first)
        execution_order = [
            t.technique_id for t in sorted(
                selected,
                key=lambda t: ["critical", "high", "medium", "low"].index(t.priority.value)
            )
        ]
        
        # Calculate estimated success rate
        if selected:
            # Combined probability: 1 - product of failure probabilities
            failure_prob = 1.0
            for t in selected:
                failure_prob *= (1 - t.success_rate)
            estimated_success = 1 - failure_prob
        else:
            estimated_success = 0.0
        
        # Calculate detection risk
        estimated_risk = max(
            (t.detection_risk for t in selected),
            default=0.0
        )
        
        plan = EvasionPlan(
            plan_id=f"plan_{int(time.time())}",
            target_defenses=[d.defense_type for d in detected_defenses],
            techniques=selected,
            estimated_success_rate=estimated_success,
            estimated_detection_risk=estimated_risk,
            execution_order=execution_order
        )
        
        logger.info(f"Created evasion plan {plan.plan_id} with "
                   f"{len(selected)} techniques "
                   f"(success rate: {estimated_success:.1%})")
        
        return plan
    
    def record_evasion_result(
        self,
        technique_id: str,
        defense_type: DefenseType,
        success: bool
    ) -> None:
        """
        Record the result of an evasion attempt.
        
        Args:
            technique_id: Evasion technique used
            defense_type: Defense it was used against
            success: Whether it succeeded
        """
        key = f"{technique_id}:{defense_type.value}"
        
        if key not in self.evasion_success_rates:
            self.evasion_success_rates[technique_id][defense_type.value] = []
        
        # Store result (1 for success, 0 for failure)
        self.evasion_success_rates[technique_id][defense_type.value] = success
        
        # Update technique in catalog
        for technique in self.evasion_catalog:
            if technique.technique_id == technique_id:
                # Simple moving average
                old_rate = technique.success_rate
                technique.success_rate = (old_rate * 0.8) + (1.0 if success else 0.0) * 0.2
                break
        
        logger.debug(f"Recorded evasion result: {technique_id} vs {defense_type.value} = {success}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Analysis Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_target_defense_profile(self, target_id: str) -> Dict[str, Any]:
        """Get defense profile for a target."""
        detections = self.detected_defenses.get(target_id, [])
        
        if not detections:
            return {
                "target_id": target_id,
                "defenses": [],
                "risk_level": "unknown"
            }
        
        # Count defense types
        defense_counts = defaultdict(int)
        for detection in detections:
            defense_counts[detection.defense_type.value] += 1
        
        # Assess risk level
        risk_level = "low"
        if len(defense_counts) > 3:
            risk_level = "very_high"
        elif len(defense_counts) > 2:
            risk_level = "high"
        elif len(defense_counts) > 1:
            risk_level = "medium"
        
        return {
            "target_id": target_id,
            "defenses": dict(defense_counts),
            "total_detections": len(detections),
            "risk_level": risk_level,
            "last_detection": max(d.timestamp for d in detections) if detections else None
        }
    
    def get_evasion_statistics(self) -> Dict[str, Any]:
        """Get evasion technique statistics."""
        stats = {
            "total_techniques": len(self.evasion_catalog),
            "by_priority": defaultdict(int),
            "top_performers": [],
            "avg_success_rate": 0.0
        }
        
        # Count by priority
        for technique in self.evasion_catalog:
            stats["by_priority"][technique.priority.value] += 1
        
        # Top performers
        sorted_techniques = sorted(
            self.evasion_catalog,
            key=lambda t: t.success_rate,
            reverse=True
        )
        stats["top_performers"] = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "success_rate": t.success_rate,
                "detection_risk": t.detection_risk
            }
            for t in sorted_techniques[:10]
        ]
        
        # Average success rate
        if self.evasion_catalog:
            stats["avg_success_rate"] = sum(
                t.success_rate for t in self.evasion_catalog
            ) / len(self.evasion_catalog)
        
        return stats
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _get_adjusted_success_rate(
        self,
        technique_id: str,
        defense_types: Set[DefenseType]
    ) -> float:
        """Get adjusted success rate based on historical data."""
        # Find base rate
        base_rate = 0.5
        for technique in self.evasion_catalog:
            if technique.technique_id == technique_id:
                base_rate = technique.success_rate
                break
        
        # Adjust based on specific defense history
        if technique_id in self.evasion_success_rates:
            relevant_rates = []
            for defense_type in defense_types:
                if defense_type.value in self.evasion_success_rates[technique_id]:
                    relevant_rates.append(
                        self.evasion_success_rates[technique_id][defense_type.value]
                    )
            
            if relevant_rates:
                # Weighted average: 70% historical, 30% base
                historical_rate = sum(relevant_rates) / len(relevant_rates)
                return base_rate * 0.3 + historical_rate * 0.7
        
        return base_rate
    
    def _filter_by_context(
        self,
        techniques: List[EvasionTechnique],
        context: Dict[str, Any]
    ) -> List[EvasionTechnique]:
        """Filter techniques by context requirements."""
        filtered = []
        
        for technique in techniques:
            # Check stealth requirements
            if context.get("stealth_required") and technique.detection_risk > 0.5:
                continue  # Skip high-risk techniques
            
            # Check complexity constraints
            if context.get("max_complexity") == "easy" and technique.complexity == "hard":
                continue
            
            filtered.append(technique)
        
        return filtered
    
    def _assess_impact(self, defense_type: DefenseType) -> str:
        """Assess impact level of a defense."""
        high_impact = [DefenseType.FIREWALL, DefenseType.EDR, DefenseType.WAF]
        medium_impact = [DefenseType.IDS_IPS, DefenseType.ANTIVIRUS]
        
        if defense_type in high_impact:
            return "high"
        elif defense_type in medium_impact:
            return "medium"
        else:
            return "low"
    
    def _assess_difficulty(self, defense_type: DefenseType) -> str:
        """Assess bypass difficulty."""
        very_hard = [DefenseType.EDR, DefenseType.BEHAVIORAL]
        hard = [DefenseType.WAF, DefenseType.SANDBOX]
        medium = [DefenseType.FIREWALL, DefenseType.IDS_IPS]
        
        if defense_type in very_hard:
            return "very_hard"
        elif defense_type in hard:
            return "hard"
        elif defense_type in medium:
            return "medium"
        else:
            return "easy"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Data Loading Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _load_defense_signatures(self) -> List[DefenseSignature]:
        """Load defense detection signatures."""
        return [
            # Firewall signatures
            DefenseSignature(
                defense_type=DefenseType.FIREWALL,
                indicators=[
                    "connection refused",
                    "host unreachable",
                    "no route to host",
                    "network unreachable",
                    "filtered",
                    "firewall"
                ],
                confidence_threshold=0.6
            ),
            
            # IDS/IPS signatures
            DefenseSignature(
                defense_type=DefenseType.IDS_IPS,
                indicators=[
                    "rate limit",
                    "too many requests",
                    "blocked by policy",
                    "suspicious activity",
                    "intrusion",
                    "snort",
                    "suricata"
                ],
                confidence_threshold=0.7
            ),
            
            # Antivirus signatures
            DefenseSignature(
                defense_type=DefenseType.ANTIVIRUS,
                indicators=[
                    "virus",
                    "malware",
                    "trojan",
                    "quarantine",
                    "windows defender",
                    "access is denied",
                    "operation did not complete successfully because the file contains a virus"
                ],
                confidence_threshold=0.7
            ),
            
            # EDR signatures
            DefenseSignature(
                defense_type=DefenseType.EDR,
                indicators=[
                    "crowdstrike",
                    "carbon black",
                    "sentinel",
                    "cortex",
                    "edr",
                    "endpoint detection"
                ],
                confidence_threshold=0.8
            ),
            
            # WAF signatures
            DefenseSignature(
                defense_type=DefenseType.WAF,
                indicators=[
                    "mod_security",
                    "cloudflare",
                    "imperva",
                    "akamai",
                    "blocked for security reasons",
                    "request forbidden by administrative rules"
                ],
                confidence_threshold=0.7
            ),
        ]
    
    def _load_evasion_catalog(self) -> List[EvasionTechnique]:
        """Load evasion techniques catalog."""
        return [
            # Network evasion
            EvasionTechnique(
                technique_id="evade_fw_fragment",
                name="IP Fragmentation",
                description="Fragment packets to evade firewall inspection",
                applicable_defenses=[DefenseType.FIREWALL],
                priority=EvasionPriority.HIGH,
                parameters={"fragment_size": 16, "fragment_overlap": False},
                success_rate=0.7,
                detection_risk=0.3,
                complexity="easy"
            ),
            
            EvasionTechnique(
                technique_id="evade_fw_source_port",
                name="Source Port Manipulation",
                description="Use common source ports (53, 80) to bypass firewall",
                applicable_defenses=[DefenseType.FIREWALL],
                priority=EvasionPriority.MEDIUM,
                parameters={"source_port": 53},
                success_rate=0.6,
                detection_risk=0.2,
                complexity="easy"
            ),
            
            EvasionTechnique(
                technique_id="evade_fw_decoy",
                name="Decoy Scanning",
                description="Use decoy IPs to mask real source",
                applicable_defenses=[DefenseType.FIREWALL, DefenseType.IDS_IPS],
                priority=EvasionPriority.MEDIUM,
                parameters={"num_decoys": 5},
                success_rate=0.5,
                detection_risk=0.4,
                complexity="medium"
            ),
            
            # Timing evasion
            EvasionTechnique(
                technique_id="evade_ids_timing",
                name="Timing Randomization",
                description="Randomize packet timing to evade IDS",
                applicable_defenses=[DefenseType.IDS_IPS],
                priority=EvasionPriority.HIGH,
                parameters={"timing": "T2", "delay_range": [100, 500]},
                success_rate=0.75,
                detection_risk=0.1,
                complexity="easy"
            ),
            
            EvasionTechnique(
                technique_id="evade_ids_rate_limit",
                name="Rate Limiting",
                description="Reduce request rate to stay under IDS threshold",
                applicable_defenses=[DefenseType.IDS_IPS],
                priority=EvasionPriority.CRITICAL,
                parameters={"max_rate": "10/minute"},
                success_rate=0.9,
                detection_risk=0.05,
                complexity="easy"
            ),
            
            # Payload evasion
            EvasionTechnique(
                technique_id="evade_av_encoding",
                name="Payload Encoding",
                description="Encode payload to evade signature detection",
                applicable_defenses=[DefenseType.ANTIVIRUS, DefenseType.EDR],
                priority=EvasionPriority.CRITICAL,
                parameters={"encoding": "base64", "iterations": 3},
                success_rate=0.65,
                detection_risk=0.4,
                complexity="medium"
            ),
            
            EvasionTechnique(
                technique_id="evade_av_encryption",
                name="Payload Encryption",
                description="Encrypt payload with runtime decryption",
                applicable_defenses=[DefenseType.ANTIVIRUS, DefenseType.EDR],
                priority=EvasionPriority.CRITICAL,
                parameters={"cipher": "AES256", "key_derivation": "PBKDF2"},
                success_rate=0.8,
                detection_risk=0.3,
                complexity="hard"
            ),
            
            EvasionTechnique(
                technique_id="evade_av_obfuscation",
                name="Code Obfuscation",
                description="Obfuscate code structure and variables",
                applicable_defenses=[DefenseType.ANTIVIRUS, DefenseType.EDR],
                priority=EvasionPriority.HIGH,
                parameters={"obfuscation_level": "high"},
                success_rate=0.7,
                detection_risk=0.25,
                complexity="medium"
            ),
            
            # Memory evasion
            EvasionTechnique(
                technique_id="evade_edr_memory_only",
                name="Memory-Only Execution",
                description="Execute payload entirely in memory",
                applicable_defenses=[DefenseType.EDR, DefenseType.ANTIVIRUS],
                priority=EvasionPriority.CRITICAL,
                parameters={"technique": "reflective_dll"},
                success_rate=0.75,
                detection_risk=0.4,
                complexity="hard"
            ),
            
            # WAF evasion
            EvasionTechnique(
                technique_id="evade_waf_encoding",
                name="Parameter Encoding",
                description="Encode parameters to bypass WAF rules",
                applicable_defenses=[DefenseType.WAF],
                priority=EvasionPriority.HIGH,
                parameters={"encoding": ["url", "unicode", "hex"]},
                success_rate=0.6,
                detection_risk=0.3,
                complexity="easy"
            ),
            
            EvasionTechnique(
                technique_id="evade_waf_case_manipulation",
                name="Case Manipulation",
                description="Mix case to evade signature matching",
                applicable_defenses=[DefenseType.WAF],
                priority=EvasionPriority.MEDIUM,
                parameters={"strategy": "random"},
                success_rate=0.5,
                detection_risk=0.2,
                complexity="easy"
            ),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    "DefenseIntelligence",
    "DefenseType",
    "DetectedDefense",
    "EvasionTechnique",
    "EvasionPlan",
    "EvasionPriority",
]
