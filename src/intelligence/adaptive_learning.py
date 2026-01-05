"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Adaptive Learning Layer
═══════════════════════════════════════════════════════════════════════════════

Advanced adaptive learning system that learns from every operation to improve
future attack success rates.

Features:
- Success pattern recognition
- Failure pattern analysis
- Optimal parameter discovery
- Historical insight application
- Continuous improvement

Author: RAGLOX Team
Version: 3.0.0
"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

logger = logging.getLogger("raglox.intelligence.adaptive_learning")


# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════

class OutcomeType(Enum):
    """Operation outcome types."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    ERROR = "error"


@dataclass
class OperationRecord:
    """Record of a single operation execution."""
    operation_id: str
    operation_type: str  # scan, exploit, enum, etc.
    technique_id: Optional[str]
    target_info: Dict[str, Any]
    parameters: Dict[str, Any]
    outcome: OutcomeType
    metrics: Dict[str, Any]  # ports_found, vulns_discovered, etc.
    timestamp: float
    duration_ms: int
    error_message: Optional[str] = None
    detection_probability: float = 0.0  # 0-1


@dataclass
class SuccessPattern:
    """A successful operation pattern."""
    pattern_id: str
    operation_type: str
    technique_id: Optional[str]
    target_characteristics: Dict[str, Any]  # os, services, defenses
    optimal_parameters: Dict[str, Any]
    success_count: int
    avg_success_rate: float
    avg_duration_ms: int
    last_used: float
    confidence: float  # 0-1


@dataclass
class FailurePattern:
    """A failure pattern to avoid."""
    pattern_id: str
    operation_type: str
    technique_id: Optional[str]
    failure_indicators: List[str]  # error messages, behaviors
    context: Dict[str, Any]
    failure_count: int
    last_occurrence: float
    recommended_alternatives: List[str]


@dataclass
class LearningStats:
    """Learning system statistics."""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    patterns_discovered: int = 0
    recommendations_made: int = 0
    recommendations_successful: int = 0
    learning_accuracy: float = 0.0
    last_updated: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive Learning Layer
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveLearningLayer:
    """
    Advanced adaptive learning system that continuously improves from experience.
    
    Core Capabilities:
    1. **Success Pattern Recognition**: Identifies and remembers what works
    2. **Failure Pattern Analysis**: Learns from failures to avoid repetition
    3. **Parameter Optimization**: Discovers optimal settings over time
    4. **Context-Aware Recommendations**: Suggests actions based on similar past situations
    5. **Continuous Improvement**: Gets smarter with every operation
    
    Learning Approach:
    - Supervised: Learns from labeled success/failure outcomes
    - Unsupervised: Discovers patterns in operation data
    - Reinforcement: Optimizes parameters based on rewards (success rate)
    """
    
    def __init__(
        self,
        storage_path: Optional[str] = None,
        auto_save: bool = True,
        pattern_threshold: int = 3  # Min occurrences to form pattern
    ):
        """
        Initialize adaptive learning layer.
        
        Args:
            storage_path: Path to store learning data (default: ./data/learning/)
            auto_save: Automatically save learning data
            pattern_threshold: Minimum occurrences to recognize a pattern
        """
        self.storage_path = Path(storage_path or "./data/learning")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.auto_save = auto_save
        self.pattern_threshold = pattern_threshold
        
        # Learning storage
        self.operation_history: List[OperationRecord] = []
        self.success_patterns: Dict[str, SuccessPattern] = {}
        self.failure_patterns: Dict[str, FailurePattern] = {}
        self.optimal_configs: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.stats = LearningStats()
        
        # Load existing learning data
        self._load_learning_data()
        
        logger.info("AdaptiveLearningLayer initialized")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Core Learning Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def learn_from_operation(
        self,
        operation_type: str,
        technique_id: Optional[str],
        target_info: Dict[str, Any],
        parameters: Dict[str, Any],
        result: Dict[str, Any]
    ) -> None:
        """
        Learn from an operation execution.
        
        Args:
            operation_type: Type of operation (scan, exploit, enum, etc.)
            technique_id: MITRE ATT&CK technique ID if applicable
            target_info: Information about the target (OS, services, etc.)
            parameters: Parameters used in the operation
            result: Operation result including success/failure
        """
        # Create operation record
        outcome = self._determine_outcome(result)
        record = OperationRecord(
            operation_id=result.get("operation_id", f"op_{int(time.time())}"),
            operation_type=operation_type,
            technique_id=technique_id,
            target_info=target_info,
            parameters=parameters,
            outcome=outcome,
            metrics=result.get("metrics", {}),
            timestamp=time.time(),
            duration_ms=result.get("duration_ms", 0),
            error_message=result.get("error_message"),
            detection_probability=result.get("detection_probability", 0.0)
        )
        
        # Store in history
        self.operation_history.append(record)
        self.stats.total_operations += 1
        
        # Update statistics
        if outcome == OutcomeType.SUCCESS:
            self.stats.successful_operations += 1
            await self._learn_from_success(record)
        elif outcome == OutcomeType.FAILURE:
            self.stats.failed_operations += 1
            await self._learn_from_failure(record)
        
        # Update learning accuracy
        self._update_learning_accuracy()
        
        # Auto-save if enabled
        if self.auto_save:
            self._save_learning_data()
        
        logger.info(
            f"Learned from {operation_type} operation: {outcome.value} "
            f"(Total: {self.stats.total_operations}, "
            f"Success Rate: {self._get_success_rate():.1%})"
        )
    
    async def _learn_from_success(self, record: OperationRecord) -> None:
        """Learn from a successful operation."""
        # Extract key characteristics
        pattern_key = self._generate_pattern_key(
            record.operation_type,
            record.technique_id,
            record.target_info
        )
        
        # Update or create success pattern
        if pattern_key in self.success_patterns:
            pattern = self.success_patterns[pattern_key]
            pattern.success_count += 1
            pattern.last_used = record.timestamp
            
            # Update average metrics
            total = pattern.success_count
            pattern.avg_duration_ms = int(
                (pattern.avg_duration_ms * (total - 1) + record.duration_ms) / total
            )
            pattern.avg_success_rate = (
                pattern.avg_success_rate * (total - 1) + 1.0
            ) / total
            
            # Refine optimal parameters
            self._refine_optimal_parameters(pattern, record.parameters, record.metrics)
        else:
            # Create new pattern
            pattern = SuccessPattern(
                pattern_id=pattern_key,
                operation_type=record.operation_type,
                technique_id=record.technique_id,
                target_characteristics=self._extract_characteristics(record.target_info),
                optimal_parameters=record.parameters.copy(),
                success_count=1,
                avg_success_rate=1.0,
                avg_duration_ms=record.duration_ms,
                last_used=record.timestamp,
                confidence=0.5  # Initial confidence
            )
            self.success_patterns[pattern_key] = pattern
            self.stats.patterns_discovered += 1
        
        # Update optimal configs
        config_key = f"{record.operation_type}:{record.technique_id or 'general'}"
        if config_key not in self.optimal_configs:
            self.optimal_configs[config_key] = record.parameters.copy()
        else:
            # Blend with existing config (weighted average)
            self._blend_configurations(
                self.optimal_configs[config_key],
                record.parameters,
                weight=0.3  # 30% weight to new data
            )
    
    async def _learn_from_failure(self, record: OperationRecord) -> None:
        """Learn from a failed operation."""
        # Extract failure indicators
        indicators = self._extract_failure_indicators(record)
        
        pattern_key = self._generate_pattern_key(
            record.operation_type,
            record.technique_id,
            record.target_info,
            include_error=True
        )
        
        # Update or create failure pattern
        if pattern_key in self.failure_patterns:
            pattern = self.failure_patterns[pattern_key]
            pattern.failure_count += 1
            pattern.last_occurrence = record.timestamp
            
            # Update failure indicators
            for indicator in indicators:
                if indicator not in pattern.failure_indicators:
                    pattern.failure_indicators.append(indicator)
        else:
            # Create new failure pattern
            pattern = FailurePattern(
                pattern_id=pattern_key,
                operation_type=record.operation_type,
                technique_id=record.technique_id,
                failure_indicators=indicators,
                context=self._extract_characteristics(record.target_info),
                failure_count=1,
                last_occurrence=record.timestamp,
                recommended_alternatives=self._find_alternatives(record)
            )
            self.failure_patterns[pattern_key] = pattern
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Recommendation Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def suggest_parameters(
        self,
        operation_type: str,
        technique_id: Optional[str],
        target_info: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Suggest optimal parameters for an operation.
        
        Args:
            operation_type: Type of operation
            technique_id: MITRE technique ID
            target_info: Target information
            context: Additional context (stealth required, etc.)
            
        Returns:
            Suggested parameters
        """
        self.stats.recommendations_made += 1
        
        # Try to find matching success pattern
        pattern_key = self._generate_pattern_key(
            operation_type, technique_id, target_info
        )
        
        if pattern_key in self.success_patterns:
            pattern = self.success_patterns[pattern_key]
            params = pattern.optimal_parameters.copy()
            
            logger.info(
                f"Recommending parameters from pattern {pattern_key} "
                f"(confidence: {pattern.confidence:.2f}, "
                f"success rate: {pattern.avg_success_rate:.1%})"
            )
        else:
            # Use general optimal config
            config_key = f"{operation_type}:{technique_id or 'general'}"
            params = self.optimal_configs.get(config_key, {}).copy()
            
            logger.info(f"Using general config for {config_key}")
        
        # Apply context-specific adjustments
        if context:
            params = self._adjust_for_context(params, context)
        
        return params
    
    def should_skip_operation(
        self,
        operation_type: str,
        technique_id: Optional[str],
        target_info: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if an operation should be skipped based on failure history.
        
        Returns:
            (should_skip, reason)
        """
        pattern_key = self._generate_pattern_key(
            operation_type, technique_id, target_info, include_error=True
        )
        
        if pattern_key in self.failure_patterns:
            pattern = self.failure_patterns[pattern_key]
            
            # Skip if failed multiple times recently
            if pattern.failure_count >= self.pattern_threshold:
                recent_failures = self._count_recent_failures(pattern_key, hours=24)
                if recent_failures >= 2:
                    reason = (
                        f"Operation failed {pattern.failure_count} times "
                        f"({recent_failures} in last 24h). "
                        f"Common issues: {', '.join(pattern.failure_indicators[:3])}"
                    )
                    logger.warning(f"Recommending to skip: {reason}")
                    return True, reason
        
        return False, None
    
    def get_alternatives(
        self,
        operation_type: str,
        technique_id: Optional[str],
        target_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Get alternative approaches based on learning.
        
        Returns:
            List of alternative operations with confidence scores
        """
        pattern_key = self._generate_pattern_key(
            operation_type, technique_id, target_info, include_error=True
        )
        
        alternatives = []
        
        # Check if we have failure pattern with recommendations
        if pattern_key in self.failure_patterns:
            pattern = self.failure_patterns[pattern_key]
            for alt_technique in pattern.recommended_alternatives:
                alternatives.append({
                    "technique_id": alt_technique,
                    "reason": "Recommended based on failure pattern",
                    "confidence": 0.7
                })
        
        # Find similar successful operations
        for success_key, success_pattern in self.success_patterns.items():
            if self._is_similar_context(
                success_pattern.target_characteristics,
                self._extract_characteristics(target_info)
            ):
                if success_pattern.technique_id != technique_id:
                    alternatives.append({
                        "technique_id": success_pattern.technique_id,
                        "reason": "Successful in similar context",
                        "confidence": success_pattern.confidence,
                        "success_rate": success_pattern.avg_success_rate
                    })
        
        # Sort by confidence and success rate
        alternatives.sort(
            key=lambda x: (x.get("confidence", 0), x.get("success_rate", 0)),
            reverse=True
        )
        
        return alternatives[:5]  # Top 5
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Analytics Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning system statistics."""
        return {
            "total_operations": self.stats.total_operations,
            "successful_operations": self.stats.successful_operations,
            "failed_operations": self.stats.failed_operations,
            "success_rate": self._get_success_rate(),
            "patterns_discovered": self.stats.patterns_discovered,
            "success_patterns": len(self.success_patterns),
            "failure_patterns": len(self.failure_patterns),
            "optimal_configs": len(self.optimal_configs),
            "recommendations_made": self.stats.recommendations_made,
            "recommendations_successful": self.stats.recommendations_successful,
            "recommendation_accuracy": (
                self.stats.recommendations_successful / max(self.stats.recommendations_made, 1)
            ),
            "learning_accuracy": self.stats.learning_accuracy,
            "last_updated": datetime.fromtimestamp(self.stats.last_updated).isoformat()
        }
    
    def get_top_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top performing patterns."""
        patterns = []
        
        for pattern in self.success_patterns.values():
            patterns.append({
                "pattern_id": pattern.pattern_id,
                "operation_type": pattern.operation_type,
                "technique_id": pattern.technique_id,
                "success_count": pattern.success_count,
                "success_rate": pattern.avg_success_rate,
                "confidence": pattern.confidence,
                "avg_duration_ms": pattern.avg_duration_ms
            })
        
        # Sort by success rate and count
        patterns.sort(
            key=lambda x: (x["success_rate"], x["success_count"]),
            reverse=True
        )
        
        return patterns[:limit]
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _determine_outcome(self, result: Dict[str, Any]) -> OutcomeType:
        """Determine operation outcome."""
        if result.get("success"):
            return OutcomeType.SUCCESS
        elif result.get("partial_success"):
            return OutcomeType.PARTIAL
        elif result.get("error"):
            return OutcomeType.ERROR
        else:
            return OutcomeType.FAILURE
    
    def _generate_pattern_key(
        self,
        operation_type: str,
        technique_id: Optional[str],
        target_info: Dict[str, Any],
        include_error: bool = False
    ) -> str:
        """Generate unique pattern key."""
        os_type = target_info.get("os", "unknown")
        has_firewall = target_info.get("has_firewall", False)
        
        key = f"{operation_type}:{technique_id or 'none'}:{os_type}:fw={has_firewall}"
        
        if include_error and "error" in target_info:
            error_type = target_info.get("error_type", "unknown")
            key += f":err={error_type}"
        
        return key
    
    def _extract_characteristics(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key target characteristics."""
        return {
            "os": target_info.get("os", "unknown"),
            "os_version": target_info.get("os_version"),
            "services": target_info.get("services", []),
            "has_firewall": target_info.get("has_firewall", False),
            "has_ids": target_info.get("has_ids", False),
            "has_av": target_info.get("has_av", False),
        }
    
    def _extract_failure_indicators(self, record: OperationRecord) -> List[str]:
        """Extract indicators from failure."""
        indicators = []
        
        if record.error_message:
            # Common error patterns
            error_lower = record.error_message.lower()
            
            if "connection refused" in error_lower:
                indicators.append("connection_refused")
            if "timeout" in error_lower:
                indicators.append("timeout")
            if "permission denied" in error_lower:
                indicators.append("permission_denied")
            if "not found" in error_lower:
                indicators.append("not_found")
            if "blocked" in error_lower or "filtered" in error_lower:
                indicators.append("blocked_by_defense")
        
        return indicators
    
    def _find_alternatives(self, record: OperationRecord) -> List[str]:
        """Find alternative techniques."""
        # This would query knowledge base for similar techniques
        # For now, return empty list
        return []
    
    def _refine_optimal_parameters(
        self,
        pattern: SuccessPattern,
        new_params: Dict[str, Any],
        metrics: Dict[str, Any]
    ) -> None:
        """Refine optimal parameters based on new success."""
        # Simple approach: if new params performed better, blend them in
        for key, value in new_params.items():
            if key in pattern.optimal_parameters:
                # Weighted average for numeric values
                if isinstance(value, (int, float)) and isinstance(
                    pattern.optimal_parameters[key], (int, float)
                ):
                    old_value = pattern.optimal_parameters[key]
                    pattern.optimal_parameters[key] = (old_value * 0.8 + value * 0.2)
            else:
                pattern.optimal_parameters[key] = value
    
    def _blend_configurations(
        self,
        base_config: Dict[str, Any],
        new_config: Dict[str, Any],
        weight: float = 0.3
    ) -> None:
        """Blend two configurations (modifies base_config in place)."""
        for key, new_value in new_config.items():
            if key in base_config:
                old_value = base_config[key]
                
                # Numeric values: weighted average
                if isinstance(new_value, (int, float)) and isinstance(old_value, (int, float)):
                    base_config[key] = old_value * (1 - weight) + new_value * weight
                # Otherwise: use new value with probability = weight
                elif hash(str(new_value)) % 100 < weight * 100:
                    base_config[key] = new_value
            else:
                base_config[key] = new_value
    
    def _adjust_for_context(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Adjust parameters based on context."""
        adjusted = params.copy()
        
        # Stealth mode adjustments
        if context.get("stealth_required"):
            adjusted["timing"] = adjusted.get("timing", "T4").replace("T4", "T2")
            adjusted["threads"] = min(adjusted.get("threads", 10), 3)
            adjusted["randomize"] = True
        
        # Detected defenses
        if context.get("has_firewall"):
            adjusted["fragmentation"] = True
            adjusted["source_port"] = 53  # DNS
        
        if context.get("has_ids"):
            adjusted["timing"] = "T2"
            adjusted["decoys"] = True
        
        return adjusted
    
    def _is_similar_context(
        self,
        context1: Dict[str, Any],
        context2: Dict[str, Any],
        threshold: float = 0.7
    ) -> bool:
        """Check if two contexts are similar."""
        # Simple similarity: count matching keys
        matching_keys = sum(
            1 for k in context1.keys()
            if k in context2 and context1[k] == context2[k]
        )
        total_keys = len(set(context1.keys()) | set(context2.keys()))
        
        similarity = matching_keys / max(total_keys, 1)
        return similarity >= threshold
    
    def _count_recent_failures(self, pattern_key: str, hours: int = 24) -> int:
        """Count recent failures for a pattern."""
        cutoff = time.time() - (hours * 3600)
        count = 0
        
        for record in reversed(self.operation_history):
            if record.timestamp < cutoff:
                break
            
            record_key = self._generate_pattern_key(
                record.operation_type,
                record.technique_id,
                record.target_info,
                include_error=True
            )
            
            if record_key == pattern_key and record.outcome == OutcomeType.FAILURE:
                count += 1
        
        return count
    
    def _get_success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.stats.total_operations == 0:
            return 0.0
        return self.stats.successful_operations / self.stats.total_operations
    
    def _update_learning_accuracy(self) -> None:
        """Update learning accuracy metric."""
        if self.stats.recommendations_made > 0:
            self.stats.learning_accuracy = (
                self.stats.recommendations_successful / self.stats.recommendations_made
            )
        self.stats.last_updated = time.time()
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Persistence Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _save_learning_data(self) -> None:
        """Save learning data to disk."""
        try:
            # Save success patterns
            success_file = self.storage_path / "success_patterns.json"
            with open(success_file, 'w') as f:
                data = {k: asdict(v) for k, v in self.success_patterns.items()}
                json.dump(data, f, indent=2)
            
            # Save failure patterns
            failure_file = self.storage_path / "failure_patterns.json"
            with open(failure_file, 'w') as f:
                data = {k: asdict(v) for k, v in self.failure_patterns.items()}
                json.dump(data, f, indent=2)
            
            # Save optimal configs
            config_file = self.storage_path / "optimal_configs.json"
            with open(config_file, 'w') as f:
                json.dump(self.optimal_configs, f, indent=2)
            
            # Save stats
            stats_file = self.storage_path / "learning_stats.json"
            with open(stats_file, 'w') as f:
                json.dump(asdict(self.stats), f, indent=2)
            
            logger.debug(f"Learning data saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")
    
    def _load_learning_data(self) -> None:
        """Load learning data from disk."""
        try:
            # Load success patterns
            success_file = self.storage_path / "success_patterns.json"
            if success_file.exists():
                with open(success_file) as f:
                    data = json.load(f)
                    self.success_patterns = {
                        k: SuccessPattern(**v) for k, v in data.items()
                    }
            
            # Load failure patterns
            failure_file = self.storage_path / "failure_patterns.json"
            if failure_file.exists():
                with open(failure_file) as f:
                    data = json.load(f)
                    self.failure_patterns = {
                        k: FailurePattern(**v) for k, v in data.items()
                    }
            
            # Load optimal configs
            config_file = self.storage_path / "optimal_configs.json"
            if config_file.exists():
                with open(config_file) as f:
                    self.optimal_configs = json.load(f)
            
            # Load stats
            stats_file = self.storage_path / "learning_stats.json"
            if stats_file.exists():
                with open(stats_file) as f:
                    self.stats = LearningStats(**json.load(f))
            
            logger.info(
                f"Loaded learning data: "
                f"{len(self.success_patterns)} success patterns, "
                f"{len(self.failure_patterns)} failure patterns"
            )
        except Exception as e:
            logger.warning(f"Failed to load learning data: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    "AdaptiveLearningLayer",
    "OperationRecord",
    "SuccessPattern",
    "FailurePattern",
    "LearningStats",
    "OutcomeType",
]
