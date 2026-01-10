# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intelligent Task Prioritization
# Phase 5.0: Advanced Features
# ═══════════════════════════════════════════════════════════════

"""
Intelligent Task Prioritization using ML-inspired concepts.

Features:
- Success probability estimation
- Priority scoring based on multiple factors
- Learning from past task results

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("raglox.core.prioritization")


@dataclass
class TaskScore:
    """Task priority score."""
    task_id: str
    priority_score: float  # 0.0-10.0
    success_probability: float  # 0.0-1.0
    value_score: float  # 0.0-10.0
    risk_score: float  # 0.0-10.0
    urgency_score: float  # 0.0-10.0


class IntelligentTaskPrioritizer:
    """
    Intelligent Task Prioritization Engine.
    
    Uses ML-inspired concepts to prioritize tasks optimally.
    """
    
    def __init__(self):
        self._task_history: List[Dict[str, Any]] = []
        self._weights = {
            "success_probability": 0.3,
            "value": 0.3,
            "urgency": 0.2,
            "risk": 0.2,
        }
        logger.info("Initialized IntelligentTaskPrioritizer")
    
    async def score_task(
        self,
        task_type: str,
        target_id: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> TaskScore:
        """Score a task for prioritization."""
        
        # Estimate success probability (simplified)
        success_prob = self._estimate_success_probability(task_type, parameters)
        
        # Calculate value score
        value_score = self._calculate_value_score(task_type, target_id)
        
        # Calculate risk score (inverse - lower risk = higher priority)
        risk_score = 5.0  # Default medium risk
        
        # Calculate urgency
        urgency_score = 5.0  # Default medium urgency
        
        # Combined priority score
        priority_score = (
            self._weights["success_probability"] * success_prob * 10 +
            self._weights["value"] * value_score +
            self._weights["urgency"] * urgency_score +
            self._weights["risk"] * (10 - risk_score)  # Inverse risk
        )
        
        return TaskScore(
            task_id=f"task-{task_type}-{target_id}",
            priority_score=min(priority_score, 10.0),
            success_probability=success_prob,
            value_score=value_score,
            risk_score=risk_score,
            urgency_score=urgency_score,
        )
    
    def _estimate_success_probability(
        self,
        task_type: str,
        parameters: Optional[Dict[str, Any]]
    ) -> float:
        """Estimate task success probability."""
        # Simple heuristic-based estimation
        
        # Check historical success rate
        similar_tasks = [t for t in self._task_history 
                        if t.get("task_type") == task_type]
        
        if similar_tasks:
            success_count = len([t for t in similar_tasks if t.get("success")])
            return success_count / len(similar_tasks)
        
        # Default probabilities by task type
        defaults = {
            "network_scan": 0.95,
            "port_scan": 0.90,
            "vuln_scan": 0.85,
            "exploit": 0.60,
            "lateral_move": 0.50,
            "privilege_escalation": 0.40,
        }
        
        return defaults.get(task_type, 0.70)
    
    def _calculate_value_score(self, task_type: str, target_id: str) -> float:
        """Calculate task value score."""
        # Value based on task type
        value_scores = {
            "network_scan": 6.0,
            "port_scan": 7.0,
            "vuln_scan": 8.0,
            "exploit": 9.0,
            "privilege_escalation": 10.0,
            "lateral_move": 8.5,
        }
        
        return value_scores.get(task_type, 5.0)
    
    async def prioritize_tasks(
        self,
        tasks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Prioritize a list of tasks."""
        
        scored_tasks = []
        for task in tasks:
            score = await self.score_task(
                task.get("task_type"),
                task.get("target_id"),
                task.get("parameters"),
            )
            task["priority_score"] = score.priority_score
            task["success_probability"] = score.success_probability
            scored_tasks.append(task)
        
        # Sort by priority score (descending)
        scored_tasks.sort(key=lambda t: t["priority_score"], reverse=True)
        
        return scored_tasks
    
    def record_task_result(
        self,
        task_type: str,
        success: bool,
        duration_seconds: float
    ):
        """Record task result for learning."""
        self._task_history.append({
            "task_type": task_type,
            "success": success,
            "duration_seconds": duration_seconds,
        })
