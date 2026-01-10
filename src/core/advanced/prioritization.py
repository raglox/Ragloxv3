"""
RAGLOX v3.0 - Intelligent Task Prioritization
Phase 5.0: AI-Powered Task Ranking

Prioritizes tasks based on:
- Mission goals alignment
- Resource availability
- Risk-reward ratio
- Dependencies
- Historical success rates
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio


@dataclass
class TaskScore:
    """Task priority score breakdown"""
    task_id: str
    total_score: float  # 0.0-1.0
    goal_alignment: float = 0.0
    criticality: float = 0.0
    resource_efficiency: float = 0.0
    risk_reward: float = 0.0
    urgency: float = 0.0


class IntelligentTaskPrioritizer:
    """
    Intelligent Task Prioritization Engine
    
    Uses multi-factor scoring to rank tasks:
    1. Goal alignment: How well task supports mission goals
    2. Criticality: Impact on mission success
    3. Resource efficiency: ROI in terms of effort
    4. Risk-reward: Probability of success vs. detection
    5. Urgency: Time-sensitivity
    
    Usage:
        prioritizer = IntelligentTaskPrioritizer(mission_id, blackboard)
        ranked_tasks = await prioritizer.rank_tasks([task1, task2, ...])
        top_task = ranked_tasks[0]
    """
    
    def __init__(self, mission_id: str, blackboard: "Blackboard"):
        self.mission_id = mission_id
        self.blackboard = blackboard
        self._scoring_history: List[TaskScore] = []
    
    async def rank_tasks(self, task_ids: List[str]) -> List[TaskScore]:
        """
        Rank tasks by priority score.
        
        Args:
            task_ids: List of task IDs to rank
            
        Returns:
            List of TaskScore objects sorted by total_score (highest first)
        """
        scores = []
        
        for task_id in task_ids:
            task_data = await self.blackboard.get_task(task_id)
            if not task_data:
                continue
            
            score = await self._calculate_task_score(task_id, task_data)
            scores.append(score)
            self._scoring_history.append(score)
        
        # Sort by total score (descending)
        scores.sort(key=lambda s: s.total_score, reverse=True)
        return scores
    
    async def prioritize_tasks(self, task_ids: List[str]) -> List[str]:
        """
        Prioritize tasks and return sorted task IDs.
        
        Args:
            task_ids: List of task IDs to prioritize
            
        Returns:
            List of task IDs sorted by priority (highest first)
        """
        scores = await self.rank_tasks(task_ids)
        return [score.task_id for score in scores]
    
    async def _calculate_task_score(
        self,
        task_id: str,
        task_data: Dict[str, Any]
    ) -> TaskScore:
        """Calculate comprehensive score for a task"""
        
        # Extract task properties
        task_type = task_data.get("type", "")
        priority_str = task_data.get("priority", "5")
        # Convert priority to numeric value
        priority_map = {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 3,
            "minimal": 1
        }
        if isinstance(priority_str, str):
            priority_value = priority_map.get(priority_str.lower(), 5)
        else:
            priority_value = int(priority_str)
        
        params = task_data.get("params", {})
        
        # Factor 1: Goal Alignment (0.0-1.0)
        # Higher for tasks that directly support goals
        goal_alignment = 0.5  # Baseline
        if "exploit" in task_type.lower():
            goal_alignment = 0.9  # Exploitation highly aligned
        elif "recon" in task_type.lower():
            goal_alignment = 0.7  # Recon important
        elif "scan" in task_type.lower():
            goal_alignment = 0.6  # Scanning moderately aligned
        
        # Factor 2: Criticality (0.0-1.0)
        # Based on task priority
        criticality = min(priority_value / 10.0, 1.0)
        
        # Factor 3: Resource Efficiency (0.0-1.0)
        # Simpler tasks = higher efficiency
        resource_efficiency = 0.7  # Default
        if "network_scan" in task_type.lower():
            resource_efficiency = 0.9  # Scanning is efficient
        elif "exploit" in task_type.lower():
            resource_efficiency = 0.5  # Exploitation resource-intensive
        
        # Factor 4: Risk-Reward (0.0-1.0)
        # Higher reward, lower risk = better score
        risk_reward = 0.6  # Baseline
        cvss_score = params.get("cvss_score", 5.0)
        if cvss_score >= 8.0:
            risk_reward = 0.9  # High-impact vuln = high reward
        elif cvss_score >= 6.0:
            risk_reward = 0.7
        
        # Factor 5: Urgency (0.0-1.0)
        # Time-sensitive tasks get higher urgency
        urgency = 0.5  # Default
        if priority_value >= 8:
            urgency = 0.9  # Critical priority = urgent
        elif priority_value >= 6:
            urgency = 0.7
        
        # Calculate weighted total
        # Weights: goal=0.3, criticality=0.25, efficiency=0.15, risk_reward=0.2, urgency=0.1
        total_score = (
            goal_alignment * 0.3 +
            criticality * 0.25 +
            resource_efficiency * 0.15 +
            risk_reward * 0.2 +
            urgency * 0.1
        )
        
        return TaskScore(
            task_id=task_id,
            total_score=total_score,
            goal_alignment=goal_alignment,
            criticality=criticality,
            resource_efficiency=resource_efficiency,
            risk_reward=risk_reward,
            urgency=urgency
        )
    
    async def get_next_task(self) -> Optional[str]:
        """
        Get the highest-priority pending task.
        
        Returns:
            Task ID of highest-priority task, or None if no pending tasks
        """
        pending_tasks = await self.blackboard.get_pending_tasks(self.mission_id)
        
        if not pending_tasks:
            return None
        
        # Rank all pending tasks
        scores = await self.rank_tasks(pending_tasks)
        
        if scores:
            return scores[0].task_id
        
        return None
    
    async def reprioritize_all_tasks(self) -> List[TaskScore]:
        """
        Reprioritize all pending tasks in the mission.
        
        Returns:
            List of ranked tasks
        """
        pending_tasks = await self.blackboard.get_pending_tasks(self.mission_id)
        return await self.rank_tasks(pending_tasks)
    
    async def get_scoring_history(self) -> List[TaskScore]:
        """Get historical task scores"""
        return self._scoring_history.copy()
    
    async def explain_score(self, task_id: str) -> Dict[str, Any]:
        """
        Get detailed explanation of task score.
        
        Args:
            task_id: Task to explain
            
        Returns:
            Dictionary with score breakdown and explanation
        """
        # Find most recent score for this task
        for score in reversed(self._scoring_history):
            if score.task_id == task_id:
                return {
                    "task_id": task_id,
                    "total_score": score.total_score,
                    "breakdown": {
                        "goal_alignment": {
                            "value": score.goal_alignment,
                            "weight": 0.3,
                            "contribution": score.goal_alignment * 0.3
                        },
                        "criticality": {
                            "value": score.criticality,
                            "weight": 0.25,
                            "contribution": score.criticality * 0.25
                        },
                        "resource_efficiency": {
                            "value": score.resource_efficiency,
                            "weight": 0.15,
                            "contribution": score.resource_efficiency * 0.15
                        },
                        "risk_reward": {
                            "value": score.risk_reward,
                            "weight": 0.2,
                            "contribution": score.risk_reward * 0.2
                        },
                        "urgency": {
                            "value": score.urgency,
                            "weight": 0.1,
                            "contribution": score.urgency * 0.1
                        }
                    },
                    "ranking": "high" if score.total_score >= 0.7 else "medium" if score.total_score >= 0.5 else "low"
                }
        
        return {"error": "Task score not found"}
    
    async def calculate_priority_scores(self, task_ids: List[str]) -> Dict[str, float]:
        """
        Calculate priority scores for multiple tasks.
        
        Args:
            task_ids: List of task IDs
            
        Returns:
            Dictionary mapping task_id to total_score
        """
        scores = await self.rank_tasks(task_ids)
        return {score.task_id: score.total_score for score in scores}
