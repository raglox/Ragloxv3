"""
RAGLOX v3.0 - Visualization Dashboard API
Phase 5.0: Real-time Mission Visualization

Provides data for real-time dashboards:
- Mission progress tracking
- Target network maps
- Risk heatmaps
- Timeline views
- Statistics and metrics
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json


@dataclass
class DashboardData:
    """Complete dashboard data snapshot"""
    mission_id: str
    timestamp: datetime
    overview: Dict[str, Any] = field(default_factory=dict)
    targets: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    risk_metrics: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)


class VisualizationDashboardAPI:
    """
    Visualization Dashboard API
    
    Generates real-time data for mission dashboards:
    - Overview statistics
    - Target network topology
    - Attack timeline
    - Risk assessments
    - Performance metrics
    
    Usage:
        viz = VisualizationDashboardAPI(mission_id, blackboard)
        data = await viz.generate_dashboard_data()
        print(f"Mission Progress: {data.statistics['progress']}%")
    """
    
    def __init__(
        self, 
        mission_id: str, 
        blackboard: "Blackboard",
        redis: Optional[Any] = None  # Optional Redis client for advanced features
    ):
        self.mission_id = mission_id
        self.blackboard = blackboard
        self.redis = redis or blackboard.redis  # Use blackboard's redis if not provided
        self._update_history: List[DashboardData] = []
    
    async def generate_dashboard_data(self) -> DashboardData:
        """
        Generate complete dashboard data snapshot.
        
        Returns:
            DashboardData with all visualization components
        """
        # Get mission state
        mission = await self.blackboard.get_mission(self.mission_id)
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        # vulns = await self.blackboard.get_mission_vulns(self.mission_id)
        stats = await self.blackboard.get_mission_stats(self.mission_id)
        
        # Overview
        overview = {
            "mission_id": self.mission_id,
            "mission_name": mission.get("name", "Unknown") if mission else "Unknown",
            "status": mission.get("status", "unknown") if mission else "unknown",
            "start_time": mission.get("created_at") if mission else None,
            "duration": self._calculate_duration(mission),
        }
        
        # Targets data
        target_data = []
        for target_full_id in targets[:10]:  # Limit to 10 for visualization
            # Strip 'target:' prefix if present
            target_id = target_full_id.replace("target:", "") if isinstance(target_full_id, str) else target_full_id
            target = await self.blackboard.get_target(target_id)
            if target:
                target_data.append({
                    "id": target_id,
                    "ip": target.get("ip", "unknown"),
                    "hostname": target.get("hostname", "unknown"),
                    "status": target.get("status", "unknown"),
                    "ports": len(target.get("ports", {}))
                })
        
        # Timeline (recent events)
        timeline = await self._generate_timeline()
        
        # Risk metrics
        risk_metrics = {
            "overall_risk": "medium",  # Placeholder
            "detection_probability": 0.5,
            "success_probability": 0.7
        }
        
        # Statistics
        statistics = {
            "targets_discovered": stats.targets_discovered,
            "vulnerabilities_found": stats.vulns_found,
            "credentials_harvested": stats.creds_harvested,
            "sessions_established": stats.sessions_established,
            "goals_achieved": stats.goals_achieved,
            "progress": self._calculate_progress(stats)
        }
        
        data = DashboardData(
            mission_id=self.mission_id,
            timestamp=datetime.utcnow(),
            overview=overview,
            targets=target_data,
            timeline=timeline,
            risk_metrics=risk_metrics,
            statistics=statistics
        )
        
        self._update_history.append(data)
        return data
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get dashboard data as dict (for test compatibility).
        
        Returns:
            Dictionary with dashboard components
        """
        data = await self.generate_dashboard_data()
        
        # Get tasks from blackboard
        try:
            pending_tasks = await self.blackboard.get_pending_tasks(self.mission_id)
            running_tasks = await self.blackboard.get_running_tasks(self.mission_id)
            completed_tasks = await self.blackboard.get_completed_tasks(self.mission_id)
            total_tasks = len(pending_tasks) + len(running_tasks) + len(completed_tasks)
        except:
            total_tasks = 0
        
        # Convert to dict format expected by tests
        return {
            "mission": data.overview,
            "targets": data.targets,
            "tasks": [],  # Simplified for now
            "statistics": {
                "total_targets": len(data.targets),
                "total_tasks": total_tasks,
                **data.statistics
            },
            "timeline": data.timeline,
            "risk_metrics": data.risk_metrics
        }
    
    def _calculate_duration(self, mission: Optional[Dict]) -> str:
        """Calculate mission duration"""
        if not mission or "created_at" not in mission:
            return "Unknown"
        
        # Simplified - would parse datetime properly
        return "1h 30m"
    
    def _calculate_progress(self, stats) -> float:
        """Calculate overall mission progress (0-100)"""
        # Simple heuristic: average of normalized metrics
        max_targets = 10
        max_vulns = 20
        max_creds = 5
        
        progress = (
            (min(stats.targets_discovered, max_targets) / max_targets) * 30 +
            (min(stats.vulns_found, max_vulns) / max_vulns) * 40 +
            (min(stats.creds_harvested, max_creds) / max_creds) * 30
        )
        
        return round(progress, 1)
    
    async def _generate_timeline(self) -> List[Dict[str, Any]]:
        """Generate recent events timeline"""
        # Placeholder - would query actual events
        return [
            {
                "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                "type": "target_discovered",
                "description": "New target discovered: 192.168.1.10"
            },
            {
                "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                "type": "vulnerability_found",
                "description": "Critical vulnerability found: CVE-2024-0001"
            }
        ]
    
    async def get_network_topology(self) -> Dict[str, Any]:
        """
        Generate network topology visualization data.
        
        Returns:
            Graph structure with nodes and edges
        """
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        
        nodes = []
        edges = []
        
        for target_id in targets:
            target = await self.blackboard.get_target(target_id)
            if target:
                nodes.append({
                    "id": target_id,
                    "label": target.get("hostname", target.get("ip", "unknown")),
                    "type": "target",
                    "status": target.get("status", "unknown")
                })
        
        # Add edges for relationships (simplified)
        # Would analyze actual network connections
        
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    async def get_risk_heatmap(self) -> List[Dict[str, Any]]:
        """
        Generate risk heatmap data.
        
        Returns:
            List of items with risk scores for visualization
        """
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        
        heatmap = []
        for target_id in targets:
            target = await self.blackboard.get_target(target_id)
            if target:
                # Calculate risk score (simplified)
                risk_score = 0.5  # Placeholder
                
                heatmap.append({
                    "id": target_id,
                    "label": target.get("hostname", target.get("ip")),
                    "risk_score": risk_score,
                    "color": self._risk_to_color(risk_score)
                })
        
        return heatmap
    
    def _risk_to_color(self, risk_score: float) -> str:
        """Convert risk score to color"""
        if risk_score >= 0.8:
            return "red"
        elif risk_score >= 0.6:
            return "orange"
        elif risk_score >= 0.4:
            return "yellow"
        else:
            return "green"
    
    async def export_data(self, format: str = "json") -> str:
        """
        Export dashboard data in specified format.
        
        Args:
            format: Export format (json, csv, etc.)
            
        Returns:
            Serialized data string
        """
        data = await self.generate_dashboard_data()
        
        if format == "json":
            return json.dumps({
                "mission_id": data.mission_id,
                "timestamp": data.timestamp.isoformat(),
                "overview": data.overview,
                "statistics": data.statistics,
                "targets": data.targets,
                "timeline": data.timeline,
                "risk_metrics": data.risk_metrics
            }, indent=2)
        
        # Other formats can be added
        return str(data)
    
    async def get_real_time_updates(self, since: datetime) -> List[Dict[str, Any]]:
        """
        Get updates since specified time for real-time dashboard.
        
        Args:
            since: Get updates after this timestamp
            
        Returns:
            List of updates
        """
        updates = []
        
        for data in self._update_history:
            if data.timestamp > since:
                updates.append({
                    "timestamp": data.timestamp.isoformat(),
                    "statistics": data.statistics,
                    "targets_count": len(data.targets)
                })
        
        return updates
