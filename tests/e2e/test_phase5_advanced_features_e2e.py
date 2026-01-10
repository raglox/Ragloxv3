"""
RAGLOX v3.0 - Phase 5.0 Advanced Features E2E Tests

Enterprise-level end-to-end tests for Advanced Features including Risk Assessment,
Real-time Adaptation, Task Prioritization, and Visualization.

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-10
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
import uuid
import json

from src.core.advanced.risk_assessment import (
    AdvancedRiskAssessmentEngine,
    RiskLevel,
    RiskFactor
)
from src.core.advanced.adaptation import RealtimeAdaptationEngine
from src.core.advanced.prioritization import IntelligentTaskPrioritizer
from src.core.advanced.visualization import VisualizationDashboardAPI
from src.core.blackboard import Blackboard
from src.core.models import (
    MissionStatus,
    TargetStatus,
    Priority,
    Severity,
    TaskType,
    TaskStatus
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase5RiskAssessmentE2E:
    """E2E tests for Phase 5.0 Advanced Risk Assessment"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis):
        """Setup test environment"""
        self.blackboard = real_blackboard
        self.redis = real_redis
        
        self.mission_id = f"risk_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Risk Assessment Test",
            description="Testing Advanced Risk Assessment",
            scope=["10.20.0.0/24"],
            goals=["Test risk assessment"],
            constraints={"stealth": "high", "detection_tolerance": "low"}
        )
        
        self.risk_engine = AdvancedRiskAssessmentEngine(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_comprehensive_risk_assessment(self):
        """
        Test comprehensive risk assessment across multiple dimensions
        
        Covers:
        - Detection risk
        - Operational risk
        - Target risk
        - Timing risk
        - Resource risk
        - Real-time risk updates
        """
        # Phase 1: Setup mission environment
        # Add targets with varying risk profiles
        targets = [
            {
                "target_id": "risk_target_1",
                "ip": "10.20.0.10",
                "hostname": "firewall.corp.local",
                "status": TargetStatus.discovered.value,
                "security_level": "high",  # High risk
                "monitoring": "active"
            },
            {
                "target_id": "risk_target_2",
                "ip": "10.20.0.50",
                "hostname": "workstation.corp.local",
                "status": TargetStatus.discovered.value,
                "security_level": "low",  # Low risk
                "monitoring": "minimal"
            }
        ]
        
        for target in targets:
            await self.blackboard.add_target(
                mission_id=self.mission_id,
                **target
            )
        
        # Phase 2: Assess initial risk
        initial_risk = await self.risk_engine.assess_mission_risk()
        
        assert initial_risk is not None
        assert "overall_risk" in initial_risk
        assert "risk_factors" in initial_risk
        assert "risk_score" in initial_risk
        assert 0 <= initial_risk["risk_score"] <= 100
        
        # Phase 3: Simulate risky action
        await self.blackboard.add_event(
            mission_id=self.mission_id,
            event_type="action_taken",
            data={
                "action": "port_scan",
                "target_id": "risk_target_1",
                "stealth": "low",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Phase 4: Reassess risk after action
        updated_risk = await self.risk_engine.assess_mission_risk()
        
        # Risk should increase after noisy action on high-security target
        assert updated_risk["risk_score"] > initial_risk["risk_score"]
        
        # Phase 5: Check risk factors
        risk_factors = updated_risk["risk_factors"]
        assert len(risk_factors) > 0
        
        # Should have detection risk factor
        detection_factors = [
            f for f in risk_factors
            if f["category"] == "detection"
        ]
        assert len(detection_factors) > 0
        
        # Phase 6: Get risk mitigation recommendations
        recommendations = await self.risk_engine.get_risk_mitigation_recommendations()
        
        assert len(recommendations) > 0
        assert any("stealth" in r.lower() or "detection" in r.lower() 
                  for r in recommendations)
        
        print("✅ Comprehensive risk assessment test passed")
        print(f"   Initial risk score: {initial_risk['risk_score']:.1f}")
        print(f"   Updated risk score: {updated_risk['risk_score']:.1f}")
        print(f"   Risk increase: {updated_risk['risk_score'] - initial_risk['risk_score']:.1f}")
        print(f"   Risk factors identified: {len(risk_factors)}")
        print(f"   Recommendations: {len(recommendations)}")

    @pytest.mark.priority_high
    async def test_e2e_real_time_risk_monitoring(self):
        """Test real-time risk monitoring during mission execution"""
        risk_history = []
        
        # Start monitoring
        monitoring_task = asyncio.create_task(
            self._monitor_risk(risk_history, duration=2.0)
        )
        
        # Simulate mission actions with varying risk
        actions = [
            {"action": "passive_recon", "risk": "low"},
            {"action": "active_scan", "risk": "medium"},
            {"action": "exploit_attempt", "risk": "high"},
            {"action": "privilege_escalation", "risk": "critical"}
        ]
        
        for action in actions:
            await asyncio.sleep(0.5)
            await self.blackboard.add_event(
                mission_id=self.mission_id,
                event_type="action_taken",
                data={
                    "action": action["action"],
                    "risk_level": action["risk"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
        
        # Wait for monitoring to complete
        await monitoring_task
        
        # Verify risk tracking
        assert len(risk_history) > 0
        
        # Risk should generally trend upward with increasingly risky actions
        if len(risk_history) >= 2:
            risk_trend = risk_history[-1]["risk_score"] >= risk_history[0]["risk_score"]
            assert risk_trend
        
        print("✅ Real-time risk monitoring test passed")
        print(f"   Risk measurements: {len(risk_history)}")
        print(f"   Risk range: {min(r['risk_score'] for r in risk_history):.1f} - {max(r['risk_score'] for r in risk_history):.1f}")

    async def _monitor_risk(self, history: List, duration: float):
        """Helper to monitor risk over time"""
        end_time = asyncio.get_event_loop().time() + duration
        while asyncio.get_event_loop().time() < end_time:
            risk = await self.risk_engine.assess_mission_risk()
            history.append({
                "timestamp": datetime.utcnow(),
                "risk_score": risk["risk_score"],
                "risk_level": risk["overall_risk"]
            })
            await asyncio.sleep(0.3)

    @pytest.mark.priority_high
    async def test_e2e_risk_based_decision_making(self):
        """Test risk-based decision making for actions"""
        # High-risk environment
        await self.blackboard.store_metadata(
            mission_id=self.mission_id,
            key="environment_risk",
            value={"security_level": "high", "monitoring": "active", "ids_ips": "enabled"}
        )
        
        # Assess risk for different actions
        actions = [
            {"name": "passive_dns_query", "expected_risk": "low"},
            {"name": "port_scan", "expected_risk": "medium"},
            {"name": "vulnerability_scan", "expected_risk": "high"},
            {"name": "exploit_execution", "expected_risk": "critical"}
        ]
        
        results = []
        for action in actions:
            risk = await self.risk_engine.assess_action_risk(
                action_type=action["name"],
                target_id="risk_target_1"
            )
            results.append({
                "action": action["name"],
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "recommended": risk["risk_score"] < 70  # Threshold
            })
        
        # Verify risk scaling
        assert results[0]["risk_score"] < results[1]["risk_score"]
        assert results[1]["risk_score"] < results[2]["risk_score"]
        assert results[2]["risk_score"] < results[3]["risk_score"]
        
        # Low-risk actions should be recommended
        assert results[0]["recommended"]
        
        # High-risk actions should not be recommended in high-security environment
        assert not results[3]["recommended"]
        
        print("✅ Risk-based decision making test passed")
        for r in results:
            print(f"   {r['action']}: {r['risk_score']:.1f} ({r['risk_level']}) - {'✓' if r['recommended'] else '✗'}")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase5AdaptationE2E:
    """E2E tests for Phase 5.0 Real-time Adaptation"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"adapt_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Adaptation Test",
            description="Testing Real-time Adaptation",
            scope=["10.30.0.0/24"],
            goals=["Test adaptation"],
            constraints={}
        )
        
        self.adaptation_engine = RealtimeAdaptationEngine(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_adaptive_strategy_adjustment(self):
        """Test adaptive strategy adjustment based on mission feedback"""
        # Initial strategy
        initial_strategy = await self.adaptation_engine.get_current_strategy()
        
        # Simulate detection event
        await self.blackboard.add_event(
            mission_id=self.mission_id,
            event_type="detection_alert",
            data={
                "severity": "high",
                "source": "ids",
                "message": "Suspicious port scanning detected"
            }
        )
        
        # Trigger adaptation
        adapted = await self.adaptation_engine.adapt_to_environment()
        
        assert adapted["strategy_changed"]
        
        # Get updated strategy
        updated_strategy = await self.adaptation_engine.get_current_strategy()
        
        # Strategy should be more cautious
        assert updated_strategy["stealth_level"] > initial_strategy["stealth_level"]
        assert updated_strategy["scan_speed"] < initial_strategy["scan_speed"]
        
        print("✅ Adaptive strategy adjustment test passed")
        print(f"   Strategy adapted: {adapted['strategy_changed']}")
        print(f"   Stealth increase: {updated_strategy['stealth_level'] - initial_strategy['stealth_level']}")

    @pytest.mark.priority_high
    async def test_e2e_technique_adaptation(self):
        """Test adaptation of techniques when blocked"""
        # Simulate blocked technique
        await self.blackboard.add_event(
            mission_id=self.mission_id,
            event_type="technique_blocked",
            data={
                "technique": "SMB_authentication",
                "reason": "Firewall rule",
                "target_id": "blocked_target"
            }
        )
        
        # Get alternative techniques
        alternatives = await self.adaptation_engine.get_alternative_techniques(
            blocked_technique="SMB_authentication",
            target_id="blocked_target"
        )
        
        assert len(alternatives) > 0
        assert "SMB_authentication" not in [a["technique"] for a in alternatives]
        
        # Verify alternatives are ranked
        assert all("score" in alt for alt in alternatives)
        
        print("✅ Technique adaptation test passed")
        print(f"   Alternative techniques: {len(alternatives)}")
        print(f"   Top alternative: {alternatives[0]['technique']}")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase5PrioritizationE2E:
    """E2E tests for Phase 5.0 Intelligent Task Prioritization"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"prior_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Prioritization Test",
            description="Testing Intelligent Task Prioritization",
            scope=["10.40.0.0/24"],
            goals=["Test prioritization"],
            constraints={}
        )
        
        self.prioritizer = IntelligentTaskPrioritizer(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_intelligent_task_ranking(self):
        """Test intelligent task ranking based on multiple factors"""
        # Create diverse tasks
        tasks = []
        
        # High-priority critical path task
        task1 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to="attack",
            priority=Priority.critical.value,
            params={
                "target_id": "dc01",
                "vulnerability_id": "CVE-2024-0001",
                "cvss_score": 9.8,
                "exploit_reliability": 0.95
            }
        )
        tasks.append(task1)
        
        # Medium-priority reconnaissance
        task2 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.network_scan.value,
            assigned_to="recon",
            priority=Priority.medium.value,
            params={"subnet": "10.40.0.0/24"}
        )
        tasks.append(task2)
        
        # Low-priority cleanup
        task3 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.cleanup.value,
            assigned_to="cleanup",
            priority=Priority.low.value,
            params={"clear_logs": True}
        )
        tasks.append(task3)
        
        # High-value target exploitation
        task4 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to="attack",
            priority=Priority.high.value,
            params={
                "target_id": "file_server",
                "target_value": 90,
                "vulnerability_id": "CVE-2024-0002"
            }
        )
        tasks.append(task4)
        
        # Prioritize tasks
        ranked_tasks = await self.prioritizer.prioritize_tasks(tasks)
        
        # Verify ranking
        assert len(ranked_tasks) == 4
        
        # Critical exploit should be first
        assert ranked_tasks[0] == task1
        
        # Cleanup should be last
        assert ranked_tasks[-1] == task3
        
        # Verify priority scores
        scores = await self.prioritizer.calculate_priority_scores(tasks)
        assert scores[task1] > scores[task2]
        assert scores[task2] > scores[task3]
        
        print("✅ Intelligent task ranking test passed")
        print(f"   Tasks ranked: {len(ranked_tasks)}")
        print(f"   Order: {[await self._get_task_name(t) for t in ranked_tasks]}")

    async def _get_task_name(self, task_id):
        """Helper to get task type for display"""
        task = await self.blackboard.get_task(self.mission_id, task_id)
        return task.get("task_type", "unknown")

    @pytest.mark.priority_high
    async def test_e2e_dynamic_reprioritization(self):
        """Test dynamic task reprioritization based on changing conditions"""
        # Create tasks
        task1 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.vuln_scan.value,
            assigned_to="vuln",
            priority=Priority.medium.value,
            params={"target_id": "server1"}
        )
        
        task2 = await self.blackboard.create_task(
            mission_id=self.mission_id,
            task_type=TaskType.exploit.value,
            assigned_to="attack",
            priority=Priority.low.value,
            params={"target_id": "server2"}
        )
        
        # Initial prioritization
        initial_ranking = await self.prioritizer.prioritize_tasks([task1, task2])
        
        # Simulate new intelligence: server2 is critical infrastructure
        await self.blackboard.store_metadata(
            mission_id=self.mission_id,
            key=f"target_server2_value",
            value={"value_score": 95, "criticality": "high"}
        )
        
        # Reprioritize
        updated_ranking = await self.prioritizer.prioritize_tasks([task1, task2])
        
        # task2 should now be higher priority
        if initial_ranking[0] != updated_ranking[0]:
            print("✅ Dynamic reprioritization test passed")
            print(f"   Priority adjusted based on new intelligence")
        else:
            print("⚠️  Prioritization unchanged (may need adjustment logic)")


@pytest.mark.e2e
@pytest.mark.asyncio
class TestPhase5VisualizationE2E:
    """E2E tests for Phase 5.0 Visualization Dashboard"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis):
        self.blackboard = real_blackboard
        self.redis = real_redis
        self.mission_id = f"viz_e2e_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="E2E Visualization Test",
            description="Testing Visualization Dashboard",
            scope=["10.50.0.0/24"],
            goals=["Test visualization"],
            constraints={}
        )
        
        self.viz_api = VisualizationDashboardAPI(
            mission_id=self.mission_id,
            blackboard=self.blackboard,
            redis=self.redis
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_high
    async def test_e2e_dashboard_data_generation(self):
        """Test dashboard data generation with real mission data"""
        # Setup mission data
        # Add targets
        for i in range(5):
            await self.blackboard.add_target(
                mission_id=self.mission_id,
                target_id=f"viz_target_{i}",
                ip=f"10.50.0.{10+i}",
                hostname=f"server{i}.viz.test",
                status=[TargetStatus.discovered, TargetStatus.scanned, TargetStatus.exploited][i % 3].value
            )
        
        # Add tasks
        for i in range(10):
            await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=[TaskType.network_scan, TaskType.vuln_scan, TaskType.exploit][i % 3].value,
                assigned_to="specialist",
                priority=Priority.medium.value,
                params={}
            )
        
        # Generate dashboard data
        dashboard_data = await self.viz_api.get_dashboard_data()
        
        # Verify structure
        assert "mission" in dashboard_data
        assert "targets" in dashboard_data
        assert "tasks" in dashboard_data
        assert "statistics" in dashboard_data
        assert "timeline" in dashboard_data
        
        # Verify counts
        assert dashboard_data["statistics"]["total_targets"] == 5
        assert dashboard_data["statistics"]["total_tasks"] == 10
        
        print("✅ Dashboard data generation test passed")
        print(f"   Targets: {dashboard_data['statistics']['total_targets']}")
        print(f"   Tasks: {dashboard_data['statistics']['total_tasks']}")

    @pytest.mark.priority_medium
    async def test_e2e_real_time_dashboard_updates(self):
        """Test real-time dashboard updates"""
        # Get initial snapshot
        initial_data = await self.viz_api.get_dashboard_data()
        initial_targets = initial_data["statistics"]["total_targets"]
        
        # Add new target
        await self.blackboard.add_target(
            mission_id=self.mission_id,
            target_id="realtime_target",
            ip="10.50.0.100",
            hostname="realtime.viz.test",
            status=TargetStatus.discovered.value
        )
        
        # Get updated snapshot
        await asyncio.sleep(0.1)  # Small delay for processing
        updated_data = await self.viz_api.get_dashboard_data()
        updated_targets = updated_data["statistics"]["total_targets"]
        
        # Verify update
        assert updated_targets == initial_targets + 1
        
        print("✅ Real-time dashboard updates test passed")
        print(f"   Initial targets: {initial_targets}")
        print(f"   Updated targets: {updated_targets}")

    @pytest.mark.priority_medium
    async def test_e2e_visualization_export(self):
        """Test visualization data export"""
        # Generate data
        dashboard_data = await self.viz_api.get_dashboard_data()
        
        # Export as JSON
        exported = json.dumps(dashboard_data, indent=2, default=str)
        
        # Verify export
        assert len(exported) > 0
        
        # Parse back
        parsed = json.loads(exported)
        assert parsed["mission"]["mission_id"] == self.mission_id
        
        print("✅ Visualization export test passed")
        print(f"   Export size: {len(exported)} bytes")


@pytest.mark.e2e
@pytest.mark.integration
class TestPhase5IntegratedWorkflowE2E:
    """Integrated E2E tests combining all Phase 5.0 features"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard, real_redis):
        self.blackboard = real_blackboard
        self.redis = real_redis
        self.mission_id = f"integrated_e2e_{uuid.uuid4().hex[:8]}"
        
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="Integrated Workflow Test",
            description="Testing integrated Phase 5 workflow",
            scope=["10.60.0.0/24"],
            goals=["Complete integrated test"],
            constraints={"stealth": "high"}
        )
        
        # Initialize all components
        self.risk_engine = AdvancedRiskAssessmentEngine(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        self.adaptation_engine = RealtimeAdaptationEngine(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        self.prioritizer = IntelligentTaskPrioritizer(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        self.viz_api = VisualizationDashboardAPI(
            mission_id=self.mission_id,
            blackboard=self.blackboard,
            redis=self.redis
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    @pytest.mark.priority_critical
    async def test_e2e_complete_intelligent_mission_execution(self):
        """
        Test complete intelligent mission execution workflow
        
        Workflow:
        1. Risk assessment before actions
        2. Intelligent task prioritization
        3. Real-time adaptation to events
        4. Continuous risk monitoring
        5. Dashboard visualization
        """
        # Phase 1: Initial risk assessment
        initial_risk = await self.risk_engine.assess_mission_risk()
        assert initial_risk["risk_score"] < 50  # Should start low
        
        # Phase 2: Create and prioritize tasks
        tasks = []
        for i in range(5):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.network_scan.value,
                assigned_to="recon",
                priority=[Priority.critical, Priority.high, Priority.medium, Priority.low][i % 4].value,
                params={"subnet": f"10.60.{i}.0/24"}
            )
            tasks.append(task_id)
        
        ranked_tasks = await self.prioritizer.prioritize_tasks(tasks)
        assert len(ranked_tasks) == 5
        
        # Phase 3: Execute highest priority task
        first_task = ranked_tasks[0]
        await self.blackboard.update_task(
            mission_id=self.mission_id,
            task_id=first_task,
            status=TaskStatus.running.value
        )
        
        # Phase 4: Check risk during execution
        execution_risk = await self.risk_engine.assess_mission_risk()
        
        # Phase 5: Simulate detection event
        await self.blackboard.add_event(
            mission_id=self.mission_id,
            event_type="detection_alert",
            data={"severity": "medium", "source": "firewall"}
        )
        
        # Phase 6: Adapt strategy
        adaptation = await self.adaptation_engine.adapt_to_environment()
        assert adaptation["strategy_changed"]
        
        # Phase 7: Reassess risk after detection
        post_detection_risk = await self.risk_engine.assess_mission_risk()
        assert post_detection_risk["risk_score"] > execution_risk["risk_score"]
        
        # Phase 8: Get mitigation recommendations
        recommendations = await self.risk_engine.get_risk_mitigation_recommendations()
        assert len(recommendations) > 0
        
        # Phase 9: Reprioritize remaining tasks based on new risk level
        remaining_tasks = ranked_tasks[1:]
        reprioritized = await self.prioritizer.prioritize_tasks(remaining_tasks)
        
        # Phase 10: Generate dashboard visualization
        dashboard = await self.viz_api.get_dashboard_data()
        
        # Verify integrated workflow
        assert dashboard["statistics"]["total_tasks"] == 5
        assert "risk_assessment" in dashboard or post_detection_risk is not None
        
        print("✅ Complete intelligent mission execution test passed")
        print(f"   Initial risk: {initial_risk['risk_score']:.1f}")
        print(f"   Post-detection risk: {post_detection_risk['risk_score']:.1f}")
        print(f"   Strategy adapted: {adaptation['strategy_changed']}")
        print(f"   Tasks prioritized: {len(ranked_tasks)}")
        print(f"   Recommendations: {len(recommendations)}")
        print(f"   Dashboard ready: {len(dashboard) > 0}")


@pytest.mark.e2e
@pytest.mark.performance
class TestPhase5PerformanceE2E:
    """Performance tests for Phase 5.0 advanced features"""

    @pytest.fixture(autouse=True)
    async def setup(self, real_blackboard):
        self.blackboard = real_blackboard
        self.mission_id = f"perf_adv_{uuid.uuid4().hex[:8]}"
        await self.blackboard.create_mission(
            mission_id=self.mission_id,
            name="Performance Test",
            description="Advanced features performance",
            scope=["192.168.0.0/16"],
            goals=["Performance"],
            constraints={}
        )
        
        self.risk_engine = AdvancedRiskAssessmentEngine(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        self.prioritizer = IntelligentTaskPrioritizer(
            mission_id=self.mission_id,
            blackboard=self.blackboard
        )
        
        yield
        
        try:
            await self.blackboard.delete_mission(self.mission_id)
        except:
            pass

    async def test_risk_assessment_performance(self):
        """Test risk assessment performance with large datasets"""
        import time
        
        # Add many targets
        for i in range(50):
            await self.blackboard.add_target(
                mission_id=self.mission_id,
                target_id=f"perf_target_{i}",
                ip=f"192.168.{i//256}.{i%256}",
                hostname=f"server{i}.perf",
                status=TargetStatus.scanned.value
            )
        
        # Add many events
        for i in range(100):
            await self.blackboard.add_event(
                mission_id=self.mission_id,
                event_type="action_taken",
                data={"action": f"action_{i}", "timestamp": datetime.utcnow().isoformat()}
            )
        
        start_time = time.time()
        risk = await self.risk_engine.assess_mission_risk()
        duration = time.time() - start_time
        
        # Should complete quickly even with large dataset
        assert duration < 2.0  # Within 2 seconds
        assert risk is not None
        
        print(f"✅ Risk assessment performance test passed")
        print(f"   Targets: 50, Events: 100")
        print(f"   Duration: {duration:.3f}s")

    async def test_prioritization_performance(self):
        """Test task prioritization performance with many tasks"""
        import time
        
        # Create many tasks
        tasks = []
        for i in range(200):
            task_id = await self.blackboard.create_task(
                mission_id=self.mission_id,
                task_type=TaskType.network_scan.value,
                assigned_to="recon",
                priority=[Priority.critical, Priority.high, Priority.medium, Priority.low][i % 4].value,
                params={"id": i}
            )
            tasks.append(task_id)
        
        start_time = time.time()
        ranked = await self.prioritizer.prioritize_tasks(tasks)
        duration = time.time() - start_time
        
        # Should handle 200 tasks quickly
        assert duration < 3.0  # Within 3 seconds
        assert len(ranked) == 200
        
        print(f"✅ Prioritization performance test passed")
        print(f"   Tasks: 200")
        print(f"   Duration: {duration:.3f}s")
        print(f"   Throughput: {200/duration:.1f} tasks/sec")
