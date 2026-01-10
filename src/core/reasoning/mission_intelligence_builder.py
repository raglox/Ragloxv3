# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mission Intelligence Builder
# Phase 3.0: Automated Intelligence Collection and Analysis
# ═══════════════════════════════════════════════════════════════

"""
Mission Intelligence Builder for RAGLOX v3.0

This module provides automated intelligence collection from the Blackboard
and specialists, building a comprehensive MissionIntelligence object.

Key Functions:
- collect_recon_intelligence(): Gather data from recon specialists
- analyze_vulnerability_scan(): Process vulnerability scan results
- extract_exploitation_data(): Collect post-exploitation intelligence
- build_attack_graph(): Create attack path analysis
- generate_recommendations(): Produce tactical recommendations

Architecture:
┌─────────────────────────────────────────────────────────────┐
│            MissionIntelligenceBuilder                       │
│                                                             │
│  collect_recon_intelligence()                               │
│         │                                                   │
│         ▼                                                   │
│  ┌───────────────┐                                         │
│  │  Blackboard   │  ──→  TargetIntel                      │
│  │    Targets    │  ──→  NetworkMap                       │
│  └───────────────┘                                         │
│                                                             │
│  analyze_vulnerability_scan()                               │
│         │                                                   │
│         ▼                                                   │
│  ┌───────────────┐                                         │
│  │  Blackboard   │  ──→  VulnerabilityIntel              │
│  │Vulnerabilities│  ──→  AttackSurfaceAnalysis           │
│  └───────────────┘                                         │
│                                                             │
│  extract_exploitation_data()                                │
│         │                                                   │
│         ▼                                                   │
│  ┌───────────────┐                                         │
│  │  Blackboard   │  ──→  CredentialIntel                 │
│  │Sessions/Creds │  ──→  Update TargetIntel              │
│  └───────────────┘                                         │
│                                                             │
│  generate_recommendations()                                 │
│         │                                                   │
│         ▼                                                   │
│  ┌───────────────┐                                         │
│  │ TacticalEngine│  ──→  TacticRecommendation            │
│  │+ HybridRetrie │                                         │
│  └───────────────┘                                         │
└─────────────────────────────────────────────────────────────┘

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from ..blackboard import Blackboard
    from ..hybrid_retriever import HybridKnowledgeRetriever
    from .tactical_reasoning import TacticalReasoningEngine

from .mission_intelligence import (
    MissionIntelligence,
    TargetIntel,
    VulnerabilityIntel,
    CredentialIntel,
    NetworkMap,
    NetworkSegment,
    AttackSurfaceAnalysis,
    TacticRecommendation,
    IntelConfidence,
    AttackVectorType,
    DefenseType,
)

logger = logging.getLogger("raglox.core.mission_intelligence_builder")


# ═══════════════════════════════════════════════════════════════
# Mission Intelligence Builder
# ═══════════════════════════════════════════════════════════════

class MissionIntelligenceBuilder:
    """
    Automated Mission Intelligence Builder.
    
    Collects and processes intelligence from Blackboard and specialists,
    building a comprehensive MissionIntelligence object for tactical reasoning.
    
    Usage:
        builder = MissionIntelligenceBuilder(
            mission_id="mission-123",
            blackboard=bb,
            knowledge_retriever=retriever
        )
        
        # Collect intelligence
        await builder.collect_recon_intelligence()
        await builder.analyze_vulnerability_scan()
        await builder.extract_exploitation_data()
        
        # Generate recommendations
        await builder.generate_recommendations()
        
        # Get final intelligence
        intel = builder.get_intelligence()
    """
    
    def __init__(
        self,
        mission_id: str,
        blackboard: "Blackboard",
        knowledge_retriever: Optional["HybridKnowledgeRetriever"] = None,
        tactical_engine: Optional["TacticalReasoningEngine"] = None,
    ):
        """
        Initialize Intelligence Builder.
        
        Args:
            mission_id: Mission ID
            blackboard: Blackboard instance for data access
            knowledge_retriever: HybridKnowledgeRetriever for knowledge queries
            tactical_engine: TacticalReasoningEngine for recommendations
        """
        self.mission_id = mission_id
        self.blackboard = blackboard
        self.knowledge_retriever = knowledge_retriever
        self.tactical_engine = tactical_engine
        
        # Initialize intelligence object
        self.intelligence = MissionIntelligence(mission_id=mission_id)
        
        logger.info(f"Initialized MissionIntelligenceBuilder for mission {mission_id}")
    
    # ═══════════════════════════════════════════════════════════════
    # Reconnaissance Intelligence Collection
    # ═══════════════════════════════════════════════════════════════
    
    async def collect_recon_intelligence(self) -> int:
        """
        Collect reconnaissance intelligence from Blackboard.
        
        Gathers:
        - Discovered targets
        - Network topology
        - Service enumeration data
        - OS fingerprinting results
        
        Returns:
            Number of targets collected
        """
        logger.info(f"Collecting recon intelligence for mission {self.mission_id}")
        
        try:
            # Get all targets from Blackboard
            targets_data = await self.blackboard.get_all_targets(self.mission_id)
            
            collected_count = 0
            for target_data in targets_data:
                target_intel = await self._process_target_data(target_data)
                if target_intel:
                    self.intelligence.add_target(target_intel)
                    collected_count += 1
            
            # Build network topology
            await self._build_network_topology()
            
            logger.info(f"Collected {collected_count} targets for mission {self.mission_id}")
            return collected_count
            
        except Exception as e:
            logger.error(f"Failed to collect recon intelligence: {e}", exc_info=True)
            return 0
    
    async def _process_target_data(self, target_data: Dict[str, Any]) -> Optional[TargetIntel]:
        """
        Process raw target data into TargetIntel.
        
        Args:
            target_data: Raw target data from Blackboard
            
        Returns:
            TargetIntel object or None if processing fails
        """
        try:
            # Extract basic info
            target_id = str(target_data.get("id", ""))
            ip = target_data.get("ip", "")
            
            if not target_id or not ip:
                logger.warning(f"Invalid target data: missing id or ip")
                return None
            
            # Build TargetIntel
            target_intel = TargetIntel(
                target_id=target_id,
                ip=ip,
                hostname=target_data.get("hostname"),
                discovered_at=target_data.get("created_at", datetime.utcnow()),
                discovered_by=target_data.get("discovered_by", "recon"),
                confidence=IntelConfidence.CONFIRMED,
                
                # Technical details
                os=target_data.get("os"),
                os_version=target_data.get("os_version"),
                open_ports=target_data.get("open_ports", []),
                services=target_data.get("services", []),
                
                # Network
                subnet=target_data.get("subnet"),
                
                # Status
                is_compromised=(target_data.get("status") == "exploited" or 
                              target_data.get("status") == "owned"),
                
                # Metadata
                metadata=target_data.get("metadata", {}),
            )
            
            return target_intel
            
        except Exception as e:
            logger.error(f"Failed to process target data: {e}", exc_info=True)
            return None
    
    async def _build_network_topology(self) -> None:
        """Build network topology from discovered targets."""
        try:
            targets = self.intelligence.get_all_targets()
            
            if not targets:
                logger.debug("No targets available for network topology")
                return
            
            # Group by subnet
            subnet_map: Dict[str, List[str]] = {}
            for target in targets:
                if target.subnet:
                    if target.subnet not in subnet_map:
                        subnet_map[target.subnet] = []
                    subnet_map[target.subnet].append(target.ip)
            
            # Create NetworkSegments
            segments = []
            for subnet, hosts in subnet_map.items():
                segment = NetworkSegment(
                    subnet=subnet,
                    hosts=hosts,
                    security_zone="unknown",  # Can be enhanced with more analysis
                )
                segments.append(segment)
            
            # Create NetworkMap
            network_map = NetworkMap(
                mission_id=self.mission_id,
                segments=segments,
                total_hosts=len(targets),
                total_subnets=len(segments),
            )
            
            self.intelligence.network_topology = network_map
            logger.debug(f"Built network topology: {len(segments)} subnets, {len(targets)} hosts")
            
        except Exception as e:
            logger.error(f"Failed to build network topology: {e}", exc_info=True)
    
    # ═══════════════════════════════════════════════════════════════
    # Vulnerability Analysis
    # ═══════════════════════════════════════════════════════════════
    
    async def analyze_vulnerability_scan(self) -> int:
        """
        Analyze vulnerability scan results from Blackboard.
        
        Gathers:
        - Discovered vulnerabilities
        - CVE details
        - Exploit availability
        - Risk assessment
        
        Returns:
            Number of vulnerabilities collected
        """
        logger.info(f"Analyzing vulnerabilities for mission {self.mission_id}")
        
        try:
            # Get all vulnerabilities from Blackboard
            vulns_data = await self.blackboard.get_all_vulnerabilities(self.mission_id)
            
            collected_count = 0
            for vuln_data in vulns_data:
                vuln_intel = await self._process_vulnerability_data(vuln_data)
                if vuln_intel:
                    self.intelligence.add_vulnerability(vuln_intel)
                    
                    # Update target intelligence with vulnerability reference
                    target = self.intelligence.get_target(vuln_intel.target_id)
                    if target:
                        if vuln_intel.vuln_id not in target.vulnerabilities:
                            target.vulnerabilities.append(vuln_intel.vuln_id)
                    
                    collected_count += 1
            
            # Build attack surface analysis
            await self._build_attack_surface_analysis()
            
            logger.info(f"Analyzed {collected_count} vulnerabilities for mission {self.mission_id}")
            return collected_count
            
        except Exception as e:
            logger.error(f"Failed to analyze vulnerabilities: {e}", exc_info=True)
            return 0
    
    async def _process_vulnerability_data(self, vuln_data: Dict[str, Any]) -> Optional[VulnerabilityIntel]:
        """
        Process raw vulnerability data into VulnerabilityIntel.
        
        Args:
            vuln_data: Raw vulnerability data from Blackboard
            
        Returns:
            VulnerabilityIntel object or None if processing fails
        """
        try:
            vuln_id = vuln_data.get("cve_id") or vuln_data.get("id") or f"vuln-{uuid4()}"
            target_id = str(vuln_data.get("target_id", ""))
            
            if not target_id:
                logger.warning(f"Invalid vulnerability data: missing target_id")
                return None
            
            # Check for exploit availability using knowledge retriever
            exploit_available = False
            exploit_ids = []
            if self.knowledge_retriever and vuln_id.startswith("CVE"):
                try:
                    # Query knowledge base for exploit modules
                    results = await self.knowledge_retriever.search(
                        f"exploit module for {vuln_id}",
                        limit=3
                    )
                    if results and results.results:
                        exploit_available = True
                        for r in results.results:
                            if "module" in r:
                                exploit_ids.append(r["module"])
                except Exception as e:
                    logger.debug(f"Failed to query exploits for {vuln_id}: {e}")
            
            vuln_intel = VulnerabilityIntel(
                vuln_id=vuln_id,
                target_id=target_id,
                discovered_at=vuln_data.get("created_at", datetime.utcnow()),
                discovered_by=vuln_data.get("discovered_by", "vuln_scan"),
                confidence=IntelConfidence.CONFIRMED,
                
                # Vulnerability details
                name=vuln_data.get("name", vuln_id),
                description=vuln_data.get("description", ""),
                severity=vuln_data.get("severity", "medium"),
                cvss_score=vuln_data.get("cvss_score"),
                
                # Exploitation
                is_exploitable=vuln_data.get("is_exploitable", exploit_available),
                exploit_available=exploit_available,
                exploit_ids=exploit_ids,
                exploit_complexity=vuln_data.get("exploit_complexity", "unknown"),
                
                # Context
                affected_service=vuln_data.get("service"),
                affected_port=vuln_data.get("port"),
                prerequisites=vuln_data.get("prerequisites", []),
                
                # References
                references=vuln_data.get("references", []),
                metadata=vuln_data.get("metadata", {}),
            )
            
            return vuln_intel
            
        except Exception as e:
            logger.error(f"Failed to process vulnerability data: {e}", exc_info=True)
            return None
    
    async def _build_attack_surface_analysis(self) -> None:
        """Build attack surface analysis from targets and vulnerabilities."""
        try:
            targets = self.intelligence.get_all_targets()
            vulnerabilities = self.intelligence.vulnerabilities.values()
            
            if not targets:
                logger.debug("No targets available for attack surface analysis")
                return
            
            # Identify entry points (targets with exploitable vulns)
            entry_points = []
            for target in targets:
                target_vulns = self.intelligence.get_vulnerabilities_by_target(target.target_id)
                exploitable_vulns = [v for v in target_vulns if v.is_exploitable]
                
                if exploitable_vulns:
                    for vuln in exploitable_vulns:
                        entry_point = {
                            "target_id": target.target_id,
                            "ip": target.ip,
                            "port": vuln.affected_port,
                            "service": vuln.affected_service,
                            "attack_vector": AttackVectorType.NETWORK.value,
                            "risk_score": self._calculate_risk_score(vuln),
                            "vuln_id": vuln.vuln_id,
                        }
                        entry_points.append(entry_point)
            
            # Sort by risk score
            entry_points.sort(key=lambda x: x["risk_score"], reverse=True)
            
            # Identify high-value targets
            high_value_targets = [t.target_id for t in self.intelligence.get_high_value_targets()]
            
            # Identify low-hanging fruit (easy wins)
            low_hanging_fruit = []
            for target in targets:
                if not target.is_compromised:
                    target_vulns = self.intelligence.get_vulnerabilities_by_target(target.target_id)
                    easy_vulns = [v for v in target_vulns 
                                if v.is_exploitable and v.exploit_complexity == "low"]
                    if easy_vulns:
                        low_hanging_fruit.append(target.target_id)
            
            # Calculate overall risk score (average of top entry points)
            overall_risk = 0.0
            if entry_points:
                top_risks = [ep["risk_score"] for ep in entry_points[:5]]
                overall_risk = sum(top_risks) / len(top_risks)
            
            # Create AttackSurfaceAnalysis
            attack_surface = AttackSurfaceAnalysis(
                mission_id=self.mission_id,
                entry_points=entry_points,
                available_vectors=[AttackVectorType.NETWORK],  # Can be expanded
                recommended_vector=AttackVectorType.NETWORK if entry_points else None,
                overall_risk_score=overall_risk,
                high_value_targets=high_value_targets,
                low_hanging_fruit=low_hanging_fruit,
                detected_defenses=[],  # Can be populated from target metadata
                security_gaps=[],      # Can be identified through analysis
                confidence=IntelConfidence.HIGH,
            )
            
            self.intelligence.attack_surface = attack_surface
            logger.debug(f"Built attack surface analysis: {len(entry_points)} entry points, "
                        f"risk score {overall_risk:.2f}")
            
        except Exception as e:
            logger.error(f"Failed to build attack surface analysis: {e}", exc_info=True)
    
    def _calculate_risk_score(self, vuln: VulnerabilityIntel) -> float:
        """
        Calculate risk score for a vulnerability.
        
        Factors:
        - Severity (critical=10, high=7, medium=5, low=3)
        - Exploitability (has exploit=+2, low complexity=+1)
        - CVSS score (if available)
        
        Returns:
            Risk score (0-10)
        """
        score = 0.0
        
        # Base score from severity
        severity_scores = {"critical": 10, "high": 7, "medium": 5, "low": 3, "info": 1}
        score = severity_scores.get(vuln.severity, 5)
        
        # Bonus for exploit availability
        if vuln.exploit_available:
            score += 2
        
        # Bonus for low complexity
        if vuln.exploit_complexity == "low":
            score += 1
        
        # Use CVSS if available
        if vuln.cvss_score:
            score = max(score, vuln.cvss_score)
        
        return min(score, 10.0)  # Cap at 10
    
    # ═══════════════════════════════════════════════════════════════
    # Post-Exploitation Intelligence
    # ═══════════════════════════════════════════════════════════════
    
    async def extract_exploitation_data(self) -> Dict[str, int]:
        """
        Extract post-exploitation intelligence from Blackboard.
        
        Gathers:
        - Active sessions
        - Discovered credentials
        - Privilege escalation status
        - Lateral movement paths
        
        Returns:
            Dict with counts: {"sessions": N, "credentials": M}
        """
        logger.info(f"Extracting exploitation data for mission {self.mission_id}")
        
        try:
            # Get sessions
            sessions_data = await self.blackboard.get_all_sessions(self.mission_id)
            sessions_count = 0
            
            for session_data in sessions_data:
                target_id = str(session_data.get("target_id", ""))
                if target_id:
                    # Mark target as compromised
                    target = self.intelligence.get_target(target_id)
                    if target:
                        target.is_compromised = True
                        target.compromise_time = session_data.get("created_at", datetime.utcnow())
                        target.active_sessions += 1
                        sessions_count += 1
            
            # Get credentials
            creds_data = await self.blackboard.get_all_credentials(self.mission_id)
            creds_count = 0
            
            for cred_data in creds_data:
                cred_intel = await self._process_credential_data(cred_data)
                if cred_intel:
                    self.intelligence.add_credential(cred_intel)
                    creds_count += 1
            
            logger.info(f"Extracted exploitation data: {sessions_count} sessions, {creds_count} credentials")
            return {"sessions": sessions_count, "credentials": creds_count}
            
        except Exception as e:
            logger.error(f"Failed to extract exploitation data: {e}", exc_info=True)
            return {"sessions": 0, "credentials": 0}
    
    async def _process_credential_data(self, cred_data: Dict[str, Any]) -> Optional[CredentialIntel]:
        """
        Process raw credential data into CredentialIntel.
        
        Args:
            cred_data: Raw credential data from Blackboard
            
        Returns:
            CredentialIntel object or None if processing fails
        """
        try:
            cred_id = cred_data.get("id") or f"cred-{uuid4()}"
            
            # Determine privilege level
            privilege_level = cred_data.get("privilege_level", "user")
            is_privileged = privilege_level in ["admin", "system", "root", "domain_admin"]
            
            cred_intel = CredentialIntel(
                cred_id=cred_id,
                discovered_at=cred_data.get("created_at", datetime.utcnow()),
                discovered_by=cred_data.get("discovered_by", "credential_harvest"),
                source_target=cred_data.get("source_target"),
                confidence=IntelConfidence.CONFIRMED,
                
                # Credential details
                username=cred_data.get("username"),
                password=cred_data.get("password"),  # Should be encrypted
                hash_value=cred_data.get("hash"),
                hash_type=cred_data.get("hash_type"),
                
                # Type & context
                credential_type=cred_data.get("type", "password"),
                domain=cred_data.get("domain"),
                service=cred_data.get("service"),
                
                # Privilege
                privilege_level=privilege_level,
                is_privileged=is_privileged,
                
                # Validation
                is_valid=cred_data.get("is_valid"),
                last_validated=cred_data.get("last_validated"),
                
                # Metadata
                metadata=cred_data.get("metadata", {}),
            )
            
            return cred_intel
            
        except Exception as e:
            logger.error(f"Failed to process credential data: {e}", exc_info=True)
            return None
    
    # ═══════════════════════════════════════════════════════════════
    # Attack Graph & Path Analysis
    # ═══════════════════════════════════════════════════════════════
    
    async def build_attack_graph(self) -> Dict[str, Any]:
        """
        Build attack graph showing possible paths to goals.
        
        Analyzes:
        - Current compromised state
        - Available attack vectors
        - Lateral movement possibilities
        - Path to high-value targets
        
        Returns:
            Dict describing the attack graph
        """
        logger.info(f"Building attack graph for mission {self.mission_id}")
        
        try:
            compromised = self.intelligence.get_compromised_targets()
            uncompromised = self.intelligence.get_uncompromised_targets()
            high_value = self.intelligence.get_high_value_targets()
            
            # Build graph structure
            attack_graph = {
                "mission_id": self.mission_id,
                "current_foothold": [t.target_id for t in compromised],
                "potential_targets": [t.target_id for t in uncompromised],
                "high_value_targets": [t.target_id for t in high_value],
                "lateral_paths": [],
                "escalation_paths": [],
            }
            
            # Identify lateral movement paths
            for comp_target in compromised:
                # Check neighboring hosts
                for neighbor_ip in comp_target.neighboring_hosts:
                    # Find corresponding target
                    neighbor = next((t for t in uncompromised if t.ip == neighbor_ip), None)
                    if neighbor:
                        attack_graph["lateral_paths"].append({
                            "from": comp_target.target_id,
                            "to": neighbor.target_id,
                            "method": "network_proximity",
                        })
                
                # Check credential reuse
                for cred in self.intelligence.get_valid_credentials():
                    if cred.source_target == comp_target.target_id:
                        # This credential could be reused on other targets
                        for target in uncompromised:
                            attack_graph["lateral_paths"].append({
                                "from": comp_target.target_id,
                                "to": target.target_id,
                                "method": "credential_reuse",
                                "cred_id": cred.cred_id,
                            })
            
            logger.debug(f"Built attack graph with {len(attack_graph['lateral_paths'])} lateral paths")
            return attack_graph
            
        except Exception as e:
            logger.error(f"Failed to build attack graph: {e}", exc_info=True)
            return {"error": str(e)}
    
    # ═══════════════════════════════════════════════════════════════
    # Tactical Recommendations
    # ═══════════════════════════════════════════════════════════════
    
    async def generate_recommendations(self, limit: int = 10) -> int:
        """
        Generate tactical recommendations based on intelligence.
        
        Uses:
        - Attack surface analysis
        - Attack graph
        - Tactical reasoning engine (if available)
        - Knowledge retriever (if available)
        
        Args:
            limit: Maximum number of recommendations to generate
            
        Returns:
            Number of recommendations generated
        """
        logger.info(f"Generating tactical recommendations for mission {self.mission_id}")
        
        try:
            recommendations = []
            
            # Strategy 1: Exploit low-hanging fruit
            if self.intelligence.attack_surface:
                for target_id in self.intelligence.attack_surface.low_hanging_fruit[:3]:
                    target = self.intelligence.get_target(target_id)
                    if target:
                        target_vulns = self.intelligence.get_vulnerabilities_by_target(target_id)
                        easy_vulns = [v for v in target_vulns 
                                    if v.is_exploitable and v.exploit_complexity == "low"]
                        
                        if easy_vulns:
                            vuln = easy_vulns[0]
                            rec = TacticRecommendation(
                                recommendation_id=f"rec-{uuid4()}",
                                mission_id=self.mission_id,
                                action=f"exploit {vuln.vuln_id} on {target.ip}",
                                target_id=target_id,
                                rationale=f"Low complexity exploit available for {vuln.name}",
                                expected_outcome=f"Initial access to {target.ip}",
                                success_probability=0.7,
                                priority="high",
                                urgency="normal",
                                risk_level="low",
                                stealth_impact="medium",
                                mitre_tactic="Initial Access",
                                confidence=IntelConfidence.HIGH,
                            )
                            recommendations.append(rec)
            
            # Strategy 2: Pivot from compromised targets
            compromised = self.intelligence.get_compromised_targets()
            for comp_target in compromised[:2]:
                if comp_target.neighboring_hosts:
                    neighbor_ip = comp_target.neighboring_hosts[0]
                    rec = TacticRecommendation(
                        recommendation_id=f"rec-{uuid4()}",
                        mission_id=self.mission_id,
                        action=f"lateral move from {comp_target.ip} to {neighbor_ip}",
                        target_id=comp_target.target_id,
                        rationale=f"Network proximity to {neighbor_ip}",
                        expected_outcome=f"Lateral movement to {neighbor_ip}",
                        success_probability=0.6,
                        priority="medium",
                        urgency="normal",
                        risk_level="medium",
                        stealth_impact="medium",
                        mitre_tactic="Lateral Movement",
                        confidence=IntelConfidence.MEDIUM,
                    )
                    recommendations.append(rec)
            
            # Strategy 3: Privilege escalation
            for target in compromised:
                # Check for privesc vulnerabilities
                target_vulns = self.intelligence.get_vulnerabilities_by_target(target.target_id)
                privesc_vulns = [v for v in target_vulns if "privilege" in v.name.lower() or "escalation" in v.name.lower()]
                
                if privesc_vulns:
                    vuln = privesc_vulns[0]
                    rec = TacticRecommendation(
                        recommendation_id=f"rec-{uuid4()}",
                        mission_id=self.mission_id,
                        action=f"privilege escalation on {target.ip} using {vuln.vuln_id}",
                        target_id=target.target_id,
                        rationale=f"Privilege escalation vulnerability available",
                        expected_outcome=f"Elevated privileges on {target.ip}",
                        success_probability=0.65,
                        priority="high",
                        urgency="normal",
                        risk_level="medium",
                        stealth_impact="low",
                        mitre_tactic="Privilege Escalation",
                        confidence=IntelConfidence.MEDIUM,
                    )
                    recommendations.append(rec)
            
            # Strategy 4: Target high-value targets
            if self.intelligence.attack_surface:
                for target_id in self.intelligence.attack_surface.high_value_targets[:2]:
                    if target_id not in [t.target_id for t in compromised]:
                        target = self.intelligence.get_target(target_id)
                        if target:
                            rec = TacticRecommendation(
                                recommendation_id=f"rec-{uuid4()}",
                                mission_id=self.mission_id,
                                action=f"target high-value host {target.ip}",
                                target_id=target_id,
                                rationale=f"High-value target with critical vulnerabilities",
                                expected_outcome=f"Compromise high-value target",
                                success_probability=0.55,
                                priority="critical",
                                urgency="high",
                                risk_level="high",
                                stealth_impact="high",
                                mitre_tactic="Initial Access",
                                confidence=IntelConfidence.MEDIUM,
                            )
                            recommendations.append(rec)
            
            # Add recommendations to intelligence
            for rec in recommendations[:limit]:
                self.intelligence.add_recommendation(rec)
            
            logger.info(f"Generated {len(recommendations[:limit])} tactical recommendations")
            return len(recommendations[:limit])
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}", exc_info=True)
            return 0
    
    # ═══════════════════════════════════════════════════════════════
    # Full Intelligence Build Pipeline
    # ═══════════════════════════════════════════════════════════════
    
    async def build_full_intelligence(self) -> MissionIntelligence:
        """
        Execute full intelligence collection pipeline.
        
        Steps:
        1. Collect recon intelligence
        2. Analyze vulnerabilities
        3. Extract exploitation data
        4. Build attack graph
        5. Generate recommendations
        
        Returns:
            Complete MissionIntelligence object
        """
        logger.info(f"Building full intelligence for mission {self.mission_id}")
        
        start_time = datetime.utcnow()
        
        try:
            # Step 1: Recon
            targets_count = await self.collect_recon_intelligence()
            logger.debug(f"Step 1/5: Collected {targets_count} targets")
            
            # Step 2: Vulnerabilities
            vulns_count = await self.analyze_vulnerability_scan()
            logger.debug(f"Step 2/5: Analyzed {vulns_count} vulnerabilities")
            
            # Step 3: Exploitation data
            exploit_data = await self.extract_exploitation_data()
            logger.debug(f"Step 3/5: Extracted {exploit_data['sessions']} sessions, "
                        f"{exploit_data['credentials']} credentials")
            
            # Step 4: Attack graph
            attack_graph = await self.build_attack_graph()
            logger.debug(f"Step 4/5: Built attack graph")
            
            # Step 5: Recommendations
            recs_count = await self.generate_recommendations(limit=10)
            logger.debug(f"Step 5/5: Generated {recs_count} recommendations")
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Full intelligence built in {duration:.2f}s: "
                       f"{targets_count} targets, {vulns_count} vulns, {recs_count} recs")
            
            return self.intelligence
            
        except Exception as e:
            logger.error(f"Failed to build full intelligence: {e}", exc_info=True)
            return self.intelligence
    
    # ═══════════════════════════════════════════════════════════════
    # Getters
    # ═══════════════════════════════════════════════════════════════
    
    def get_intelligence(self) -> MissionIntelligence:
        """Get the current MissionIntelligence object."""
        return self.intelligence
    
    def get_intelligence_summary(self) -> Dict[str, Any]:
        """Get intelligence summary."""
        return self.intelligence.get_attack_summary()
