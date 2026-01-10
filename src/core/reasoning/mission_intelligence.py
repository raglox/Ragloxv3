# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mission Intelligence System
# Phase 3.0: Mission-specific Intelligence Collection and Analysis
# ═══════════════════════════════════════════════════════════════

"""
Mission Intelligence System for RAGLOX v3.0

This module provides mission-specific intelligence collection, aggregation,
and analysis. Unlike the global knowledge base, MissionIntelligence is
dynamically built from discovered data during mission execution.

Key Concepts:
- Mission-Specific: Each mission has its own intelligence database
- Real-Time: Updated as specialists discover new information
- Actionable: Drives tactical decisions and specialist coordination
- Comprehensive: Aggregates targets, vulns, credentials, network topology

Architecture:
┌─────────────────────────────────────────────────────────────┐
│                  MissionIntelligence                        │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │TargetIntel   │  │VulnIntel     │  │CredIntel     │     │
│  │- IP/hostname │  │- CVEs        │  │- Usernames   │     │
│  │- Services    │  │- Severity    │  │- Passwords   │     │
│  │- OS info     │  │- Exploits    │  │- Privilege   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │NetworkMap    │  │AttackSurface │  │Tactics       │     │
│  │- Topology    │  │- Entry points│  │- Recommended │     │
│  │- Routing     │  │- Risk score  │  │- Priority    │     │
│  │- Subnets     │  │- Defense     │  │- Paths       │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘

Author: RAGLOX Team
Version: 3.0.0
Date: 2026-01-09
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

logger = logging.getLogger("raglox.core.mission_intelligence")


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class IntelConfidence(Enum):
    """Confidence level of intelligence."""
    CONFIRMED = "confirmed"       # Verified by specialist
    HIGH = "high"                 # Strong evidence
    MEDIUM = "medium"             # Moderate evidence
    LOW = "low"                   # Weak/unverified evidence
    UNVERIFIED = "unverified"     # Needs verification


class AttackVectorType(Enum):
    """Types of attack vectors."""
    NETWORK = "network"           # Network-based exploit
    WEB = "web"                   # Web application
    PHISHING = "phishing"         # Social engineering
    PHYSICAL = "physical"         # Physical access
    SUPPLY_CHAIN = "supply_chain" # Third-party compromise
    INSIDER = "insider"           # Insider threat


class DefenseType(Enum):
    """Types of detected defenses."""
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    EDR = "edr"
    WAF = "waf"
    ANTIVIRUS = "antivirus"
    SIEM = "siem"
    HONEYPOT = "honeypot"
    RATE_LIMITING = "rate_limiting"


# ═══════════════════════════════════════════════════════════════
# Intelligence Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class TargetIntel:
    """
    Intelligence about a specific target.
    
    Aggregates all discovered information about a target machine.
    """
    # Identity
    target_id: str
    ip: str
    hostname: Optional[str] = None
    
    # Discovery
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_by: str = "recon"  # Specialist that found it
    confidence: IntelConfidence = IntelConfidence.CONFIRMED
    
    # Technical Details
    os: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: List[Dict[str, Any]] = field(default_factory=list)  # [{port, protocol, service, version}]
    services: List[Dict[str, Any]] = field(default_factory=list)    # [{name, version, banner}]
    
    # Security Posture
    vulnerabilities: List[str] = field(default_factory=list)  # List of vulnerability IDs
    security_products: List[str] = field(default_factory=list)  # EDR, AV, etc.
    hardening_level: str = "unknown"  # low, medium, high, unknown
    
    # Network Intelligence
    subnet: Optional[str] = None
    gateway: Optional[str] = None
    neighboring_hosts: List[str] = field(default_factory=list)
    
    # Status
    is_compromised: bool = False
    compromise_time: Optional[datetime] = None
    active_sessions: int = 0
    
    # Metadata
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityIntel:
    """
    Intelligence about a discovered vulnerability.
    
    Combines CVE data with mission-specific context.
    """
    # Identity
    vuln_id: str  # CVE-XXXX-XXXX or internal ID
    target_id: str
    
    # Discovery
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_by: str = "vuln_scan"
    confidence: IntelConfidence = IntelConfidence.CONFIRMED
    
    # Vulnerability Details
    name: str = ""
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    
    # Exploitation
    is_exploitable: bool = False
    exploit_available: bool = False
    exploit_ids: List[str] = field(default_factory=list)  # EDB IDs, Metasploit modules
    exploit_complexity: str = "unknown"  # low, medium, high
    
    # Context
    affected_service: Optional[str] = None
    affected_port: Optional[int] = None
    prerequisites: List[str] = field(default_factory=list)  # e.g., "authenticated access"
    
    # Exploitation Status
    exploitation_attempted: bool = False
    exploitation_successful: bool = False
    exploitation_notes: str = ""
    
    # Metadata
    references: List[str] = field(default_factory=list)  # URLs
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CredentialIntel:
    """
    Intelligence about discovered credentials.
    
    Tracks usernames, passwords, hashes, keys, tokens.
    """
    # Identity
    cred_id: str
    
    # Discovery
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_by: str = "credential_harvest"
    source_target: Optional[str] = None  # Target ID where found
    confidence: IntelConfidence = IntelConfidence.CONFIRMED
    
    # Credential Details
    username: Optional[str] = None
    password: Optional[str] = None  # Encrypted/hashed
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None  # NTLM, SHA256, etc.
    
    # Type & Context
    credential_type: str = "password"  # password, hash, key, token, certificate
    domain: Optional[str] = None
    service: Optional[str] = None  # SSH, RDP, SMB, etc.
    
    # Privilege
    privilege_level: str = "user"  # user, admin, system, root, domain_admin
    is_privileged: bool = False
    
    # Validation
    is_valid: Optional[bool] = None
    last_validated: Optional[datetime] = None
    validation_target: Optional[str] = None
    
    # Usage
    usage_count: int = 0
    last_used: Optional[datetime] = None
    successful_targets: List[str] = field(default_factory=list)
    
    # Metadata
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkSegment:
    """Network segment information."""
    subnet: str  # CIDR notation
    gateway: Optional[str] = None
    hosts: List[str] = field(default_factory=list)
    accessible_from: List[str] = field(default_factory=list)  # List of other subnets
    security_zone: str = "unknown"  # dmz, internal, external, etc.
    notes: str = ""


@dataclass
class NetworkMap:
    """
    Network topology intelligence.
    
    Maps out discovered network structure, routing, and connectivity.
    """
    mission_id: str
    
    # Segments
    segments: List[NetworkSegment] = field(default_factory=list)
    
    # Routing
    routes: List[Dict[str, Any]] = field(default_factory=list)  # [{from_subnet, to_subnet, via}]
    gateways: List[Dict[str, Any]] = field(default_factory=list)  # [{ip, connects_to}]
    
    # Pivot Points
    pivot_hosts: List[str] = field(default_factory=list)  # Hosts that can access multiple subnets
    
    # Metadata
    total_hosts: int = 0
    total_subnets: int = 0
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AttackSurfaceAnalysis:
    """
    Analysis of the attack surface.
    
    Identifies entry points, weaknesses, and risk assessment.
    """
    mission_id: str
    
    # Entry Points
    entry_points: List[Dict[str, Any]] = field(default_factory=list)  
    # [{target_id, ip, port, service, attack_vector, risk_score}]
    
    # Attack Vectors
    available_vectors: List[AttackVectorType] = field(default_factory=list)
    recommended_vector: Optional[AttackVectorType] = None
    
    # Risk Assessment
    overall_risk_score: float = 0.0  # 0-10
    high_value_targets: List[str] = field(default_factory=list)  # Target IDs
    low_hanging_fruit: List[str] = field(default_factory=list)   # Easy wins
    
    # Defenses
    detected_defenses: List[Dict[str, Any]] = field(default_factory=list)  
    # [{type: DefenseType, target_id, details}]
    
    # Gaps
    security_gaps: List[str] = field(default_factory=list)  # Identified weaknesses
    
    # Metadata
    confidence: IntelConfidence = IntelConfidence.MEDIUM
    updated_at: datetime = field(default_factory=datetime.utcnow)
    notes: str = ""


@dataclass
class TacticRecommendation:
    """
    Tactical recommendation for next action.
    
    Generated by intelligence analysis + reasoning engine.
    """
    # Identity
    recommendation_id: str
    mission_id: str
    
    # Recommendation
    action: str  # "exploit CVE-2024-1234", "lateral move to 10.0.1.5", etc.
    target_id: Optional[str] = None
    
    # Reasoning
    rationale: str = ""  # Why this action is recommended
    expected_outcome: str = ""
    success_probability: float = 0.5  # 0-1
    
    # Priority
    priority: str = "medium"  # critical, high, medium, low
    urgency: str = "normal"   # immediate, urgent, normal, low
    
    # Dependencies
    prerequisites: List[str] = field(default_factory=list)  # Required before executing
    depends_on: List[str] = field(default_factory=list)     # Other recommendation IDs
    
    # Risk
    risk_level: str = "medium"  # critical, high, medium, low
    stealth_impact: str = "medium"  # high_noise, medium, low, silent
    
    # Tactics & Techniques
    mitre_tactic: Optional[str] = None   # e.g., "Lateral Movement"
    mitre_technique: Optional[str] = None  # e.g., "T1021.001"
    
    # Status
    status: str = "pending"  # pending, approved, rejected, executing, completed
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata
    confidence: IntelConfidence = IntelConfidence.MEDIUM
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# Main Mission Intelligence Class
# ═══════════════════════════════════════════════════════════════

@dataclass
class MissionIntelligence:
    """
    Comprehensive mission-specific intelligence.
    
    Central hub for all discovered intelligence during a mission.
    Updated in real-time by specialists and intelligence builder.
    
    Usage:
        intel = MissionIntelligence(mission_id="mission-123")
        intel.add_target(target_intel)
        intel.add_vulnerability(vuln_intel)
        
        # Query intelligence
        high_value_targets = intel.get_high_value_targets()
        critical_vulns = intel.get_critical_vulnerabilities()
        recommendations = intel.get_top_recommendations(limit=5)
    """
    
    # Identity
    mission_id: str
    
    # Intelligence Collections
    targets: Dict[str, TargetIntel] = field(default_factory=dict)  # {target_id: TargetIntel}
    vulnerabilities: Dict[str, VulnerabilityIntel] = field(default_factory=dict)  # {vuln_id: VulnIntel}
    credentials: Dict[str, CredentialIntel] = field(default_factory=dict)  # {cred_id: CredIntel}
    
    # Analysis Products
    network_topology: Optional[NetworkMap] = None
    attack_surface: Optional[AttackSurfaceAnalysis] = None
    tactical_recommendations: List[TacticRecommendation] = field(default_factory=list)
    
    # Statistics
    total_targets: int = 0
    compromised_targets: int = 0
    total_vulnerabilities: int = 0
    exploitable_vulnerabilities: int = 0
    total_credentials: int = 0
    privileged_credentials: int = 0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    intel_version: int = 1  # Incremented on each update
    
    # ═══════════════════════════════════════════════════════════════
    # Target Intelligence Methods
    # ═══════════════════════════════════════════════════════════════
    
    def add_target(self, target: TargetIntel) -> None:
        """Add or update target intelligence."""
        self.targets[target.target_id] = target
        self.total_targets = len(self.targets)
        self.compromised_targets = sum(1 for t in self.targets.values() if t.is_compromised)
        self.last_updated = datetime.utcnow()
        self.intel_version += 1
        logger.debug(f"Added target {target.target_id} to mission {self.mission_id}")
    
    def get_target(self, target_id: str) -> Optional[TargetIntel]:
        """Get target intelligence by ID."""
        return self.targets.get(target_id)
    
    def get_all_targets(self) -> List[TargetIntel]:
        """Get all targets."""
        return list(self.targets.values())
    
    def get_compromised_targets(self) -> List[TargetIntel]:
        """Get all compromised targets."""
        return [t for t in self.targets.values() if t.is_compromised]
    
    def get_uncompromised_targets(self) -> List[TargetIntel]:
        """Get all uncompromised targets."""
        return [t for t in self.targets.values() if not t.is_compromised]
    
    # ═══════════════════════════════════════════════════════════════
    # Vulnerability Intelligence Methods
    # ═══════════════════════════════════════════════════════════════
    
    def add_vulnerability(self, vuln: VulnerabilityIntel) -> None:
        """Add or update vulnerability intelligence."""
        self.vulnerabilities[vuln.vuln_id] = vuln
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.exploitable_vulnerabilities = sum(1 for v in self.vulnerabilities.values() if v.is_exploitable)
        self.last_updated = datetime.utcnow()
        self.intel_version += 1
        logger.debug(f"Added vulnerability {vuln.vuln_id} to mission {self.mission_id}")
    
    def get_vulnerability(self, vuln_id: str) -> Optional[VulnerabilityIntel]:
        """Get vulnerability intelligence by ID."""
        return self.vulnerabilities.get(vuln_id)
    
    def get_critical_vulnerabilities(self) -> List[VulnerabilityIntel]:
        """Get all critical vulnerabilities."""
        return [v for v in self.vulnerabilities.values() if v.severity == "critical"]
    
    def get_exploitable_vulnerabilities(self) -> List[VulnerabilityIntel]:
        """Get all exploitable vulnerabilities."""
        return [v for v in self.vulnerabilities.values() if v.is_exploitable]
    
    def get_vulnerabilities_by_target(self, target_id: str) -> List[VulnerabilityIntel]:
        """Get all vulnerabilities for a specific target."""
        return [v for v in self.vulnerabilities.values() if v.target_id == target_id]
    
    # ═══════════════════════════════════════════════════════════════
    # Credential Intelligence Methods
    # ═══════════════════════════════════════════════════════════════
    
    def add_credential(self, cred: CredentialIntel) -> None:
        """Add or update credential intelligence."""
        self.credentials[cred.cred_id] = cred
        self.total_credentials = len(self.credentials)
        self.privileged_credentials = sum(1 for c in self.credentials.values() if c.is_privileged)
        self.last_updated = datetime.utcnow()
        self.intel_version += 1
        logger.debug(f"Added credential {cred.cred_id} to mission {self.mission_id}")
    
    def get_credential(self, cred_id: str) -> Optional[CredentialIntel]:
        """Get credential intelligence by ID."""
        return self.credentials.get(cred_id)
    
    def get_privileged_credentials(self) -> List[CredentialIntel]:
        """Get all privileged credentials."""
        return [c for c in self.credentials.values() if c.is_privileged]
    
    def get_valid_credentials(self) -> List[CredentialIntel]:
        """Get all validated credentials."""
        return [c for c in self.credentials.values() if c.is_valid is True]
    
    # ═══════════════════════════════════════════════════════════════
    # Recommendation Methods
    # ═══════════════════════════════════════════════════════════════
    
    def add_recommendation(self, rec: TacticRecommendation) -> None:
        """Add tactical recommendation."""
        self.tactical_recommendations.append(rec)
        self.last_updated = datetime.utcnow()
        self.intel_version += 1
        logger.debug(f"Added recommendation {rec.recommendation_id} to mission {self.mission_id}")
    
    def get_top_recommendations(self, limit: int = 5) -> List[TacticRecommendation]:
        """
        Get top tactical recommendations.
        
        Sorted by: priority (critical > high > medium > low), then success_probability.
        """
        priority_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        pending_recs = [r for r in self.tactical_recommendations if r.status == "pending"]
        
        sorted_recs = sorted(
            pending_recs,
            key=lambda r: (priority_order.get(r.priority, 0), r.success_probability),
            reverse=True
        )
        
        return sorted_recs[:limit]
    
    def get_recommendations_by_target(self, target_id: str) -> List[TacticRecommendation]:
        """Get all recommendations for a specific target."""
        return [r for r in self.tactical_recommendations if r.target_id == target_id]
    
    # ═══════════════════════════════════════════════════════════════
    # Analysis Methods
    # ═══════════════════════════════════════════════════════════════
    
    def get_high_value_targets(self) -> List[TargetIntel]:
        """
        Identify high-value targets.
        
        Criteria:
        - Has critical vulnerabilities
        - Has multiple exploitable vulnerabilities
        - Is a pivot point (accesses multiple subnets)
        - Has privileged credentials available
        """
        high_value = []
        
        for target in self.targets.values():
            score = 0
            
            # Check for critical vulnerabilities
            target_vulns = self.get_vulnerabilities_by_target(target.target_id)
            critical_vulns = [v for v in target_vulns if v.severity == "critical"]
            exploitable_vulns = [v for v in target_vulns if v.is_exploitable]
            
            if critical_vulns:
                score += 3
            if len(exploitable_vulns) >= 2:
                score += 2
            
            # Check if pivot point
            if target.neighboring_hosts and len(target.neighboring_hosts) >= 3:
                score += 2
            
            # Check for available credentials
            target_creds = [c for c in self.credentials.values() 
                          if c.source_target == target.target_id and c.is_valid]
            if target_creds:
                score += 1
            
            if score >= 3:
                high_value.append(target)
        
        return high_value
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive attack summary.
        
        Returns:
            Dict with key intelligence metrics and recommendations.
        """
        return {
            "mission_id": self.mission_id,
            "intel_version": self.intel_version,
            "last_updated": self.last_updated.isoformat(),
            
            # Targets
            "total_targets": self.total_targets,
            "compromised_targets": self.compromised_targets,
            "compromise_rate": f"{(self.compromised_targets / self.total_targets * 100) if self.total_targets > 0 else 0:.1f}%",
            
            # Vulnerabilities
            "total_vulnerabilities": self.total_vulnerabilities,
            "exploitable_vulnerabilities": self.exploitable_vulnerabilities,
            "critical_vulnerabilities": len(self.get_critical_vulnerabilities()),
            
            # Credentials
            "total_credentials": self.total_credentials,
            "privileged_credentials": self.privileged_credentials,
            "valid_credentials": len(self.get_valid_credentials()),
            
            # Recommendations
            "pending_recommendations": len([r for r in self.tactical_recommendations if r.status == "pending"]),
            "top_recommendation": self.get_top_recommendations(limit=1)[0].action if self.tactical_recommendations else None,
            
            # Network
            "total_subnets": self.network_topology.total_subnets if self.network_topology else 0,
            
            # High-value targets
            "high_value_targets": len(self.get_high_value_targets()),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "mission_id": self.mission_id,
            "intel_version": self.intel_version,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            
            "targets": {tid: self._target_to_dict(t) for tid, t in self.targets.items()},
            "vulnerabilities": {vid: self._vuln_to_dict(v) for vid, v in self.vulnerabilities.items()},
            "credentials": {cid: self._cred_to_dict(c) for cid, c in self.credentials.items()},
            
            "statistics": {
                "total_targets": self.total_targets,
                "compromised_targets": self.compromised_targets,
                "total_vulnerabilities": self.total_vulnerabilities,
                "exploitable_vulnerabilities": self.exploitable_vulnerabilities,
                "total_credentials": self.total_credentials,
                "privileged_credentials": self.privileged_credentials,
            },
            
            "network_topology": self._network_to_dict(self.network_topology) if self.network_topology else None,
            "attack_surface": self._attack_surface_to_dict(self.attack_surface) if self.attack_surface else None,
            "tactical_recommendations": [self._rec_to_dict(r) for r in self.tactical_recommendations],
        }
    
    # Helper serialization methods
    def _target_to_dict(self, t: TargetIntel) -> Dict:
        return {
            "target_id": t.target_id,
            "ip": t.ip,
            "hostname": t.hostname,
            "os": t.os,
            "is_compromised": t.is_compromised,
            "open_ports": t.open_ports,
            "vulnerabilities": t.vulnerabilities,
        }
    
    def _vuln_to_dict(self, v: VulnerabilityIntel) -> Dict:
        return {
            "vuln_id": v.vuln_id,
            "target_id": v.target_id,
            "name": v.name,
            "severity": v.severity,
            "is_exploitable": v.is_exploitable,
            "exploit_available": v.exploit_available,
        }
    
    def _cred_to_dict(self, c: CredentialIntel) -> Dict:
        return {
            "cred_id": c.cred_id,
            "username": c.username,
            "credential_type": c.credential_type,
            "privilege_level": c.privilege_level,
            "is_valid": c.is_valid,
        }
    
    def _network_to_dict(self, n: NetworkMap) -> Dict:
        return {
            "total_hosts": n.total_hosts,
            "total_subnets": n.total_subnets,
            "segments": [{"subnet": s.subnet, "hosts": s.hosts} for s in n.segments],
        }
    
    def _attack_surface_to_dict(self, a: AttackSurfaceAnalysis) -> Dict:
        return {
            "overall_risk_score": a.overall_risk_score,
            "entry_points_count": len(a.entry_points),
            "high_value_targets_count": len(a.high_value_targets),
        }
    
    def _rec_to_dict(self, r: TacticRecommendation) -> Dict:
        return {
            "recommendation_id": r.recommendation_id,
            "action": r.action,
            "priority": r.priority,
            "success_probability": r.success_probability,
            "status": r.status,
        }


# ═══════════════════════════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════════════════════════

def create_mission_intelligence(mission_id: str) -> MissionIntelligence:
    """
    Create a new MissionIntelligence instance.
    
    Args:
        mission_id: Unique mission identifier
        
    Returns:
        Initialized MissionIntelligence
    """
    intel = MissionIntelligence(mission_id=mission_id)
    logger.info(f"Created new MissionIntelligence for mission {mission_id}")
    return intel
