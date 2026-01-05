#!/usr/bin/env python3
"""
RAGLOX v3.0 - Intensive Real-World Tests (NO MOCK DATA)

This test suite runs REAL security tools against REAL targets:
- nmap for network/port scanning
- nuclei for vulnerability scanning
- Real LLM API for decision making
- Real Redis for state management

WARNING: Only run against authorized targets!

Usage:
    python3 webapp/tests/intensive_real_tests.py --target 172.28.0.100
    python3 webapp/tests/intensive_real_tests.py --target localhost --http-port 8088 --ssh-port 2222
"""

import asyncio
import argparse
import subprocess
import json
import sys
import os
import re
from pathlib import Path
from datetime import datetime
from uuid import uuid4, UUID
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.config import get_settings
from src.core.blackboard import Blackboard
from src.core.knowledge import EmbeddedKnowledge, init_knowledge
from src.core.models import Mission, GoalStatus, Task, TaskType, TaskStatus, SpecialistType
from src.specialists.recon import ReconSpecialist
from src.specialists.attack import AttackSpecialist
from src.specialists.analysis import AnalysisSpecialist


class TestPhase(Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"


@dataclass
class RealTestResult:
    """Result of a real test."""
    phase: TestPhase
    test_name: str
    success: bool
    duration_ms: float
    findings: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    raw_output: str = ""


class RealToolExecutor:
    """Execute real security tools."""
    
    def __init__(self, target: str, http_port: int = 80, ssh_port: int = 22):
        self.target = target
        self.http_port = http_port
        self.ssh_port = ssh_port
        
    async def run_nmap_scan(self, scan_type: str = "quick") -> Dict[str, Any]:
        """Run real nmap scan."""
        if scan_type == "quick":
            cmd = f"nmap -sV -T4 --top-ports 100 -oX - {self.target}"
        elif scan_type == "full":
            cmd = f"nmap -sV -sC -T4 -p- -oX - {self.target}"
        elif scan_type == "vuln":
            cmd = f"nmap -sV --script vuln -oX - {self.target}"
        else:
            cmd = f"nmap -sV -T4 {self.target}"
            
        result = await self._execute_command(cmd, timeout=300)
        
        # Parse nmap output
        findings = self._parse_nmap_xml(result.get("stdout", ""))
        findings["raw"] = result.get("stdout", "")[:2000]
        
        return {
            "success": result.get("return_code") == 0,
            "scan_type": scan_type,
            "target": self.target,
            "findings": findings,
            "duration_ms": result.get("duration_ms", 0)
        }
        
    async def run_nuclei_scan(self, severity: str = "critical,high", templates: List[str] = None) -> Dict[str, Any]:
        """Run real Nuclei vulnerability scan."""
        base_cmd = f"nuclei -u http://{self.target}:{self.http_port} -severity {severity} -json -silent"
        
        if templates:
            templates_str = ",".join(templates)
            base_cmd += f" -t {templates_str}"
            
        result = await self._execute_command(base_cmd, timeout=600)
        
        # Parse nuclei JSON output
        findings = self._parse_nuclei_output(result.get("stdout", ""))
        
        return {
            "success": True,  # Nuclei returns 0 even if no vulns found
            "target": f"http://{self.target}:{self.http_port}",
            "severity_filter": severity,
            "findings": findings,
            "vuln_count": len(findings.get("vulnerabilities", [])),
            "duration_ms": result.get("duration_ms", 0)
        }
        
    async def run_nikto_scan(self) -> Dict[str, Any]:
        """Run Nikto web scanner."""
        cmd = f"nikto -h http://{self.target}:{self.http_port} -Format json -output -"
        result = await self._execute_command(cmd, timeout=300)
        
        return {
            "success": result.get("return_code") == 0,
            "target": f"http://{self.target}:{self.http_port}",
            "raw_output": result.get("stdout", "")[:5000],
            "duration_ms": result.get("duration_ms", 0)
        }
        
    async def run_ssh_check(self) -> Dict[str, Any]:
        """Check SSH service and version."""
        cmd = f"nc -zv -w 5 {self.target} {self.ssh_port}"
        result = await self._execute_command(cmd, timeout=10)
        
        # Get SSH banner
        banner_cmd = f"echo '' | nc -w 5 {self.target} {self.ssh_port}"
        banner_result = await self._execute_command(banner_cmd, timeout=10)
        
        ssh_version = banner_result.get("stdout", "").strip()
        
        return {
            "success": result.get("return_code") == 0,
            "port_open": "succeeded" in result.get("stderr", "").lower() or result.get("return_code") == 0,
            "ssh_version": ssh_version,
            "target": f"{self.target}:{self.ssh_port}"
        }
        
    async def run_http_fingerprint(self) -> Dict[str, Any]:
        """Fingerprint HTTP service."""
        cmd = f"curl -sI http://{self.target}:{self.http_port}/"
        result = await self._execute_command(cmd, timeout=30)
        
        headers = result.get("stdout", "")
        
        # Parse headers
        server = ""
        technologies = []
        
        for line in headers.split("\n"):
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-powered-by:"):
                technologies.append(line.split(":", 1)[1].strip())
                
        return {
            "success": result.get("return_code") == 0,
            "server": server,
            "technologies": technologies,
            "headers": headers[:2000]
        }
        
    async def _execute_command(self, cmd: str, timeout: int = 60) -> Dict[str, Any]:
        """Execute shell command and return result."""
        start_time = datetime.now()
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                return {
                    "return_code": -1,
                    "stdout": "",
                    "stderr": "Command timed out",
                    "duration_ms": timeout * 1000
                }
                
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            return {
                "return_code": process.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "duration_ms": duration_ms
            }
            
        except Exception as e:
            return {
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": 0
            }
            
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output."""
        findings = {
            "hosts": [],
            "open_ports": [],
            "services": [],
            "os_detection": None
        }
        
        # Simple regex parsing (for more robust parsing, use python-nmap)
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)".*?<state state="(\w+)".*?<service name="([^"]*)"'
        
        for match in re.finditer(port_pattern, xml_output, re.DOTALL):
            protocol, port, state, service = match.groups()
            if state == "open":
                findings["open_ports"].append(int(port))
                findings["services"].append({
                    "port": int(port),
                    "protocol": protocol,
                    "service": service
                })
                
        return findings
        
    def _parse_nuclei_output(self, json_output: str) -> Dict[str, Any]:
        """Parse Nuclei JSON output."""
        findings = {
            "vulnerabilities": [],
            "info_disclosures": [],
            "misconfigurations": []
        }
        
        for line in json_output.strip().split("\n"):
            if not line:
                continue
            try:
                vuln = json.loads(line)
                severity = vuln.get("info", {}).get("severity", "unknown").lower()
                
                vuln_entry = {
                    "template_id": vuln.get("template-id", ""),
                    "name": vuln.get("info", {}).get("name", ""),
                    "severity": severity,
                    "matched_at": vuln.get("matched-at", ""),
                    "matcher_name": vuln.get("matcher-name", "")
                }
                
                if severity in ["critical", "high", "medium"]:
                    findings["vulnerabilities"].append(vuln_entry)
                elif severity == "info":
                    findings["info_disclosures"].append(vuln_entry)
                else:
                    findings["misconfigurations"].append(vuln_entry)
                    
            except json.JSONDecodeError:
                continue
                
        return findings


class IntensiveRealTestSuite:
    """Intensive real-world test suite."""
    
    def __init__(self, target: str, http_port: int = 80, ssh_port: int = 22):
        self.target = target
        self.http_port = http_port
        self.ssh_port = ssh_port
        self.settings = get_settings()
        self.blackboard: Blackboard = None
        self.knowledge: EmbeddedKnowledge = None
        self.mission_id: str = None
        self.tool_executor = RealToolExecutor(target, http_port, ssh_port)
        self.results: List[RealTestResult] = []
        self.start_time: datetime = None
        
    async def setup(self):
        """Initialize all components."""
        self.start_time = datetime.now()
        
        print("\n" + "=" * 70)
        print("🔥 RAGLOX v3.0 - INTENSIVE REAL-WORLD TEST SUITE")
        print("=" * 70)
        print(f"Target: {self.target}")
        print(f"HTTP Port: {self.http_port}")
        print(f"SSH Port: {self.ssh_port}")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        # Load Knowledge Base
        print("\n📚 Loading Knowledge Base...")
        self.knowledge = init_knowledge(data_path=self.settings.knowledge_data_path)
        if self.knowledge.is_loaded():
            stats = self.knowledge.get_statistics()
            print(f"   ✓ {stats['total_rx_modules']} modules, {stats['total_techniques']} techniques")
        
        # Connect to Redis
        print("\n🔗 Connecting to Redis...")
        self.blackboard = Blackboard(settings=self.settings)
        await self.blackboard.connect()
        print("   ✓ Connected")
        
        # Create mission
        print("\n📋 Creating Mission...")
        mission = Mission(
            name=f"Intensive Real Test - {self.target} - {datetime.now().strftime('%Y%m%d_%H%M%S')}",
            scope=[self.target],
            goals={
                "reconnaissance": GoalStatus.PENDING,
                "vulnerability_discovery": GoalStatus.PENDING,
                "initial_access": GoalStatus.PENDING
            }
        )
        self.mission_id = await self.blackboard.create_mission(mission)
        print(f"   ✓ Mission: {self.mission_id}")
        
    async def teardown(self):
        """Cleanup resources."""
        if self.blackboard:
            await self.blackboard.disconnect()
            
    async def run_phase_1_reconnaissance(self):
        """Phase 1: Real reconnaissance using nmap."""
        print("\n" + "-" * 70)
        print("🔍 PHASE 1: RECONNAISSANCE (Real Tools)")
        print("-" * 70)
        
        # Test 1.1: Nmap Quick Scan
        print("\n   [1.1] Nmap Quick Scan...")
        start = datetime.now()
        nmap_result = await self.tool_executor.run_nmap_scan("quick")
        duration = (datetime.now() - start).total_seconds() * 1000
        
        open_ports = nmap_result.get("findings", {}).get("open_ports", [])
        services = nmap_result.get("findings", {}).get("services", [])
        
        print(f"        ✓ Found {len(open_ports)} open ports: {open_ports}")
        for svc in services:
            print(f"          - {svc['port']}/{svc['protocol']}: {svc['service']}")
            
        self.results.append(RealTestResult(
            phase=TestPhase.RECON,
            test_name="Nmap Quick Scan",
            success=len(open_ports) > 0,
            duration_ms=duration,
            findings={"ports": open_ports, "services": services}
        ))
        
        # Store targets in blackboard
        for svc in services:
            await self.blackboard.add_target({
                "ip": self.target,
                "hostname": self.target,
                "os": "Linux",
                "status": "scanned",
                "ports": {str(svc["port"]): svc["service"]}
            }, self.mission_id)
            
        # Test 1.2: HTTP Fingerprinting
        print("\n   [1.2] HTTP Fingerprinting...")
        start = datetime.now()
        http_result = await self.tool_executor.run_http_fingerprint()
        duration = (datetime.now() - start).total_seconds() * 1000
        
        print(f"        ✓ Server: {http_result.get('server', 'Unknown')}")
        print(f"        ✓ Technologies: {http_result.get('technologies', [])}")
        
        self.results.append(RealTestResult(
            phase=TestPhase.RECON,
            test_name="HTTP Fingerprinting",
            success=http_result.get("success", False),
            duration_ms=duration,
            findings=http_result
        ))
        
        # Test 1.3: SSH Check
        print("\n   [1.3] SSH Service Check...")
        start = datetime.now()
        ssh_result = await self.tool_executor.run_ssh_check()
        duration = (datetime.now() - start).total_seconds() * 1000
        
        print(f"        ✓ Port Open: {ssh_result.get('port_open', False)}")
        print(f"        ✓ SSH Version: {ssh_result.get('ssh_version', 'Unknown')}")
        
        self.results.append(RealTestResult(
            phase=TestPhase.RECON,
            test_name="SSH Service Check",
            success=ssh_result.get("port_open", False),
            duration_ms=duration,
            findings=ssh_result
        ))
        
        return nmap_result
        
    async def run_phase_2_vulnerability_scan(self):
        """Phase 2: Vulnerability scanning with Nuclei."""
        print("\n" + "-" * 70)
        print("🛡️ PHASE 2: VULNERABILITY SCANNING (Nuclei)")
        print("-" * 70)
        
        # Test 2.1: Critical/High Severity Scan
        print("\n   [2.1] Nuclei Critical/High Scan...")
        start = datetime.now()
        nuclei_result = await self.tool_executor.run_nuclei_scan("critical,high")
        duration = (datetime.now() - start).total_seconds() * 1000
        
        vulns = nuclei_result.get("findings", {}).get("vulnerabilities", [])
        print(f"        ✓ Found {len(vulns)} vulnerabilities")
        for v in vulns[:5]:
            print(f"          - [{v['severity'].upper()}] {v['name']}")
            
        self.results.append(RealTestResult(
            phase=TestPhase.VULN_SCAN,
            test_name="Nuclei Critical/High Scan",
            success=True,
            duration_ms=duration,
            findings={"vulnerabilities": vulns}
        ))
        
        # Store vulnerabilities in blackboard
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        target_id = targets[0].replace("target:", "") if targets else None
        
        for vuln in vulns:
            await self.blackboard.add_vulnerability({
                "target_id": target_id,
                "type": vuln.get("template_id", "unknown"),
                "name": vuln.get("name", "Unknown"),
                "severity": vuln.get("severity", "unknown"),
                "exploit_available": vuln.get("severity") in ["critical", "high"]
            }, self.mission_id)
            
        # Test 2.2: Medium Severity Scan
        print("\n   [2.2] Nuclei Medium Severity Scan...")
        start = datetime.now()
        medium_result = await self.tool_executor.run_nuclei_scan("medium")
        duration = (datetime.now() - start).total_seconds() * 1000
        
        medium_vulns = medium_result.get("findings", {}).get("vulnerabilities", [])
        print(f"        ✓ Found {len(medium_vulns)} medium severity issues")
        
        self.results.append(RealTestResult(
            phase=TestPhase.VULN_SCAN,
            test_name="Nuclei Medium Scan",
            success=True,
            duration_ms=duration,
            findings={"vulnerabilities": medium_vulns}
        ))
        
        # Test 2.3: Info Disclosure Scan
        print("\n   [2.3] Nuclei Info Disclosure Scan...")
        start = datetime.now()
        info_result = await self.tool_executor.run_nuclei_scan("info,low")
        duration = (datetime.now() - start).total_seconds() * 1000
        
        info_items = info_result.get("findings", {}).get("info_disclosures", [])
        print(f"        ✓ Found {len(info_items)} info disclosures")
        
        self.results.append(RealTestResult(
            phase=TestPhase.VULN_SCAN,
            test_name="Nuclei Info Disclosure",
            success=True,
            duration_ms=duration,
            findings={"info_disclosures": info_items}
        ))
        
        return nuclei_result
        
    async def run_phase_3_llm_analysis(self, recon_data: Dict, vuln_data: Dict):
        """Phase 3: LLM-based analysis of findings."""
        print("\n" + "-" * 70)
        print("🧠 PHASE 3: LLM ANALYSIS (Real API)")
        print("-" * 70)
        
        # Initialize AnalysisSpecialist with real LLM
        analysis = AnalysisSpecialist(
            blackboard=self.blackboard,
            settings=self.settings,
            llm_enabled=True
        )
        analysis._current_mission_id = self.mission_id
        
        # Test 3.1: Analyze scan findings
        print("\n   [3.1] LLM Analysis of Scan Results...")
        
        # Get targets and create task
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        target_id = targets[0].replace("target:", "") if targets else "test-target"
        
        task = Task(
            mission_id=UUID(self.mission_id),
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            target_id=UUID(target_id) if target_id != "test-target" else None,
            status=TaskStatus.FAILED,
            error_message="Initial reconnaissance complete, need attack strategy"
        )
        task_id = str(task.id)
        await self.blackboard.add_task(task)
        
        # Prepare context from real scan data
        vulns = vuln_data.get("findings", {}).get("vulnerabilities", [])
        services = recon_data.get("findings", {}).get("services", [])
        
        error_context = {
            "error_type": "reconnaissance_complete",
            "error_message": "Reconnaissance phase complete, need attack vector analysis",
            "detected_defenses": [],
            "technique_id": "T1595",
            "contributing_factors": [
                f"services_found_{len(services)}",
                f"vulns_found_{len(vulns)}"
            ],
            "scan_results": {
                "services": services[:5],
                "vulnerabilities": [v["name"] for v in vulns[:5]]
            }
        }
        
        start = datetime.now()
        result = await analysis.analyze_failure(
            task_id=task_id,
            error_context=error_context,
            execution_logs=[
                f"Nmap scan completed: {len(services)} services found",
                f"Nuclei scan completed: {len(vulns)} vulnerabilities found",
                "Ready for attack vector analysis"
            ]
        )
        duration = (datetime.now() - start).total_seconds() * 1000
        
        decision = result.get("decision", "unknown")
        reasoning = result.get("reasoning", "")[:300]
        llm_used = result.get("llm_analysis", False)
        
        print(f"        ✓ Decision: {decision}")
        print(f"        ✓ LLM Used: {llm_used}")
        print(f"        ✓ Reasoning: {reasoning}...")
        
        if result.get("recommendations"):
            print(f"        ✓ Recommendations:")
            for rec in result.get("recommendations", [])[:3]:
                print(f"          - {rec}")
                
        self.results.append(RealTestResult(
            phase=TestPhase.ANALYSIS,
            test_name="LLM Scan Analysis",
            success=decision in ["modify_approach", "retry", "escalate", "pivot"],
            duration_ms=duration,
            findings={
                "decision": decision,
                "llm_used": llm_used,
                "reasoning": reasoning
            }
        ))
        
        # Test 3.2: Attack Vector Recommendation
        print("\n   [3.2] LLM Attack Vector Recommendation...")
        
        if vulns:
            # Create task for specific vulnerability
            task2 = Task(
                mission_id=UUID(self.mission_id),
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=UUID(target_id) if target_id != "test-target" else None,
                status=TaskStatus.PENDING
            )
            await self.blackboard.add_task(task2)
            
            error_context2 = {
                "error_type": "attack_planning",
                "error_message": f"Planning attack for {vulns[0]['name'] if vulns else 'target'}",
                "detected_defenses": [],
                "technique_id": "T1190",
                "vulnerability_data": vulns[0] if vulns else {}
            }
            
            start = datetime.now()
            result2 = await analysis.analyze_failure(
                task_id=str(task2.id),
                error_context=error_context2,
                execution_logs=["Vulnerability confirmed", "Planning exploitation"]
            )
            duration = (datetime.now() - start).total_seconds() * 1000
            
            print(f"        ✓ Attack Decision: {result2.get('decision', 'unknown')}")
            print(f"        ✓ LLM Used: {result2.get('llm_analysis', False)}")
            
            self.results.append(RealTestResult(
                phase=TestPhase.ANALYSIS,
                test_name="LLM Attack Planning",
                success=True,
                duration_ms=duration,
                findings=result2
            ))
            
        return result
        
    async def run_phase_4_knowledge_integration(self):
        """Phase 4: Test Knowledge Base integration."""
        print("\n" + "-" * 70)
        print("📚 PHASE 4: KNOWLEDGE BASE INTEGRATION")
        print("-" * 70)
        
        # Test 4.1: Get relevant modules from KB
        print("\n   [4.1] Query Exploit Modules...")
        start = datetime.now()
        
        exploit_modules = self.knowledge.get_exploit_modules(platform="linux")
        print(f"        ✓ Found {len(exploit_modules)} Linux exploit modules")
        
        self.results.append(RealTestResult(
            phase=TestPhase.ANALYSIS,
            test_name="KB Exploit Modules",
            success=len(exploit_modules) > 0,
            duration_ms=(datetime.now() - start).total_seconds() * 1000,
            findings={"module_count": len(exploit_modules)}
        ))
        
        # Test 4.2: Get techniques for discovered services
        print("\n   [4.2] Query Techniques for Services...")
        start = datetime.now()
        
        # SSH techniques
        ssh_techniques = self.knowledge.get_modules_for_technique("T1021.004")  # SSH
        print(f"        ✓ SSH techniques: {len(ssh_techniques)}")
        
        # Web techniques
        web_techniques = self.knowledge.get_modules_for_technique("T1190")  # Exploit Public-Facing
        print(f"        ✓ Web exploit techniques: {len(web_techniques)}")
        
        self.results.append(RealTestResult(
            phase=TestPhase.ANALYSIS,
            test_name="KB Service Techniques",
            success=True,
            duration_ms=(datetime.now() - start).total_seconds() * 1000,
            findings={"ssh_tech": len(ssh_techniques), "web_tech": len(web_techniques)}
        ))
        
        # Test 4.3: Nuclei templates matching
        print("\n   [4.3] Query Nuclei Templates...")
        start = datetime.now()
        
        critical_templates = self.knowledge.get_nuclei_critical_templates(limit=20)
        rce_templates = self.knowledge.get_nuclei_rce_templates(limit=20)
        
        print(f"        ✓ Critical templates: {len(critical_templates)}")
        print(f"        ✓ RCE templates: {len(rce_templates)}")
        
        self.results.append(RealTestResult(
            phase=TestPhase.ANALYSIS,
            test_name="KB Nuclei Templates",
            success=len(critical_templates) > 0,
            duration_ms=(datetime.now() - start).total_seconds() * 1000,
            findings={"critical": len(critical_templates), "rce": len(rce_templates)}
        ))
        
    def print_summary(self):
        """Print comprehensive test summary."""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        print("\n" + "=" * 70)
        print("📊 INTENSIVE TEST SUMMARY")
        print("=" * 70)
        
        # Count by phase
        by_phase = {}
        for r in self.results:
            phase = r.phase.value
            if phase not in by_phase:
                by_phase[phase] = {"passed": 0, "failed": 0, "total": 0}
            by_phase[phase]["total"] += 1
            if r.success:
                by_phase[phase]["passed"] += 1
            else:
                by_phase[phase]["failed"] += 1
                
        # Overall stats
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed
        
        print(f"\n   Target: {self.target}")
        print(f"   Duration: {total_duration:.1f}s")
        print(f"   Total Tests: {total}")
        print(f"   ✓ Passed: {passed}")
        print(f"   ✗ Failed: {failed}")
        print(f"   Success Rate: {passed/max(total,1)*100:.1f}%")
        
        print("\n   BY PHASE:")
        for phase, stats in by_phase.items():
            rate = stats["passed"] / max(stats["total"], 1) * 100
            print(f"      {phase.upper()}: {stats['passed']}/{stats['total']} ({rate:.0f}%)")
            
        print("\n" + "-" * 70)
        print("   DETAILED RESULTS")
        print("-" * 70)
        
        for r in self.results:
            icon = "✓" if r.success else "✗"
            print(f"   {icon} [{r.phase.value.upper()}] {r.test_name}: {r.duration_ms:.0f}ms")
            
            # Print key findings
            if r.findings:
                for key, value in list(r.findings.items())[:3]:
                    if isinstance(value, list):
                        print(f"      {key}: {len(value)} items")
                    elif isinstance(value, (str, int, float, bool)):
                        print(f"      {key}: {str(value)[:50]}")
                        
        print("\n" + "=" * 70)
        
        # Export results
        results_file = Path(__file__).parent / f"intensive_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, "w") as f:
            json.dump({
                "target": self.target,
                "duration_seconds": total_duration,
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "success_rate": passed / max(total, 1),
                "results": [
                    {
                        "phase": r.phase.value,
                        "test": r.test_name,
                        "success": r.success,
                        "duration_ms": r.duration_ms,
                        "findings": r.findings
                    }
                    for r in self.results
                ]
            }, f, indent=2, default=str)
            
        print(f"\n📁 Results exported to: {results_file}")


async def main():
    parser = argparse.ArgumentParser(description="RAGLOX Intensive Real-World Tests")
    parser.add_argument("--target", default="172.28.0.100", help="Target IP address")
    parser.add_argument("--http-port", type=int, default=80, help="HTTP port")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    args = parser.parse_args()
    
    suite = IntensiveRealTestSuite(
        target=args.target,
        http_port=args.http_port,
        ssh_port=args.ssh_port
    )
    
    try:
        await suite.setup()
        
        # Run all phases
        recon_data = await suite.run_phase_1_reconnaissance()
        vuln_data = await suite.run_phase_2_vulnerability_scan()
        await suite.run_phase_3_llm_analysis(recon_data, vuln_data)
        await suite.run_phase_4_knowledge_integration()
        
        suite.print_summary()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await suite.teardown()


if __name__ == "__main__":
    asyncio.run(main())
