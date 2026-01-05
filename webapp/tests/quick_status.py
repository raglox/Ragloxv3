#!/usr/bin/env python3
"""
Quick status check script for intensive tests
"""
import json
import os
import subprocess
from datetime import datetime

LOG_FILE = "tests/intensive_real_attack_tests.log"
RESULT_FILE = "tests/intensive_real_results.json"

def check_process():
    """Check if test process is running"""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "intensive_real_attack_tests.py"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def count_tests(log_file):
    """Count test results from log"""
    if not os.path.exists(log_file):
        return {"passed": 0, "partial": 0, "failed": 0, "total": 0}
    
    with open(log_file, 'r') as f:
        content = f.read()
    
    passed = content.count("✅")
    partial = content.count("◐")
    failed = content.count("❌")
    
    return {
        "passed": passed,
        "partial": partial,
        "failed": failed,
        "total": passed + partial + failed
    }

def get_current_phase(log_file):
    """Get current test phase"""
    if not os.path.exists(log_file):
        return "Unknown"
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    for line in reversed(lines):
        if "PHASE" in line:
            return line.strip()
    
    return "Starting..."

def main():
    print("═" * 70)
    print("🔍 RAGLOX Intensive Tests - Quick Status")
    print("═" * 70)
    print()
    
    is_running = check_process()
    print(f"Status: {'✅ RUNNING' if is_running else '⏸️  STOPPED/COMPLETED'}")
    print()
    
    if os.path.exists(LOG_FILE):
        stats = count_tests(LOG_FILE)
        phase = get_current_phase(LOG_FILE)
        size = os.path.getsize(LOG_FILE) / 1024  # KB
        
        print(f"Log Size: {size:.1f} KB")
        print()
        print(f"Tests Executed: {stats['total']}")
        print(f"  ✅ Passed:  {stats['passed']}")
        print(f"  ◐ Partial: {stats['partial']}")
        print(f"  ❌ Failed:  {stats['failed']}")
        print()
        print(f"Current Phase: {phase}")
    else:
        print("⚠️  Log file not found")
    
    print()
    
    if os.path.exists(RESULT_FILE):
        print("✅ Results file created!")
        try:
            with open(RESULT_FILE, 'r') as f:
                results = json.load(f)
            
            summary = results.get('summary', {})
            print()
            print("Final Results:")
            print(f"  Total Tests: {summary.get('total_tests', 'N/A')}")
            print(f"  Success Rate: {summary.get('success_rate', 'N/A')}%")
            
            metrics = results.get('metrics', {})
            print()
            print("Execution Metrics:")
            print(f"  Commands: {metrics.get('total_commands', 'N/A')}")
            print(f"  Nmap Scans: {metrics.get('nmap_scans', 'N/A')}")
            print(f"  Nuclei Scans: {metrics.get('nuclei_scans', 'N/A')}")
            print(f"  Duration: {metrics.get('total_execution_time_ms', 'N/A')}ms")
        except:
            print("  (Unable to parse results)")
    else:
        print("⏳ Results file not created yet")
    
    print()
    print("═" * 70)
    print()
    print("💡 Tips:")
    print("  - Monitor log: tail -f tests/intensive_real_attack_tests.log")
    print("  - Full status: ./tests/monitor_intensive_tests.sh")
    print("  - Watch continuously: ./tests/watch_tests.sh")
    print()

if __name__ == "__main__":
    main()
