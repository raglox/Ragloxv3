#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Continuous Test Watcher
# Monitors tests every 30 seconds and logs progress
# ═══════════════════════════════════════════════════════════════

WATCH_LOG="tests/test_watch.log"
LOG_FILE="tests/intensive_real_attack_tests.log"
RESULT_FILE="tests/intensive_real_results.json"

echo "════════════════════════════════════════════════════════════" | tee -a "$WATCH_LOG"
echo "🔍 Starting RAGLOX Test Watcher at $(date)" | tee -a "$WATCH_LOG"
echo "════════════════════════════════════════════════════════════" | tee -a "$WATCH_LOG"

check_status() {
    echo "" | tee -a "$WATCH_LOG"
    echo "[$(date '+%H:%M:%S')] Checking test status..." | tee -a "$WATCH_LOG"
    
    if pgrep -f "intensive_real_attack_tests.py" > /dev/null; then
        PID=$(pgrep -f "intensive_real_attack_tests.py" | head -1)
        RUNTIME=$(ps -p $PID -o etime= 2>/dev/null | xargs || echo "N/A")
        
        PASSED=$(grep -c "✅" "$LOG_FILE" 2>/dev/null || echo "0")
        PARTIAL=$(grep -c "◐" "$LOG_FILE" 2>/dev/null || echo "0")
        FAILED=$(grep -c "❌" "$LOG_FILE" 2>/dev/null || echo "0")
        
        CURRENT_PHASE=$(grep -o "PHASE [0-9]: [A-Z ]*" "$LOG_FILE" 2>/dev/null | tail -1)
        
        echo "   ✅ RUNNING | Runtime: ${RUNTIME} | Tests: $PASSED✅ $PARTIAL◐ $FAILED❌" | tee -a "$WATCH_LOG"
        echo "   Current: ${CURRENT_PHASE:-Unknown}" | tee -a "$WATCH_LOG"
        
        # Show last interesting line
        LAST_LINE=$(grep -E "(✅|◐|❌|PHASE|Category:)" "$LOG_FILE" 2>/dev/null | tail -1)
        echo "   Last: ${LAST_LINE:0:80}..." | tee -a "$WATCH_LOG"
        
        return 0
    else
        echo "   ⏸️  Test COMPLETED or STOPPED" | tee -a "$WATCH_LOG"
        
        if [ -f "$RESULT_FILE" ]; then
            echo "   ✅ Results file found!" | tee -a "$WATCH_LOG"
            SUCCESS_RATE=$(cat "$RESULT_FILE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('summary',{}).get('success_rate','N/A'))" 2>/dev/null || echo "N/A")
            echo "   Success Rate: ${SUCCESS_RATE}%" | tee -a "$WATCH_LOG"
        fi
        
        return 1
    fi
}

# Main watch loop
while true; do
    check_status
    
    if [ $? -eq 1 ]; then
        echo "" | tee -a "$WATCH_LOG"
        echo "════════════════════════════════════════════════════════════" | tee -a "$WATCH_LOG"
        echo "🎯 Test execution completed at $(date)" | tee -a "$WATCH_LOG"
        echo "════════════════════════════════════════════════════════════" | tee -a "$WATCH_LOG"
        break
    fi
    
    sleep 30
done

echo "" | tee -a "$WATCH_LOG"
echo "Watch completed. Full log saved to: $WATCH_LOG" | tee -a "$WATCH_LOG"
