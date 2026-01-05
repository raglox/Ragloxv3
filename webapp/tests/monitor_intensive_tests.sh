#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intensive Tests Monitor Script
# ═══════════════════════════════════════════════════════════════

LOG_FILE="tests/intensive_real_attack_tests.log"
RESULT_FILE="tests/intensive_real_results.json"
STATUS_FILE="tests/intensive_test_status.txt"

echo "═══════════════════════════════════════════════════════════════"
echo "🔍 RAGLOX Intensive Tests Monitor"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check if test is running
if pgrep -f "intensive_real_attack_tests.py" > /dev/null; then
    echo "✅ Status: RUNNING"
    PID=$(pgrep -f "intensive_real_attack_tests.py" | head -1)
    echo "   PID: $PID"
    if [ -n "$PID" ]; then
        RUNTIME=$(ps -p $PID -o etime= 2>/dev/null | xargs || echo "N/A")
        echo "   Runtime: ${RUNTIME}"
    fi
else
    echo "⏸️  Status: NOT RUNNING"
fi

echo ""
echo "───────────────────────────────────────────────────────────────"
echo "📊 Progress Summary"
echo "───────────────────────────────────────────────────────────────"

if [ -f "$LOG_FILE" ]; then
    echo "📝 Log Size: $(du -h $LOG_FILE | cut -f1)"
    
    # Count tests executed
    PASSED=$(grep -c "✅" "$LOG_FILE" 2>/dev/null || echo "0")
    FAILED=$(grep -c "❌" "$LOG_FILE" 2>/dev/null || echo "0")
    PARTIAL=$(grep -c "◐" "$LOG_FILE" 2>/dev/null || echo "0")
    
    echo "   ✅ Passed:  $PASSED"
    echo "   ◐ Partial: $PARTIAL"
    echo "   ❌ Failed:  $FAILED"
    
    # Check for phases
    echo ""
    echo "🔍 Phases Completed:"
    grep -o "PHASE [0-9]: [A-Z ]*" "$LOG_FILE" | tail -5
    
    # Show last 15 lines
    echo ""
    echo "───────────────────────────────────────────────────────────────"
    echo "📜 Last 15 Log Lines:"
    echo "───────────────────────────────────────────────────────────────"
    tail -15 "$LOG_FILE" | sed 's/^/   /'
else
    echo "⚠️  Log file not found yet"
fi

echo ""
echo "───────────────────────────────────────────────────────────────"

# Check if results file exists
if [ -f "$RESULT_FILE" ]; then
    echo "✅ Results file created!"
    echo "   Size: $(du -h $RESULT_FILE | cut -f1)"
    echo ""
    echo "📈 Final Results:"
    cat "$RESULT_FILE" | python3 -m json.tool | head -50
else
    echo "⏳ Results file not created yet (test still running)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
