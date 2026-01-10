#!/usr/bin/env bash
#
# RAGLOX v3.0 - Enterprise E2E Test Runner
#
# Runs comprehensive end-to-end tests for Phases 3, 4, and 5
# with real services (PostgreSQL, Redis, Vector Store)
#
# Author: RAGLOX Team
# Version: 3.0.0
# Date: 2026-01-10

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_DIR="$PROJECT_ROOT/tests/e2e"

# Test categories
declare -A TEST_SUITES=(
    ["phase3"]="test_phase3_mission_intelligence_e2e.py"
    ["phase4"]="test_phase4_orchestration_e2e.py"
    ["phase5"]="test_phase5_advanced_features_e2e.py"
    ["master"]="test_master_e2e_suite.py"
    ["all"]="test_phase3_mission_intelligence_e2e.py test_phase4_orchestration_e2e.py test_phase5_advanced_features_e2e.py test_master_e2e_suite.py"
)

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_services() {
    print_header "Checking Required Services"
    
    local all_services_ok=true
    
    # Check PostgreSQL
    if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
        print_success "PostgreSQL is running"
    else
        print_error "PostgreSQL is not running"
        print_info "Start with: sudo systemctl start postgresql"
        all_services_ok=false
    fi
    
    # Check Redis
    if redis-cli -h localhost -p 6379 ping > /dev/null 2>&1; then
        print_success "Redis is running"
    else
        print_error "Redis is not running"
        print_info "Start with: sudo systemctl start redis"
        all_services_ok=false
    fi
    
    # Check database connection
    if psql -h localhost -U raglox -d raglox -c "SELECT 1" > /dev/null 2>&1; then
        print_success "Database connection OK"
    else
        print_warning "Database connection failed (might need setup)"
        print_info "Run: python scripts/setup_database.py"
    fi
    
    echo ""
    
    if [ "$all_services_ok" = false ]; then
        print_error "Some required services are not running"
        exit 1
    fi
}

check_environment() {
    print_header "Checking Environment"
    
    # Check if in correct directory
    if [ ! -f "$PROJECT_ROOT/pytest.ini" ]; then
        print_error "Not in RAGLOX project root"
        exit 1
    fi
    print_success "Project root: $PROJECT_ROOT"
    
    # Check Python version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    print_success "Python version: $python_version"
    
    # Check if virtual environment is activated
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        print_warning "No virtual environment activated"
        print_info "Recommended: source venv/bin/activate"
    else
        print_success "Virtual environment: $VIRTUAL_ENV"
    fi
    
    # Check dependencies
    if python3 -c "import pytest" 2>/dev/null; then
        print_success "pytest installed"
    else
        print_error "pytest not installed"
        print_info "Install with: pip install -r requirements.txt"
        exit 1
    fi
    
    echo ""
}

run_test_suite() {
    local suite_name=$1
    local test_files=${TEST_SUITES[$suite_name]}
    
    print_header "Running $suite_name Tests"
    
    local test_args=""
    for file in $test_files; do
        test_args="$test_args $TEST_DIR/$file"
    done
    
    # Run tests with pytest
    cd "$PROJECT_ROOT"
    
    if python3 -m pytest $test_args \
        -v \
        --tb=short \
        --color=yes \
        --durations=10 \
        --maxfail=5 \
        -m "e2e" \
        2>&1 | tee "$PROJECT_ROOT/e2e_test_results_${suite_name}.log"; then
        print_success "$suite_name tests PASSED"
        return 0
    else
        print_error "$suite_name tests FAILED"
        return 1
    fi
}

generate_report() {
    print_header "Generating Test Report"
    
    local report_file="$PROJECT_ROOT/E2E_TEST_REPORT.md"
    
    cat > "$report_file" << EOF
# RAGLOX v3.0 - E2E Test Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**System:** $(uname -s) $(uname -r)
**Python:** $(python3 --version 2>&1)

## Test Execution Summary

EOF
    
    # Add test results for each suite
    for suite in phase3 phase4 phase5 master; do
        if [ -f "$PROJECT_ROOT/e2e_test_results_${suite}.log" ]; then
            local passed=$(grep -c "PASSED" "$PROJECT_ROOT/e2e_test_results_${suite}.log" || echo "0")
            local failed=$(grep -c "FAILED" "$PROJECT_ROOT/e2e_test_results_${suite}.log" || echo "0")
            local duration=$(grep "seconds" "$PROJECT_ROOT/e2e_test_results_${suite}.log" | tail -1 | awk '{print $NF}' || echo "N/A")
            
            cat >> "$report_file" << EOF
### $suite Tests
- **Passed:** $passed
- **Failed:** $failed
- **Duration:** $duration

EOF
        fi
    done
    
    cat >> "$report_file" << EOF
## Test Suites

### Phase 3: Mission Intelligence
- Complete intelligence pipeline
- Real-time intelligence updates
- Intelligence persistence
- Vector search integration
- Export/import functionality
- Concurrent updates
- Performance tests

### Phase 4: Specialist Orchestration
- Specialist coordination lifecycle
- Dynamic task allocation
- Task dependency coordination
- Failure recovery
- Intelligence-driven orchestration
- Mission planning

### Phase 5: Advanced Features
- Comprehensive risk assessment
- Real-time risk monitoring
- Risk-based decision making
- Adaptive strategy adjustment
- Technique adaptation
- Intelligent task ranking
- Dynamic reprioritization
- Dashboard data generation

### Master Suite
- Complete mission lifecycle
- All phases integrated
- Large-scale stress tests

## Service Integration

All tests use real services:
- ✓ PostgreSQL database
- ✓ Redis cache
- ✓ Vector knowledge store (optional)

## Notes

See individual test logs for detailed results:
- \`e2e_test_results_phase3.log\`
- \`e2e_test_results_phase4.log\`
- \`e2e_test_results_phase5.log\`
- \`e2e_test_results_master.log\`

EOF
    
    print_success "Report generated: $report_file"
}

show_usage() {
    cat << EOF
RAGLOX v3.0 Enterprise E2E Test Runner

Usage: $0 [OPTION] [SUITE]

Options:
    -h, --help          Show this help message
    -c, --check-only    Only check services and environment
    -s, --skip-checks   Skip service checks (not recommended)
    -r, --report-only   Only generate report from existing logs

Suites:
    phase3              Phase 3: Mission Intelligence tests
    phase4              Phase 4: Specialist Orchestration tests
    phase5              Phase 5: Advanced Features tests
    master              Master test suite (complete workflow)
    all                 All test suites (default)

Examples:
    $0                  # Run all tests
    $0 phase3           # Run only Phase 3 tests
    $0 -c               # Check services only
    $0 master           # Run master suite only

EOF
}

# Main execution
main() {
    local suite="all"
    local check_only=false
    local skip_checks=false
    local report_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -c|--check-only)
                check_only=true
                shift
                ;;
            -s|--skip-checks)
                skip_checks=true
                shift
                ;;
            -r|--report-only)
                report_only=true
                shift
                ;;
            phase3|phase4|phase5|master|all)
                suite=$1
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Banner
    echo ""
    print_header "RAGLOX v3.0 Enterprise E2E Test Runner"
    echo ""
    
    # Report only mode
    if [ "$report_only" = true ]; then
        generate_report
        exit 0
    fi
    
    # Check environment
    check_environment
    
    # Check services
    if [ "$skip_checks" = false ]; then
        check_services
    fi
    
    # Check only mode
    if [ "$check_only" = true ]; then
        print_success "All checks passed"
        exit 0
    fi
    
    # Run tests
    echo ""
    print_info "Starting E2E test execution..."
    print_info "Suite: $suite"
    echo ""
    
    local start_time=$(date +%s)
    local all_passed=true
    
    if [ "$suite" = "all" ]; then
        # Run all suites
        for test_suite in phase3 phase4 phase5 master; do
            if ! run_test_suite "$test_suite"; then
                all_passed=false
            fi
            echo ""
        done
    else
        # Run specific suite
        if ! run_test_suite "$suite"; then
            all_passed=false
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Generate report
    echo ""
    generate_report
    
    # Summary
    echo ""
    print_header "Test Execution Complete"
    echo -e "Total duration: ${duration}s"
    
    if [ "$all_passed" = true ]; then
        print_success "ALL TESTS PASSED ✓"
        exit 0
    else
        print_error "SOME TESTS FAILED ✗"
        exit 1
    fi
}

# Run main
main "$@"
