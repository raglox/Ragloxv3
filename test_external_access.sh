#!/bin/bash

echo "=========================================="
echo "  RAGLOX V3 - External Access Test Suite"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
BACKEND_IP="${1:-208.115.230.194}"  # Allow custom IP as argument
BACKEND_PORT="8000"
FRONTEND_PORT="3000"
TEST_EMAIL="test-$(date +%s)@example.com"
TIMEOUT_SEC=5

echo -e "${BLUE}Configuration:${NC}"
echo "  Backend IP: $BACKEND_IP"
echo "  Backend Port: $BACKEND_PORT"
echo "  Frontend Port: $FRONTEND_PORT"
echo "  Test Email: $TEST_EMAIL"
echo ""

# Counter for tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Function to run test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local success_pattern="$3"
    local is_critical="${4:-no}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Test $TOTAL_TESTS: $test_name... "
    
    RESULT=$(eval "$test_command" 2>&1)
    EXIT_CODE=$?
    
    if [ -n "$success_pattern" ]; then
        if echo "$RESULT" | grep -q "$success_pattern"; then
            echo -e "${GREEN}✓ PASS${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        fi
    elif [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    fi
    
    if [ "$is_critical" = "yes" ]; then
        echo -e "${RED}✗ FAIL (CRITICAL)${NC}"
        echo "  Response: ${RESULT:0:200}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Response: ${RESULT:0:200}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Test 1: Backend Health Check
run_test "Backend Health Check (/)" \
    "timeout $TIMEOUT_SEC curl -s http://$BACKEND_IP:$BACKEND_PORT/" \
    "RAGLOX" \
    "yes"
BACKEND_AVAILABLE=$?

echo ""

# Test 2: API Documentation
run_test "API Documentation (/docs)" \
    "timeout $TIMEOUT_SEC curl -s -o /dev/null -w '%{http_code}' http://$BACKEND_IP:$BACKEND_PORT/docs" \
    "200"

echo ""

# Test 3: OpenAPI Schema
run_test "OpenAPI Schema (/openapi.json)" \
    "timeout $TIMEOUT_SEC curl -s http://$BACKEND_IP:$BACKEND_PORT/openapi.json" \
    "openapi"

echo ""

# Test 4: Registration Endpoint
if [ $BACKEND_AVAILABLE -eq 0 ]; then
    echo "Test 4: User Registration..."
    REG_RESULT=$(timeout 10 curl -s -X POST http://$BACKEND_IP:$BACKEND_PORT/api/v1/auth/register \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"Test123!@#\",\"full_name\":\"Test User\",\"organization_name\":\"Test Org\"}" \
      2>&1)
    
    if echo "$REG_RESULT" | grep -q "access_token"; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        TOKEN=$(echo "$REG_RESULT" | jq -r '.access_token' 2>/dev/null)
        USER_EMAIL=$(echo "$REG_RESULT" | jq -r '.user.email' 2>/dev/null)
        echo "  Email: $USER_EMAIL"
        echo "  Token: ${TOKEN:0:30}..."
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Response: ${REG_RESULT:0:200}"
        TOKEN=""
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
else
    echo -e "Test 4: User Registration... ${YELLOW}⊘ SKIP (Backend unavailable)${NC}"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    TOKEN=""
fi

echo ""

# Test 5: Login
if [ -n "$TOKEN" ]; then
    echo "Test 5: User Login..."
    LOGIN_RESULT=$(timeout 10 curl -s -X POST http://$BACKEND_IP:$BACKEND_PORT/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"Test123!@#\"}" \
      2>&1)
    
    if echo "$LOGIN_RESULT" | grep -q "access_token"; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        LOGIN_TOKEN=$(echo "$LOGIN_RESULT" | jq -r '.access_token' 2>/dev/null)
        echo "  Login Token: ${LOGIN_TOKEN:0:30}..."
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Response: ${LOGIN_RESULT:0:200}"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
else
    echo -e "Test 5: User Login... ${YELLOW}⊘ SKIP (No registration token)${NC}"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

echo ""

# Test 6: Get Current User
if [ -n "$TOKEN" ]; then
    echo "Test 6: Get Current User (/api/v1/auth/me)..."
    ME_RESULT=$(timeout $TIMEOUT_SEC curl -s http://$BACKEND_IP:$BACKEND_PORT/api/v1/auth/me \
      -H "Authorization: Bearer $TOKEN" \
      2>&1)
    
    if echo "$ME_RESULT" | grep -q "$TEST_EMAIL"; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        ROLE=$(echo "$ME_RESULT" | jq -r '.role' 2>/dev/null)
        echo "  User Role: $ROLE"
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Response: ${ME_RESULT:0:200}"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
else
    echo -e "Test 6: Get Current User... ${YELLOW}⊘ SKIP (No token)${NC}"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

echo ""

# Test 7: Mission Creation
if [ -n "$TOKEN" ]; then
    echo "Test 7: Create Mission..."
    MISSION_RESULT=$(timeout 10 curl -s -X POST http://$BACKEND_IP:$BACKEND_PORT/api/v1/missions \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $TOKEN" \
      -d '{"name":"External Test Mission","scope":["127.0.0.1"],"goals":["reconnaissance"]}' \
      2>&1)
    
    if echo "$MISSION_RESULT" | grep -q "mission_id"; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        MISSION_ID=$(echo "$MISSION_RESULT" | jq -r '.mission_id' 2>/dev/null)
        echo "  Mission ID: $MISSION_ID"
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "  Response: ${MISSION_RESULT:0:200}"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
else
    echo -e "Test 7: Create Mission... ${YELLOW}⊘ SKIP (No token)${NC}"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

echo ""

# Test 8: Frontend Health
run_test "Frontend Access (port $FRONTEND_PORT)" \
    "timeout $TIMEOUT_SEC curl -s -o /dev/null -w '%{http_code}' http://$BACKEND_IP:$FRONTEND_PORT/"

echo ""

# Test 9: Frontend Proxy
echo "Test 9: Frontend API Proxy (/api)..."
PROXY_RESULT=$(timeout $TIMEOUT_SEC curl -s -o /dev/null -w '%{http_code}' http://$BACKEND_IP:$FRONTEND_PORT/api/v1/auth/me 2>&1)
TOTAL_TESTS=$((TOTAL_TESTS + 1))

if [ "$PROXY_RESULT" = "401" ] || [ "$PROXY_RESULT" = "403" ]; then
    echo -e "  ${GREEN}✓ PASS (Proxy working, auth required: HTTP $PROXY_RESULT)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
elif [ "$PROXY_RESULT" = "200" ]; then
    echo -e "  ${GREEN}✓ PASS (HTTP $PROXY_RESULT)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
elif [ "$PROXY_RESULT" = "000" ]; then
    echo -e "  ${RED}✗ FAIL (Connection failed)${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
else
    echo -e "  ${YELLOW}⚠ WARNING (HTTP $PROXY_RESULT)${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 10: Alternative IP (if provided)
if [ "$BACKEND_IP" != "208.115.230.196" ]; then
    run_test "Alternative IP (208.115.230.196:$BACKEND_PORT)" \
        "timeout $TIMEOUT_SEC curl -s http://208.115.230.196:$BACKEND_PORT/" \
        "RAGLOX"
    echo ""
fi

echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo -e "Total Tests:  $TOTAL_TESTS"
echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
echo -e "Skipped:      ${YELLOW}$SKIPPED_TESTS${NC}"
echo ""

# Calculate pass rate
if [ $TOTAL_TESTS -gt 0 ]; then
    PASS_RATE=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    echo "Pass Rate: $PASS_RATE%"
fi

echo ""
echo "Backend URL:  http://$BACKEND_IP:$BACKEND_PORT/"
echo "Frontend URL: http://$BACKEND_IP:$FRONTEND_PORT/"
echo ""

# Final verdict
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    echo ""
    echo "Your RAGLOX V3 system is fully operational!"
    EXIT_STATUS=0
else
    echo -e "${RED}⚠️  SOME TESTS FAILED${NC}"
    echo ""
    echo "Check the following:"
    echo "  1. Is Backend running? (ps aux | grep uvicorn)"
    echo "  2. Is Nginx configured? (if using reverse proxy)"
    echo "  3. Are ports 3000 and 8000 open in firewall?"
    echo "  4. Check Backend logs: /tmp/backend_all_interfaces.log"
    echo "  5. See EXTERNAL_ACCESS_FINAL_REPORT.md for solutions"
    EXIT_STATUS=1
fi

echo "=========================================="

exit $EXIT_STATUS
