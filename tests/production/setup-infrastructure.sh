#!/bin/bash
# Infrastructure Setup and Verification Script for RAGLOX Production Testing
# This script sets up and verifies the test infrastructure

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================${NC}"
}

# Check if Docker is installed
check_docker() {
    print_header "Checking Docker Installation"
    
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        print_success "Docker installed: $DOCKER_VERSION"
    else
        print_error "Docker is not installed"
        print_info "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version)
        print_success "Docker Compose installed: $COMPOSE_VERSION"
    else
        print_error "Docker Compose is not installed"
        print_info "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# Check if .env.test exists
check_env_file() {
    print_header "Checking Environment Configuration"
    
    if [ -f ".env.test" ]; then
        print_success ".env.test file found"
    else
        print_warning ".env.test not found, creating from template..."
        # The file should already be created, but just in case
        print_error "Please ensure .env.test exists"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    print_header "Creating Necessary Directories"
    
    mkdir -p tests/production/init-scripts
    print_success "Created tests/production/init-scripts"
    
    mkdir -p tests/production/nginx-test-config
    print_success "Created tests/production/nginx-test-config"
    
    mkdir -p logs
    print_success "Created logs directory"
}

# Start infrastructure
start_infrastructure() {
    print_header "Starting Test Infrastructure"
    
    print_info "Stopping any existing containers..."
    docker-compose -f docker-compose.test-production.yml down -v 2>/dev/null || true
    
    print_info "Starting services..."
    docker-compose -f docker-compose.test-production.yml up -d
    
    print_success "Services started"
}

# Wait for service to be healthy
wait_for_service() {
    local service_name=$1
    local max_attempts=30
    local attempt=1
    
    print_info "Waiting for $service_name to be healthy..."
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f docker-compose.test-production.yml ps | grep -q "$service_name.*healthy"; then
            print_success "$service_name is healthy"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "$service_name failed to become healthy"
    return 1
}

# Check PostgreSQL
check_postgres() {
    print_header "Verifying PostgreSQL"
    
    wait_for_service "postgres-test"
    
    print_info "Testing PostgreSQL connection..."
    if docker exec raglox-postgres-test psql -U raglox_test -d raglox_test_production -c "SELECT 1" &> /dev/null; then
        print_success "PostgreSQL connection successful"
    else
        print_error "PostgreSQL connection failed"
        return 1
    fi
    
    print_info "Checking database..."
    DB_EXISTS=$(docker exec raglox-postgres-test psql -U raglox_test -lqt | cut -d \| -f 1 | grep -w raglox_test_production | wc -l)
    if [ "$DB_EXISTS" -eq 1 ]; then
        print_success "Database 'raglox_test_production' exists"
    else
        print_error "Database 'raglox_test_production' not found"
        return 1
    fi
}

# Check Redis
check_redis() {
    print_header "Verifying Redis"
    
    wait_for_service "redis-test"
    
    print_info "Testing Redis connection..."
    if docker exec raglox-redis-test redis-cli ping | grep -q "PONG"; then
        print_success "Redis connection successful"
    else
        print_error "Redis connection failed"
        return 1
    fi
    
    print_info "Testing Redis operations..."
    docker exec raglox-redis-test redis-cli SET test_key "test_value" > /dev/null
    TEST_VALUE=$(docker exec raglox-redis-test redis-cli GET test_key)
    docker exec raglox-redis-test redis-cli DEL test_key > /dev/null
    
    if [ "$TEST_VALUE" == "test_value" ]; then
        print_success "Redis operations working"
    else
        print_error "Redis operations failed"
        return 1
    fi
}

# Check API
check_api() {
    print_header "Verifying RAGLOX API"
    
    wait_for_service "raglox-api-test"
    
    print_info "Testing API health endpoint..."
    sleep 5  # Give API extra time to fully start
    
    RESPONSE=$(curl -s http://localhost:8001/health || echo "FAILED")
    
    if echo "$RESPONSE" | grep -q "healthy"; then
        print_success "API health check passed"
    else
        print_error "API health check failed"
        print_info "Response: $RESPONSE"
        return 1
    fi
    
    print_info "Testing API root endpoint..."
    ROOT_RESPONSE=$(curl -s http://localhost:8001/ || echo "FAILED")
    
    if echo "$ROOT_RESPONSE" | grep -q "RAGLOX"; then
        print_success "API root endpoint working"
    else
        print_error "API root endpoint failed"
        return 1
    fi
}

# Check test targets
check_test_targets() {
    print_header "Verifying Test Targets"
    
    # DVWA
    print_info "Checking DVWA (port 8080)..."
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        print_success "DVWA is accessible"
    else
        print_warning "DVWA not accessible yet (may still be starting)"
    fi
    
    # WebGoat
    print_info "Checking WebGoat (port 8081)..."
    if curl -s http://localhost:8081/WebGoat > /dev/null 2>&1; then
        print_success "WebGoat is accessible"
    else
        print_warning "WebGoat not accessible yet (may still be starting)"
    fi
    
    # Juice Shop
    print_info "Checking Juice Shop (port 8082)..."
    if curl -s http://localhost:8082 > /dev/null 2>&1; then
        print_success "Juice Shop is accessible"
    else
        print_warning "Juice Shop not accessible yet (may still be starting)"
    fi
    
    # Nginx
    print_info "Checking Nginx (port 8083)..."
    if curl -s http://localhost:8083 > /dev/null 2>&1; then
        print_success "Nginx is accessible"
    else
        print_warning "Nginx not accessible yet (may still be starting)"
    fi
}

# Show services status
show_services_status() {
    print_header "Services Status"
    docker-compose -f docker-compose.test-production.yml ps
}

# Show logs
show_logs() {
    print_header "Recent Logs"
    print_info "To view full logs, run:"
    echo "  docker-compose -f docker-compose.test-production.yml logs -f [service-name]"
    echo ""
    print_info "Service names:"
    echo "  - postgres-test"
    echo "  - redis-test"
    echo "  - raglox-api-test"
    echo "  - test-target-dvwa"
    echo "  - test-target-webgoat"
    echo "  - test-target-juiceshop"
    echo "  - test-target-nginx"
}

# Print summary
print_summary() {
    print_header "Infrastructure Setup Complete"
    echo ""
    echo -e "${GREEN}✓ Infrastructure is ready for production testing!${NC}"
    echo ""
    echo "Access Points:"
    echo "  • PostgreSQL:  localhost:5433"
    echo "  • Redis:       localhost:6380"
    echo "  • API:         http://localhost:8001"
    echo "  • DVWA:        http://localhost:8080"
    echo "  • WebGoat:     http://localhost:8081"
    echo "  • Juice Shop:  http://localhost:8082"
    echo "  • Nginx:       http://localhost:8083"
    echo ""
    echo "Next Steps:"
    echo "  1. Run integration tests:"
    echo "     pytest tests/production/ -m 'production and integration' -v"
    echo ""
    echo "  2. Run E2E tests:"
    echo "     pytest tests/production/ -m 'production and e2e' -v"
    echo ""
    echo "  3. Stop infrastructure:"
    echo "     docker-compose -f docker-compose.test-production.yml down"
    echo ""
}

# Main execution
main() {
    print_header "RAGLOX Production Testing - Infrastructure Setup"
    
    check_docker
    check_env_file
    create_directories
    start_infrastructure
    
    echo ""
    print_info "Waiting for services to start (this may take 30-60 seconds)..."
    sleep 10
    
    check_postgres
    check_redis
    check_api
    check_test_targets
    
    echo ""
    show_services_status
    echo ""
    show_logs
    echo ""
    print_summary
}

# Run main function
main
