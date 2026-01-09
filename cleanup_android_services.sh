#!/bin/bash

# ============================================
# RAGLOX - Clean Android & ai-manus Services
# Remove old services to free ports 80/443
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  RAGLOX - Service Cleanup${NC}"
echo -e "${BLUE}  Removing Android & ai-manus services${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}This script must be run as root or with sudo${NC}"
    exit 1
fi

# ============================================
# Step 1: List what will be removed
# ============================================
echo -e "${BLUE}Step 1: Services to be removed:${NC}"
echo ""

echo "Docker Containers:"
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | grep -E "android|ai-manus" || echo "  None found"
echo ""

echo "Docker Images:"
docker images | grep -E "android|manus" | head -5 || echo "  None found"
echo ""

echo "Docker Compose files:"
find /opt -name "*docker-compose*.yml" -type f 2>/dev/null | grep -E "manus|android" | head -5 || echo "  None found"
echo ""

# ============================================
# Confirmation
# ============================================
echo -e "${YELLOW}⚠️  WARNING: This will:${NC}"
echo "  1. Stop and remove ALL Android emulator containers (3 containers)"
echo "  2. Stop and remove ai-manus-frontend container"
echo "  3. Stop and remove ai-manus-mongodb container"
echo "  4. Remove related Docker images (optional)"
echo "  5. Remove related docker-compose files (optional)"
echo ""
echo -e "${YELLOW}⚠️  Ports 80 and 443 will be freed for RAGLOX${NC}"
echo ""

read -p "Are you sure you want to continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""

# ============================================
# Step 2: Stop and remove Android containers
# ============================================
echo -e "${BLUE}Step 2: Removing Android containers...${NC}"

ANDROID_CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep -E "^android[0-9]+" || true)

if [ -n "$ANDROID_CONTAINERS" ]; then
    for container in $ANDROID_CONTAINERS; do
        echo -n "  Stopping $container... "
        docker stop "$container" 2>/dev/null || true
        echo "stopped"
        
        echo -n "  Removing $container... "
        docker rm "$container" 2>/dev/null || true
        echo "removed"
    done
    echo -e "${GREEN}✓ Android containers removed${NC}"
else
    echo "  No Android containers found"
fi

echo ""

# ============================================
# Step 3: Stop and remove ai-manus containers
# ============================================
echo -e "${BLUE}Step 3: Removing ai-manus containers...${NC}"

MANUS_CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep "ai-manus" || true)

if [ -n "$MANUS_CONTAINERS" ]; then
    for container in $MANUS_CONTAINERS; do
        echo -n "  Stopping $container... "
        docker stop "$container" 2>/dev/null || true
        echo "stopped"
        
        echo -n "  Removing $container... "
        docker rm "$container" 2>/dev/null || true
        echo "removed"
    done
    echo -e "${GREEN}✓ ai-manus containers removed${NC}"
else
    echo "  No ai-manus containers found"
fi

echo ""

# ============================================
# Step 4: Remove mitmproxy (if not needed)
# ============================================
echo -e "${BLUE}Step 4: Checking mitmproxy...${NC}"

if docker ps -a | grep -q "mitmproxy"; then
    read -p "Remove mitmproxy container? (yes/no): " REMOVE_MITM
    if [ "$REMOVE_MITM" = "yes" ]; then
        docker stop mitmproxy 2>/dev/null || true
        docker rm mitmproxy 2>/dev/null || true
        echo -e "${GREEN}✓ mitmproxy removed${NC}"
    else
        echo "  Keeping mitmproxy"
    fi
else
    echo "  mitmproxy not found"
fi

echo ""

# ============================================
# Step 5: Remove Docker images (optional)
# ============================================
echo -e "${BLUE}Step 5: Cleaning up Docker images...${NC}"

read -p "Remove related Docker images? (yes/no): " REMOVE_IMAGES

if [ "$REMOVE_IMAGES" = "yes" ]; then
    echo ""
    echo "Images to remove:"
    docker images | grep -E "android|manus" | head -10
    echo ""
    
    read -p "Confirm image removal? (yes/no): " CONFIRM_IMAGES
    
    if [ "$CONFIRM_IMAGES" = "yes" ]; then
        # Remove Android images
        docker images | grep "android" | awk '{print $3}' | xargs -r docker rmi -f 2>/dev/null || true
        
        # Remove manus images
        docker images | grep "manus" | awk '{print $3}' | xargs -r docker rmi -f 2>/dev/null || true
        
        echo -e "${GREEN}✓ Docker images removed${NC}"
    else
        echo "  Keeping images"
    fi
else
    echo "  Keeping images"
fi

echo ""

# ============================================
# Step 6: Clean up docker-compose files (optional)
# ============================================
echo -e "${BLUE}Step 6: Cleaning up docker-compose files...${NC}"

read -p "Archive old docker-compose files? (yes/no): " ARCHIVE_COMPOSE

if [ "$ARCHIVE_COMPOSE" = "yes" ]; then
    ARCHIVE_DIR="/opt/raglox/archive_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$ARCHIVE_DIR"
    
    # Find and move docker-compose files
    find /opt/raglox -name "*docker-compose*.yml" -type f 2>/dev/null | while read file; do
        if [ -f "$file" ]; then
            echo "  Archiving: $file"
            cp "$file" "$ARCHIVE_DIR/"
        fi
    done
    
    echo -e "${GREEN}✓ Files archived to: $ARCHIVE_DIR${NC}"
else
    echo "  Keeping docker-compose files"
fi

echo ""

# ============================================
# Step 7: Clean up Docker system
# ============================================
echo -e "${BLUE}Step 7: Docker system cleanup...${NC}"

read -p "Run 'docker system prune' to free space? (yes/no): " PRUNE

if [ "$PRUNE" = "yes" ]; then
    echo ""
    docker system prune -f
    echo -e "${GREEN}✓ Docker system cleaned${NC}"
else
    echo "  Skipping system prune"
fi

echo ""

# ============================================
# Step 8: Verify cleanup
# ============================================
echo -e "${BLUE}Step 8: Verification...${NC}"
echo ""

echo "Remaining containers:"
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
echo ""

echo "Port 80 status:"
if ss -tlnp 2>/dev/null | grep -q ":80 "; then
    echo -e "${YELLOW}  ⚠️  Port 80 still in use:${NC}"
    ss -tlnp 2>/dev/null | grep ":80 "
else
    echo -e "${GREEN}  ✓ Port 80 is FREE${NC}"
fi
echo ""

echo "Port 443 status:"
if ss -tlnp 2>/dev/null | grep -q ":443 "; then
    echo -e "${YELLOW}  ⚠️  Port 443 still in use:${NC}"
    ss -tlnp 2>/dev/null | grep ":443 "
else
    echo -e "${GREEN}  ✓ Port 443 is FREE${NC}"
fi
echo ""

# ============================================
# Summary
# ============================================
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "What was removed:"
echo "  ✓ Android emulator containers (android1, android2, android3)"
echo "  ✓ ai-manus-frontend container"
echo "  ✓ ai-manus-mongodb container"
if [ "$REMOVE_MITM" = "yes" ]; then
    echo "  ✓ mitmproxy container"
fi
if [ "$REMOVE_IMAGES" = "yes" ]; then
    echo "  ✓ Related Docker images"
fi
echo ""
echo "Next steps:"
echo "  1. Verify ports are free: ss -tlnp | grep -E ':80 |:443 '"
echo "  2. Run RAGLOX deployment: sudo bash /opt/raglox/webapp/deploy_production.sh"
echo ""
echo -e "${BLUE}Ready to deploy RAGLOX on raglox.com!${NC}"
echo ""
