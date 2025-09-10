#!/bin/bash

# Enhanced connection info display for macOS

# Color definitions
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

echo ""
echo -e "${CYAN}🔐 ===== REMOTE ACCESS DETAILS =====${NC}"
echo -e "${WHITE}🖥️  Device Type: ${DEVICE_TYPE:-Unknown}${NC}"
echo -e "${YELLOW}🌐 Tailscale IP: ${TAILSCALE_IP:-Not Available}${NC}"
echo -e "${GREEN}👤 Credentials: ${RDP_CREDS:-Not Available}${NC}"
echo -e "${WHITE}🔌 Port: ${CONNECTION_PORT:-5900}${NC}"
echo -e "${MAGENTA}📱 Protocol: ${CONNECTION_PROTOCOL:-VNC}${NC}"

# macOS-specific information
echo ""
echo -e "${BLUE}🔧 Recommended Clients:${NC}"
echo -e "${GRAY}  • VNC Viewer (cross-platform)${NC}"
echo -e "${GRAY}  • Screen Sharing (built-in macOS)${NC}"
echo -e "${GRAY}  • TigerVNC (Linux)${NC}"
echo -e "${GRAY}  • RealVNC (commercial)${NC}"

# Connection instructions
echo ""
echo -e "${BLUE}📋 Connection Instructions:${NC}"
echo -e "${GRAY}  1. Open VNC client${NC}"
echo -e "${GRAY}  2. Enter server: ${TAILSCALE_IP:-IP}:${CONNECTION_PORT:-5900}${NC}"
echo -e "${GRAY}  3. Use provided credentials when prompted${NC}"

# System information
if [[ -n "${MACOS_VERSION:-}" ]]; then
    echo ""
    echo -e "${BLUE}🍎 System Information:${NC}"
    echo -e "${GRAY}  • macOS Version: ${MACOS_VERSION}${NC}"
    echo -e "${GRAY}  • Hardware: ${HARDWARE_MODEL:-Unknown}${NC}"
    echo -e "${GRAY}  • Memory: ${AVAILABLE_MEMORY:-Unknown}${NC}"
fi

# Session information
echo ""
echo -e "${YELLOW}⏰ Session Duration: ${SESSION_DURATION:-Unknown} minutes${NC}"
setup_color="${GREEN}"
[[ "${SETUP_STATUS:-}" != "SUCCESS" ]] && setup_color="${RED}"
echo -e "${setup_color}📊 Setup Status: ${SETUP_STATUS:-Unknown}${NC}"
echo -e "${GRAY}🏷️  Script Version: ${SCRIPT_VERSION:-Unknown}${NC}"

# VNC test results if available
if [[ -n "${VNC_TEST_RESULTS:-}" ]]; then
    echo ""
    echo -e "${BLUE}🔍 Connectivity Tests:${NC}"
    echo -e "${GRAY}  Results: ${VNC_TEST_RESULTS}${NC}"
    echo -e "${GRAY}  Score: ${VNC_TEST_SCORE:-Unknown}${NC}"
fi

if [[ "${SETUP_STATUS:-}" != "SUCCESS" ]]; then
    echo ""
    echo -e "${YELLOW}⚠️  Setup Issues Detected:${NC}"
    [[ -n "${FAILED_STEPS:-}" ]] && echo -e "${RED}   Failed Steps: ${FAILED_STEPS}${NC}"
    [[ -n "${WARNING_STEPS:-}" ]] && echo -e "${YELLOW}   Warning Steps: ${WARNING_STEPS}${NC}"
fi

echo -e "${CYAN}=================================${NC}"
echo ""
