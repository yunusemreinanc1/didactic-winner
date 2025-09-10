#!/bin/bash

# Enhanced keep-alive script for macOS

readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly GRAY='\033[0;37m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

session_duration="${SESSION_DURATION:-240}"
max_iterations=$((session_duration * 60 / 300))  # 5-minute intervals

echo -e "${CYAN}🔄 Maintaining macOS VNC connection for $session_duration minutes...${NC}"
echo -e "${YELLOW}⚠️  Use 'Cancel workflow' button in GitHub Actions to terminate${NC}"
echo ""

counter=0
start_time=$(date +%s)

while [[ $counter -lt $max_iterations ]]; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    remaining=$((session_duration * 60 - elapsed))
    
    # Format remaining time
    hours=$((remaining / 3600))
    minutes=$(((remaining % 3600) / 60))
    seconds=$((remaining % 60))
    
    status="🟢"
    [[ "${SETUP_STATUS:-}" != "SUCCESS" ]] && status="🟡"
    
    printf "[%s] %s macOS VNC Active | Remaining: %02d:%02d:%02d\n" \
           "$(date '+%H:%M:%S')" "$status" "$hours" "$minutes" "$seconds"
    
    # System health check every 15 minutes
    if [[ $((counter % 3)) -eq 0 && $counter -gt 0 ]]; then
        # CPU usage
        cpu_usage=$(top -l 1 -n 0 | grep "CPU usage" | awk '{print $3}' | sed 's/%//')
        
        # Memory usage
        memory_info=$(vm_stat | grep "Pages free" | awk '{print $3}' | sed 's/\.//')
        free_memory=$((memory_info * 4096 / 1024 / 1024))  # Convert to MB
        
        echo -e "${GRAY}  📊 System Check - CPU: ${cpu_usage}% | RAM: ${free_memory}MB free${NC}"
        
        # Check VNC/Screen Sharing status
        if pgrep -f "ARDAgent" >/dev/null; then
            echo -e "${GREEN}  ✅ VNC Service: Running${NC}"
        else
            echo -e "${RED}  ❌ VNC Service: Not Running${NC}"
        fi
        
        # Check Tailscale connection
        if command -v tailscale >/dev/null 2>&1; then
            if tailscale_status=$(tailscale status 2>/dev/null) && [[ -n "$tailscale_status" ]]; then
                tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "Unknown")
                echo -e "${GREEN}  ✅ Tailscale: Connected ($tailscale_ip)${NC}"
            else
                echo -e "${RED}  ❌ Tailscale: Disconnected${NC}"
            fi
        fi
        
        # Check active VNC connections
        vnc_connections=$(netstat -an | grep ":$VNC_PORT " | grep ESTABLISHED | wc -l)
        if [[ $vnc_connections -gt 0 ]]; then
            echo -e "${GREEN}  👥 Active VNC connections: $vnc_connections${NC}"
        else
            echo -e "${GRAY}  👥 Active VNC connections: 0${NC}"
        fi
    fi
    
    sleep 300  # 5 minutes
    ((counter++))
done

echo ""
echo -e "${YELLOW}⏰ Session timeout reached. Cleaning up and terminating...${NC}"

# Cleanup processes if they exist
if [[ -f "/tmp/caffeinate.pid" ]]; then
    caffeinate_pid=$(cat /tmp/caffeinate.pid)
    kill "$caffeinate_pid" 2>/dev/null || true
    rm -f /tmp/caffeinate.pid
    echo -e "${GRAY}🧹 Stopped keep-alive process${NC}"
fi
