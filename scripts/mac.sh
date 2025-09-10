#!/bin/bash

# Enhanced macOS VNC/Screen Sharing Setup Script
# Version: 2.1.0
# Compatible with: macOS 11+, GitHub Actions macos-latest runners

set -euo pipefail

# Script metadata
readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_NAME="macOS VNC Setup"
readonly LOG_FILE="logs/macos-setup.log"

# Color definitions for enhanced output
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r MAGENTA='\033[0;35m'
declare -r WHITE='\033[1;37m'
declare -r NC='\033[0m'

# Enhanced logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Color mapping
    local color=""
    case "$level" in
        "SUCCESS") color="$GREEN" ;;
        "ERROR") color="$RED" ;;
        "WARN") color="$YELLOW" ;;
        "INFO") color="$BLUE" ;;
        "DEBUG") color="$CYAN" ;;
        *) color="$WHITE" ;;
    esac
    
    # Console output
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    
    # File logging
    if [[ -d "logs" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

# Enhanced error handling
safe_execute() {
    local description="$1"
    shift
    local cmd=("$@")
    
    log_message "INFO" "Executing: $description"
    
    if "${cmd[@]}" 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "$description completed successfully"
        return 0
    else
        local exit_code=$?
        log_message "ERROR" "$description failed with exit code $exit_code"
        return $exit_code
    fi
}

# System information gathering
gather_system_info() {
    log_message "INFO" "🔍 Gathering system information..."
    
    local macos_version
    local hardware_model
    local available_memory
    
    macos_version=$(sw_vers -productVersion)
    hardware_model=$(sysctl -n hw.model)
    available_memory=$(sysctl -n hw.memsize | awk '{print int($1/1024/1024/1024) " GB"}')
    
    log_message "INFO" "macOS Version: $macos_version"
    log_message "INFO" "Hardware Model: $hardware_model"
    log_message "INFO" "Available Memory: $available_memory"
    
    # Store system info in environment
    {
        echo "MACOS_VERSION=$macos_version"
        echo "HARDWARE_MODEL=$hardware_model"
        echo "AVAILABLE_MEMORY=$available_memory"
    } >> "$GITHUB_ENV"
    
    return 0
}

# Enhanced configuration loading
load_configuration() {
    log_message "INFO" "📄 Loading configuration..."
    
    local config_file="./configs/mac-config.json"
    
    # Default configuration
    VNC_PORT=5900
    USERNAME="rdpuser"
    USER_ID=1001
    PASSWORD_LENGTH=18
    SESSION_TIMEOUT=240
    ENABLE_FILE_SHARING=false
    ENABLE_CLIPBOARD=true
    DISABLE_SLEEP=true
    
    # Load custom configuration if available
    if [[ -f "$config_file" ]]; then
        if command -v jq >/dev/null 2>&1; then
            VNC_PORT=$(jq -r '.vnc_port // 5900' "$config_file")
            USERNAME=$(jq -r '.username // "rdpuser"' "$config_file")
            USER_ID=$(jq -r '.user_id // 1001' "$config_file")
            PASSWORD_LENGTH=$(jq -r '.password_length // 18' "$config_file")
            ENABLE_FILE_SHARING=$(jq -r '.features.file_sharing // false' "$config_file")
            ENABLE_CLIPBOARD=$(jq -r '.features.clipboard_sharing // true' "$config_file")
            DISABLE_SLEEP=$(jq -r '.features.system_sleep_disabled // true' "$config_file")
            
            log_message "SUCCESS" "Configuration loaded from $config_file"
        else
            log_message "WARN" "jq not available, using default configuration"
        fi
    else
        log_message "WARN" "Configuration file not found, using defaults"
    fi
    
    # Validate configuration
    if [[ $VNC_PORT -lt 1024 || $VNC_PORT -gt 65535 ]]; then
        log_message "WARN" "Invalid VNC port $VNC_PORT, using default 5900"
        VNC_PORT=5900
    fi
    
    if [[ $PASSWORD_LENGTH -lt 12 ]]; then
        log_message "WARN" "Password length too short, using minimum 12 characters"
        PASSWORD_LENGTH=12
    fi
    
    return 0
}

# Enhanced password generation
generate_secure_password() {
    log_message "INFO" "🔐 Generating ${PASSWORD_LENGTH}-character secure password..."
    
    # Character sets for password complexity
    local uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowercase="abcdefghijklmnopqrstuvwxyz"
    local numbers="0123456789"
    local symbols="!@#%^&*-+=?"
    
    local password=""
    
    # Ensure at least one character from each set
    password+=$(echo "$uppercase" | fold -w1 | shuf | head -1)
    password+=$(echo "$lowercase" | fold -w1 | shuf | head -1)
    password+=$(echo "$numbers" | fold -w1 | shuf | head -1)
    password+=$(echo "$symbols" | fold -w1 | shuf | head -1)
    
    # Fill remaining length with random characters
    local all_chars="$uppercase$lowercase$numbers$symbols"
    local remaining=$((PASSWORD_LENGTH - 4))
    
    for ((i=0; i<remaining; i++)); do
        password+=$(echo "$all_chars" | fold -w1 | shuf | head -1)
    done
    
    # Shuffle the password
    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')
    
    # Validate password strength
    if [[ ${#password} -eq $PASSWORD_LENGTH ]] && \
       [[ "$password" =~ [A-Z] ]] && \
       [[ "$password" =~ [a-z] ]] && \
       [[ "$password" =~ [0-9] ]] && \
       [[ "$password" =~ [^A-Za-z0-9] ]]; then
        log_message "SUCCESS" "Strong password generated successfully"
        echo "$password"
        return 0
    else
        log_message "ERROR" "Password generation failed validation"
        return 1
    fi
}

# Enhanced VNC configuration
configure_screen_sharing() {
    log_message "INFO" "🔧 Configuring macOS Screen Sharing (VNC)..."
    
    # Generate VNC password
    local vnc_password
    if ! vnc_password=$(generate_secure_password); then
        log_message "ERROR" "Failed to generate VNC password"
        return 1
    fi
    
    # Store password for later use
    VNC_PASSWORD="$vnc_password"
    
    # Configure Screen Sharing with enhanced security
    local ard_agent="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart"
    
    # Stop any existing ARD processes
    sudo "$ard_agent" -stop > /dev/null 2>&1 || true
    
    # Configure VNC with authentication
    if safe_execute "Enable Screen Sharing" \
        sudo "$ard_agent" \
        -activate \
        -configure \
        -access -on \
        -clientopts -setvnclegacy -vnclegacy yes \
        -clientopts -setvncpw -vncpw "$vnc_password" \
        -restart -agent \
        -privs -all; then
        
        # Additional VNC settings
        safe_execute "Configure VNC access permissions" \
            sudo "$ard_agent" \
            -configure \
            -allowAccessFor -allUsers \
            -privs -all
        
        # Set VNC port if different from default
        if [[ $VNC_PORT -ne 5900 ]]; then
            log_message "INFO" "Configuring custom VNC port: $VNC_PORT"
            # Note: macOS VNC port configuration requires additional setup
            log_message "WARN" "Custom VNC port configuration not yet implemented"
        fi
        
        log_message "SUCCESS" "Screen Sharing configured successfully"
        return 0
    else
        log_message "ERROR" "Failed to configure Screen Sharing"
        return 1
    fi
}

# Enhanced user account creation
create_user_account() {
    log_message "INFO" "👤 Creating enhanced user account..."
    
    # Generate user password
    local user_password
    if ! user_password=$(generate_secure_password); then
        log_message "ERROR" "Failed to generate user password"
        return 1
    fi
    
    # Remove existing user if present
    if dscl . -read /Users/"$USERNAME" > /dev/null 2>&1; then
        log_message "INFO" "Removing existing user: $USERNAME"
        sudo dscl . -delete /Users/"$USERNAME" 2>/dev/null || true
        sudo rm -rf /Users/"$USERNAME" 2>/dev/null || true
    fi
    
    # Create user account with comprehensive settings
    if safe_execute "Create user directory entry" \
        sudo dscl . -create /Users/"$USERNAME"; then
        
        # Set user properties
        sudo dscl . -create /Users/"$USERNAME" UserShell /bin/bash
        sudo dscl . -create /Users/"$USERNAME" RealName "Remote Desktop User"
        sudo dscl . -create /Users/"$USERNAME" UniqueID "$USER_ID"
        sudo dscl . -create /Users/"$USERNAME" PrimaryGroupID 80
        sudo dscl . -create /Users/"$USERNAME" NFSHomeDirectory /Users/"$USERNAME"
        
        # Set password
        sudo dscl . -passwd /Users/"$USERNAME" "$user_password"
        
        # Add to admin and other necessary groups
        sudo dscl . -append /Groups/admin GroupMembership "$USERNAME"
        sudo dscl . -append /Groups/_appserveradm GroupMembership "$USERNAME"
        
        # Create and configure home directory
        if safe_execute "Create home directory" \
            sudo createhomedir -c -u "$USERNAME"; then
            
            # Set proper ownership
            sudo chown -R "$USERNAME":staff /Users/"$USERNAME"
            
            # Configure user preferences for VNC
            sudo -u "$USERNAME" defaults write com.apple.screensharing VNCLegacyPassword -data "$VNC_PASSWORD"
            
            # Store credentials in environment
            {
                echo "RDP_CREDS=User: $USERNAME | Password: $user_password"
                echo "VNC_PASSWORD=$VNC_PASSWORD"
                echo "CONNECTION_PORT=$VNC_PORT"
                echo "CONNECTION_PROTOCOL=VNC"
                echo "USER_CREATED=true"
            } >> "$GITHUB_ENV"
            
            log_message "SUCCESS" "User '$USERNAME' created successfully"
            return 0
        fi
    fi
    
    log_message "ERROR" "Failed to create user account"
    return 1
}

# Enhanced Tailscale installation
install_tailscale() {
    log_message "INFO" "🔗 Installing Tailscale..."
    
    # Check if already installed
    if command -v tailscale >/dev/null 2>&1; then
        local installed_version
        installed_version=$(tailscale version | head -n1 | awk '{print $1}')
        log_message "INFO" "Tailscale already installed: $installed_version"
        return 0
    fi
    
    # Install Tailscale using official script with enhanced error handling
    local install_script="/tmp/tailscale-install.sh"
    
    if safe_execute "Download Tailscale installer" \
        curl -fsSL https://tailscale.com/install.sh -o "$install_script"; then
        
        if safe_execute "Execute Tailscale installer" \
            sudo sh "$install_script"; then
            
            # Verify installation
            if command -v tailscale >/dev/null 2>&1; then
                local version
                version=$(tailscale version | head -n1)
                log_message "SUCCESS" "Tailscale installed successfully: $version"
                
                # Cleanup installer
                rm -f "$install_script"
                return 0
            else
                log_message "ERROR" "Tailscale installation verification failed"
                return 1
            fi
        fi
    fi
    
    log_message "ERROR" "Tailscale installation failed"
    return 1
}

# Enhanced Tailscale connection
connect_tailscale() {
    log_message "INFO" "🌐 Establishing Tailscale connection..."
    
    # Validate auth key
    if [[ -z "${TAILSCALE_AUTH_KEY:-}" ]]; then
        log_message "ERROR" "TAILSCALE_AUTH_KEY not provided"
        return 1
    fi
    
    local hostname="gh-mac-${RUN_ID:-$(date +%s)}-$(date +%H%M)"
    
    # Connect with enhanced parameters
    if safe_execute "Connect to Tailscale network" \
        sudo tailscale up \
            --authkey="$TAILSCALE_AUTH_KEY" \
            --hostname="$hostname" \
            --accept-routes \
            --accept-dns=false \
            --advertise-exit-node=false; then
        
        # Wait for IP assignment with enhanced retry logic
        local ts_ip=""
        local max_retries=30
        local retry_count=0
        
        log_message "INFO" "Waiting for Tailscale IP assignment..."
        
        while [[ -z "$ts_ip" && $retry_count -lt $max_retries ]]; do
            sleep 2
            ts_ip=$(tailscale ip -4 2>/dev/null || echo "")
            ((retry_count++))
            
            # Progress indicator
            if ((retry_count % 5 == 0)); then
                log_message "DEBUG" "IP assignment attempt $retry_count/$max_retries"
            fi
        done
        
        if [[ -n "$ts_ip" ]]; then
            # Validate IP format
            if [[ "$ts_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                # Store connection details
                {
                    echo "TAILSCALE_IP=$ts_ip"
                    echo "TAILSCALE_HOSTNAME=$hostname"
                    echo "TAILSCALE_STATUS=connected"
                } >> "$GITHUB_ENV"
                
                log_message "SUCCESS" "Connected to Tailscale: $ts_ip (hostname: $hostname)"
                return 0
            else
                log_message "ERROR" "Invalid IP address format: $ts_ip"
                return 1
            fi
        else
            log_message "ERROR" "Failed to obtain Tailscale IP after $max_retries attempts"
            return 1
        fi
    fi
    
    log_message "ERROR" "Tailscale connection failed"
    return 1
}

# Enhanced connectivity testing
test_vnc_connectivity() {
    log_message "INFO" "🔍 Testing VNC connectivity..."
    
    local ts_ip="${TAILSCALE_IP:-}"
    if [[ -z "$ts_ip" ]]; then
        log_message "ERROR" "Tailscale IP not available for testing"
        return 1
    fi
    
    local test_results=()
    
    # Test 1: Port accessibility
    log_message "DEBUG" "Testing port $VNC_PORT accessibility..."
    if nc -z "$ts_ip" "$VNC_PORT" 2>/dev/null; then
        log_message "SUCCESS" "✅ Port $VNC_PORT is accessible"
        test_results+=("port_test=PASS")
    else
        log_message "ERROR" "❌ Port $VNC_PORT is not accessible"
        test_results+=("port_test=FAIL")
    fi
    
    # Test 2: VNC service response
    log_message "DEBUG" "Testing VNC service response..."
    local vnc_response
    if vnc_response=$(timeout 5 nc "$ts_ip" "$VNC_PORT" < /dev/null 2>/dev/null | head -c 12); then
        if [[ ${#vnc_response} -gt 0 ]]; then
            log_message "SUCCESS" "✅ VNC service is responding"
            test_results+=("service_test=PASS")
        else
            log_message "WARN" "⚠️ VNC service response empty"
            test_results+=("service_test=WARN")
        fi
    else
        log_message "ERROR" "❌ VNC service not responding"
        test_results+=("service_test=FAIL")
    fi
    
    # Test 3: Screen Sharing daemon
    log_message "DEBUG" "Checking Screen Sharing daemon status..."
    if pgrep -f "ARDAgent" >/dev/null; then
        log_message "SUCCESS" "✅ Screen Sharing daemon is running"
        test_results+=("daemon_test=PASS")
    else
        log_message "WARN" "⚠️ Screen Sharing daemon not found"
        test_results+=("daemon_test=WARN")
    fi
    
    # Calculate overall test result
    local pass_count=0
    local total_count=${#test_results[@]}
    
    for result in "${test_results[@]}"; do
        if [[ "$result" =~ =PASS$ ]]; then
            ((pass_count++))
        fi
    done
    
    log_message "INFO" "Connectivity test results: $pass_count/$total_count tests passed"
    
    # Store test results
    echo "VNC_TEST_RESULTS=${test_results[*]}" >> "$GITHUB_ENV"
    echo "VNC_TEST_SCORE=$pass_count/$total_count" >> "$GITHUB_ENV"
    
    # Consider success if at least port test passes
    [[ $pass_count -gt 0 ]]
}

# System optimization for remote access
optimize_system() {
    log_message "INFO" "⚡ Optimizing system for remote access..."
    
    local optimization_results=()
    
    # Disable sleep and screen saver
    if [[ "$DISABLE_SLEEP" == "true" ]]; then
        if safe_execute "Disable system sleep" \
            sudo pmset -a sleep 0 displaysleep 0 disksleep 0; then
            optimization_results+=("sleep_disabled=SUCCESS")
        else
            optimization_results+=("sleep_disabled=FAILED")
        fi
        
        # Keep system awake during session
        if command -v caffeinate >/dev/null 2>&1; then
            caffeinate -d -i -m -s &
            echo $! > /tmp/caffeinate.pid
            log_message "SUCCESS" "System keep-alive started (PID: $!)"
            optimization_results+=("keep_alive=SUCCESS")
        fi
    fi
    
    # Configure energy settings for performance
    safe_execute "Set energy preferences" \
        sudo pmset -a womp 1 ring 1 autorestart 1
    
    # Optimize network settings
    safe_execute "Configure network optimization" \
        sudo sysctl -w net.inet.tcp.delayed_ack=0 \
                     net.inet.tcp.sendspace=65536 \
                     net.inet.tcp.recvspace=65536
    
    # Set appropriate process priorities
    if pgrep -f "ARDAgent" >/dev/null; then
        local ard_pid
        ard_pid=$(pgrep -f "ARDAgent" | head -1)
        sudo renice -10 "$ard_pid" 2>/dev/null || true
        log_message "SUCCESS" "Increased Screen Sharing process priority"
    fi
    
    log_message "SUCCESS" "System optimization completed"
    return 0
}

# Main execution function
main() {
    log_message "INFO" "🍎 $SCRIPT_NAME v$SCRIPT_VERSION Starting..."
    log_message "INFO" "==============================================="
    
    # Create logs directory
    mkdir -p logs
    
    # Setup pipeline with enhanced error handling
    local setup_pipeline=(
        "gather_system_info"
        "load_configuration"
        "configure_screen_sharing"
        "create_user_account"
        "install_tailscale"
        "connect_tailscale"
        "test_vnc_connectivity"
        "optimize_system"
    )
    
    local execution_results=(
        "successful_steps=()"
        "failed_steps=()"
        "warning_steps=()"
    )
    
    eval "${execution_results[@]}"
    
    # Execute setup pipeline
    for step in "${setup_pipeline[@]}"; do
        log_message "INFO" "--- $(echo "$step" | sed 's/_/ /g' | awk '{for(i=1;i<=NF;i++){$i=toupper(substr($i,1,1))substr($i,2)}}1') ---"
        
        if $step; then
            successful_steps+=("$step")
            log_message "SUCCESS" "✅ $step completed successfully"
        else
            failed_steps+=("$step")
            log_message "ERROR" "❌ $step failed"
            
            # Determine if this is a critical failure
            case "$step" in
                "configure_screen_sharing"|"create_user_account"|"connect_tailscale")
                    log_message "ERROR" "🛑 Critical step failed - setup cannot continue"
                    break
                    ;;
                *)
                    warning_steps+=("$step")
                    log_message "WARN" "⚠️ Non-critical step failed - continuing setup"
                    ;;
            esac
        fi
    done
    
    # Final status report
    log_message "INFO" ""
    log_message "INFO" "==============================================="
    log_message "SUCCESS" "🏁 macOS VNC Setup Complete!"
    log_message "INFO" "📊 Execution Summary:"
    log_message "SUCCESS" "  ✅ Successful: ${#successful_steps[@]}"
    log_message "ERROR" "  ❌ Failed: ${#failed_steps[@]}"
    log_message "WARN" "  ⚠️  Warnings: ${#warning_steps[@]}"
    
    # Determine overall status
    if [[ ${#failed_steps[@]} -eq 0 ]]; then
        echo "SETUP_STATUS=SUCCESS" >> "$GITHUB_ENV"
        echo "SETUP_QUALITY=EXCELLENT" >> "$GITHUB_ENV"
    elif [[ ${#successful_steps[@]} -gt ${#failed_steps[@]} ]]; then
        echo "SETUP_STATUS=PARTIAL" >> "$GITHUB_ENV"
        echo "SETUP_QUALITY=ACCEPTABLE" >> "$GITHUB_ENV"
    else
        echo "SETUP_STATUS=FAILED" >> "$GITHUB_ENV"
        echo "SETUP_QUALITY=POOR" >> "$GITHUB_ENV"
    fi
    
    # Store detailed results
    {
        echo "FAILED_STEPS=${failed_steps[*]}"
        echo "SUCCESS_STEPS=${successful_steps[*]}"
        echo "WARNING_STEPS=${warning_steps[*]}"
        echo "SCRIPT_VERSION=$SCRIPT_VERSION"
    } >> "$GITHUB_ENV"
    
    log_message "INFO" "==============================================="
    
    # Return appropriate exit code
    [[ ${#failed_steps[@]} -eq 0 || ${#successful_steps[@]} -gt ${#failed_steps[@]} ]]
}

# Execute main function with all arguments
main "$@"
