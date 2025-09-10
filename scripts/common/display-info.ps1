# Enhanced connection info display for Windows
param()

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "🔐 ===== REMOTE ACCESS DETAILS ===== " -ForegroundColor Cyan
Write-Host "🖥️  Device Type: $env:DEVICE_TYPE" -ForegroundColor White
Write-Host "🌐 Tailscale IP: $env:TAILSCALE_IP" -ForegroundColor Yellow
Write-Host "👤 Credentials: $env:RDP_CREDS" -ForegroundColor Green
Write-Host "🔌 Port: $env:CONNECTION_PORT" -ForegroundColor White
Write-Host "📱 Protocol: $env:CONNECTION_PROTOCOL" -ForegroundColor Magenta

# Windows-specific information
Write-Host ""
Write-Host "🔧 Recommended Clients:" -ForegroundColor Blue
Write-Host "  • Windows Remote Desktop (built-in)" -ForegroundColor Gray
Write-Host "  • Microsoft Remote Desktop (mobile/macOS)" -ForegroundColor Gray
Write-Host "  • FreeRDP (Linux/cross-platform)" -ForegroundColor Gray
Write-Host "  • Remmina (Linux)" -ForegroundColor Gray

# Connection instructions
Write-Host ""
Write-Host "📋 Connection Instructions:" -ForegroundColor Blue
Write-Host "  1. Open Remote Desktop client" -ForegroundColor Gray
Write-Host "  2. Enter server: $env:TAILSCALE_IP`:$env:CONNECTION_PORT" -ForegroundColor Gray
Write-Host "  3. Use provided credentials when prompted" -ForegroundColor Gray

# Session information
Write-Host ""
Write-Host "⏰ Session Duration: $env:SESSION_DURATION minutes" -ForegroundColor Yellow
Write-Host "📊 Setup Status: $env:SETUP_STATUS" -ForegroundColor $(if($env:SETUP_STATUS -eq "SUCCESS"){"Green"}else{"Red"})
Write-Host "🏷️  Script Version: $env:SCRIPT_VERSION" -ForegroundColor Gray

if ($env:SETUP_STATUS -ne "SUCCESS") {
    Write-Host ""
    Write-Host "⚠️  Setup Issues Detected:" -ForegroundColor Yellow
    if ($env:FAILED_STEPS) {
        Write-Host "   Failed Steps: $env:FAILED_STEPS" -ForegroundColor Red
    }
}

Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""
