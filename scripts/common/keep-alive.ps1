# Enhanced keep-alive script for Windows
param()

$sessionDuration = [int]$env:SESSION_DURATION
$maxIterations = [math]::Ceiling($sessionDuration * 60 / 300)  # 5-minute intervals

Write-Host "🔄 Maintaining Windows RDP connection for $sessionDuration minutes..." -ForegroundColor Cyan
Write-Host "⚠️  Use 'Cancel workflow' button in GitHub Actions to terminate" -ForegroundColor Yellow
Write-Host ""

$counter = 0
$startTime = Get-Date

while ($counter -lt $maxIterations) {
    $currentTime = Get-Date
    $elapsed = $currentTime - $startTime
    $remaining = [TimeSpan]::FromMinutes($sessionDuration) - $elapsed
    
    $status = if ($env:SETUP_STATUS -eq "SUCCESS") { "🟢" } else { "🟡" }
    
    Write-Host "[$($currentTime.ToString('HH:mm:ss'))] $status Windows RDP Active | Remaining: $($remaining.ToString('hh\:mm\:ss'))" -ForegroundColor Green
    
    # System health check every 15 minutes
    if ($counter % 3 -eq 0 -and $counter -gt 0) {
        Write-Host "  📊 System Check - CPU: $((Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)% | RAM: $([math]::Round((Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory/1MB, 1))GB free" -ForegroundColor Gray
        
        # Check if RDP service is still running
        $rdpService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
        if ($rdpService -and $rdpService.Status -eq "Running") {
            Write-Host "  ✅ RDP Service: Running" -ForegroundColor Green
        } else {
            Write-Host "  ❌ RDP Service: Not Running" -ForegroundColor Red
        }
        
        # Check Tailscale connection
        $tailscaleStatus = & "$env:ProgramFiles\Tailscale\tailscale.exe" status --json 2>$null | ConvertFrom-Json
        if ($tailscaleStatus) {
            Write-Host "  ✅ Tailscale: Connected ($($tailscaleStatus.Self.TailscaleIPs[0]))" -ForegroundColor Green
        } else {
            Write-Host "  ❌ Tailscale: Disconnected" -ForegroundColor Red
        }
    }
    
    Start-Sleep -Seconds 300  # 5 minutes
    $counter++
}

Write-Host ""
Write-Host "⏰ Session timeout reached. Cleaning up and terminating..." -ForegroundColor Yellow
