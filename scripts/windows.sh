#!/usr/bin/env pwsh
#Requires -Version 5.1

<#
.SYNOPSIS
    Enhanced Windows RDP Setup Script for GitHub Actions
.DESCRIPTION
    Automated RDP configuration with Tailscale integration, security enhancements,
    and comprehensive error handling for GitHub Actions runners.
.PARAMETER Verbose
    Enable verbose logging and debug output
.PARAMETER ConfigPath
    Path to custom configuration file
.EXAMPLE
    .\windows.sh -Verbose
#>

param(
    [switch]$Verbose,
    [string]$ConfigPath = "./configs/windows-config.json",
    [string]$AuthKey = $env:TAILSCALE_AUTH_KEY,
    [string]$SessionDuration = $env:SESSION_DURATION,
    [string]$RunId = $env:RUN_ID
)

# Script metadata
$ScriptVersion = "2.1.0"
$ScriptName = "Windows RDP Setup"
$LogFile = "logs/windows-setup.log"

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            "DEBUG" { "Cyan" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    
    # File logging
    if (Test-Path "logs") {
        $logEntry | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
}

# Enhanced error handling
function Invoke-SafeCommand {
    param(
        [scriptblock]$Command,
        [string]$ErrorMessage = "Command failed",
        [switch]$ContinueOnError
    )
    
    try {
        $result = & $Command
        return @{ Success = $true; Result = $result; Error = $null }
    }
    catch {
        Write-Log -Message "$ErrorMessage : $($_.Exception.Message)" -Level "ERROR"
        if (-not $ContinueOnError) {
            throw
        }
        return @{ Success = $false; Result = $null; Error = $_.Exception.Message }
    }
}

Write-Log -Message "🪟 $ScriptName v$ScriptVersion Starting..." -Level "INFO"
Write-Log -Message "===============================================" -Level "INFO"

# Load and validate configuration
$config = @{
    rdp_port = 3389
    user_name = "RDPUser"
    password_length = 18
    firewall_rule_name = "GitHub-RDP-Access"
    enable_clipboard = $true
    enable_drives = $true
    max_concurrent_sessions = 2
    session_timeout_minutes = 15
    security_level = "enhanced"
}

if (Test-Path $ConfigPath) {
    try {
        $customConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        foreach ($key in $customConfig.PSObject.Properties.Name) {
            $config[$key] = $customConfig.$key
        }
        Write-Log -Message "✅ Configuration loaded from $ConfigPath" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "⚠️ Failed to load config, using defaults: $($_.Exception.Message)" -Level "WARN"
    }
} else {
    Write-Log -Message "⚠️ Config file not found, using default configuration" -Level "WARN"
}

# Enhanced RDP configuration function
function Initialize-RDPConfiguration {
    Write-Log -Message "🔧 Configuring advanced RDP settings..." -Level "INFO"
    
    $rdpSettings = @(
        @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'; Name = 'fDenyTSConnections'; Value = 0 },
        @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'UserAuthentication'; Value = 0 },
        @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'SecurityLayer'; Value = 0 },
        @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'MinEncryptionLevel'; Value = 2 },
        @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'PortNumber'; Value = $config.rdp_port }
    )
    
    if ($config.enable_clipboard) {
        $rdpSettings += @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'fDisableClip'; Value = 0 }
    }
    
    if ($config.enable_drives) {
        $rdpSettings += @{ Path = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'fDisableCdm'; Value = 0 }
    }
    
    $successCount = 0
    foreach ($setting in $rdpSettings) {
        $result = Invoke-SafeCommand -Command {
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force
        } -ErrorMessage "Failed to set registry value $($setting.Name)" -ContinueOnError
        
        if ($result.Success) { $successCount++ }
    }
    
    Write-Log -Message "✅ RDP registry configuration: $successCount/$($rdpSettings.Count) settings applied" -Level "SUCCESS"
    return $successCount -eq $rdpSettings.Count
}

# Enhanced firewall configuration
function Initialize-FirewallRules {
    Write-Log -Message "🔥 Configuring Windows Firewall rules..." -Level "INFO"
    
    # Remove existing rules
    netsh advfirewall firewall delete rule name="$($config.firewall_rule_name)" 2>$null
    
    # Add comprehensive firewall rules
    $firewallRules = @(
        "netsh advfirewall firewall add rule name=`"$($config.firewall_rule_name)-Inbound`" dir=in action=allow protocol=TCP localport=$($config.rdp_port)",
        "netsh advfirewall firewall add rule name=`"$($config.firewall_rule_name)-Outbound`" dir=out action=allow protocol=TCP remoteport=$($config.rdp_port)"
    )
    
    $successCount = 0
    foreach ($rule in $firewallRules) {
        $result = Invoke-Expression $rule
        if ($LASTEXITCODE -eq 0) {
            $successCount++
        } else {
            Write-Log -Message "Failed to add firewall rule: $rule" -Level "WARN"
        }
    }
    
    Write-Log -Message "✅ Firewall configuration: $successCount/$($firewallRules.Count) rules added" -Level "SUCCESS"
    return $successCount -gt 0
}

# Enhanced password generation
function New-SecurePassword {
    param([int]$Length = $config.password_length)
    
    Write-Log -Message "🔐 Generating $Length-character secure password..." -Level "INFO"
    
    Add-Type -AssemblyName System.Security
    
    $charSets = @{
        Uppercase = [char[]](65..90)     # A-Z
        Lowercase = [char[]](97..122)    # a-z
        Numbers = [char[]](48..57)       # 0-9
        Symbols = [char[]](33,35,36,37,38,42,43,45,61,63,64,94,126)  # Safe symbols
    }
    
    # Ensure at least one character from each set
    $password = @()
    $password += $charSets.Uppercase | Get-Random -Count 3
    $password += $charSets.Lowercase | Get-Random -Count 3
    $password += $charSets.Numbers | Get-Random -Count 3
    $password += $charSets.Symbols | Get-Random -Count 2
    
    # Fill remaining length
    $remainingLength = $Length - $password.Count
    if ($remainingLength -gt 0) {
        $allChars = $charSets.Values | ForEach-Object { $_ }
        $password += $allChars | Get-Random -Count $remainingLength
    }
    
    $finalPassword = -join ($password | Sort-Object { Get-Random })
    
    # Password strength validation
    $hasUpper = $finalPassword -cmatch '[A-Z]'
    $hasLower = $finalPassword -cmatch '[a-z]'
    $hasDigit = $finalPassword -cmatch '[0-9]'
    $hasSymbol = $finalPassword -match '[^A-Za-z0-9]'
    
    if ($hasUpper -and $hasLower -and $hasDigit -and $hasSymbol) {
        Write-Log -Message "✅ Strong password generated successfully" -Level "SUCCESS"
        return $finalPassword
    } else {
        Write-Log -Message "⚠️ Password strength validation failed, regenerating..." -Level "WARN"
        return New-SecurePassword -Length $Length
    }
}

# Enhanced user creation
function New-RDPUserAccount {
    Write-Log -Message "👤 Creating enhanced RDP user account..." -Level "INFO"
    
    $password = New-SecurePassword
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    
    # Remove existing user
    try {
        Remove-LocalUser -Name $config.user_name -ErrorAction SilentlyContinue
        Write-Log -Message "Removed existing user account" -Level "DEBUG"
    } catch {}
    
    # Create new user with enhanced settings
    $result = Invoke-SafeCommand -Command {
        $user = New-LocalUser -Name $config.user_name -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop
        
        # Add to groups
        Add-LocalGroupMember -Group "Administrators" -Member $config.user_name -ErrorAction Stop
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $config.user_name -ErrorAction Stop
        
        # Set user rights
        $user | Set-LocalUser -UserMayChangePassword $false -ErrorAction Stop
        
        return $user
    } -ErrorMessage "Failed to create RDP user"
    
    if ($result.Success) {
        # Store credentials securely
        $credInfo = "User: $($config.user_name) | Password: $password"
        echo "RDP_CREDS=$credInfo" >> $env:GITHUB_ENV
        echo "CONNECTION_PORT=$($config.rdp_port)" >> $env:GITHUB_ENV
        echo "CONNECTION_PROTOCOL=RDP" >> $env:GITHUB_ENV
        echo "USER_CREATED=true" >> $env:GITHUB_ENV
        
        Write-Log -Message "✅ RDP user '$($config.user_name)' created successfully" -Level "SUCCESS"
        return $true
    }
    
    return $false
}

# Enhanced service management
function Initialize-RDPServices {
    Write-Log -Message "🔄 Configuring RDP services..." -Level "INFO"
    
    $services = @("TermService", "UmRdpService", "SessionEnv")
    $successCount = 0
    
    foreach ($serviceName in $services) {
        $result = Invoke-SafeCommand -Command {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            if ($service.Status -ne "Running") {
                Start-Service -Name $serviceName -ErrorAction Stop
            }
            Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
        } -ErrorMessage "Failed to configure service $serviceName" -ContinueOnError
        
        if ($result.Success) {
            $successCount++
            Write-Log -Message "✅ Service $serviceName configured" -Level "DEBUG"
        }
    }
    
    Write-Log -Message "✅ RDP services: $successCount/$($services.Count) configured successfully" -Level "SUCCESS"
    return $successCount -gt 0
}

# Enhanced Tailscale installation
function Install-TailscaleClient {
    Write-Log -Message "🔗 Installing Tailscale client..." -Level "INFO"
    
    $tsVersion = "1.82.0"
    $tsUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-$tsVersion-amd64.msi"
    $installerPath = "$env:TEMP\tailscale-setup.msi"
    
    $result = Invoke-SafeCommand -Command {
        # Download with progress
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($tsUrl, $installerPath)
        
        if (-not (Test-Path $installerPath)) {
            throw "Download failed - installer not found"
        }
        
        # Verify file size (approximate check)
        $fileSize = (Get-Item $installerPath).Length
        if ($fileSize -lt 1MB) {
            throw "Downloaded file too small - may be corrupted"
        }
        
        # Install with detailed logging
        $installArgs = @("/i", "`"$installerPath`"", "/quiet", "/norestart", "/l*v", "`"$env:TEMP\tailscale-install.log`"")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            throw "Installation failed with exit code $($process.ExitCode)"
        }
        
        # Verify installation
        $tailscalePath = "$env:ProgramFiles\Tailscale\tailscale.exe"
        if (-not (Test-Path $tailscalePath)) {
            throw "Tailscale executable not found after installation"
        }
        
        return $tailscalePath
    } -ErrorMessage "Tailscale installation failed"
    
    # Cleanup
    if (Test-Path $installerPath) {
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    }
    
    if ($result.Success) {
        Write-Log -Message "✅ Tailscale installed successfully: $($result.Result)" -Level "SUCCESS"
        return $true
    }
    
    return $false
}

# Enhanced Tailscale connection
function Connect-TailscaleNetwork {
    Write-Log -Message "🌐 Establishing Tailscale connection..." -Level "INFO"
    
    $hostname = "gh-win-$RunId-$(Get-Date -Format 'HHmm')"
    $tailscaleExe = "$env:ProgramFiles\Tailscale\tailscale.exe"
    
    $result = Invoke-SafeCommand -Command {
        # Connect with enhanced parameters
        $connectArgs = @(
            "up",
            "--authkey=$AuthKey",
            "--hostname=$hostname",
            "--accept-routes",
            "--accept-dns=false",
            "--advertise-exit-node=false"
        )
        
        & $tailscaleExe @connectArgs
        
        if ($LASTEXITCODE -ne 0) {
            throw "Tailscale connection failed with exit code $LASTEXITCODE"
        }
        
        # Wait for IP assignment with timeout
        $maxRetries = 30
        $retryCount = 0
        $tsIP = $null
        
        do {
            Start-Sleep -Seconds 2
            $tsIP = & $tailscaleExe ip -4 2>$null
            $retryCount++
            
            if ($Verbose -and $retryCount % 5 -eq 0) {
                Write-Log -Message "Waiting for IP assignment... attempt $retryCount/$maxRetries" -Level "DEBUG"
            }
        } while (-not $tsIP -and $retryCount -lt $maxRetries)
        
        if (-not $tsIP) {
            throw "Failed to obtain Tailscale IP after $maxRetries attempts"
        }
        
        # Validate IP format
        if ($tsIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
            throw "Invalid IP address format: $tsIP"
        }
        
        return $tsIP
    } -ErrorMessage "Tailscale network connection failed"
    
    if ($result.Success) {
        $tsIP = $result.Result
        echo "TAILSCALE_IP=$tsIP" >> $env:GITHUB_ENV
        echo "TAILSCALE_HOSTNAME=$hostname" >> $env:GITHUB_ENV
        Write-Log -Message "✅ Connected to Tailscale network: $tsIP (hostname: $hostname)" -Level "SUCCESS"
        return $true
    }
    
    return $false
}

# Enhanced connectivity testing
function Test-RDPConnectivity {
    Write-Log -Message "🔍 Testing RDP connectivity..." -Level "INFO"
    
    $tsIP = $env:TAILSCALE_IP
    $testResults = @{}
    
    # Test TCP connectivity
    $result = Invoke-SafeCommand -Command {
        $tcpTest = Test-NetConnection -ComputerName $tsIP -Port $config.rdp_port -InformationLevel Quiet
        return $tcpTest
    } -ErrorMessage "TCP connectivity test failed" -ContinueOnError
    
    $testResults["TCP"] = $result.Success -and $result.Result
    
    # Test RDP service responsiveness
    if ($testResults["TCP"]) {
        $result = Invoke-SafeCommand -Command {
            $socket = New-Object System.Net.Sockets.TcpClient
            $socket.ReceiveTimeout = 5000
            $socket.SendTimeout = 5000
            $socket.Connect($tsIP, $config.rdp_port)
            $connected = $socket.Connected
            $socket.Close()
            return $connected
        } -ErrorMessage "RDP service test failed" -ContinueOnError
        
        $testResults["RDP_Service"] = $result.Success -and $result.Result
    }
    
    # Report results
    $successTests = ($testResults.Values | Where-Object { $_ }).Count
    $totalTests = $testResults.Count
    
    Write-Log -Message "✅ Connectivity tests: $successTests/$totalTests passed" -Level "SUCCESS"
    
    foreach ($test in $testResults.GetEnumerator()) {
        $status = if ($test.Value) { "✅ PASS" } else { "❌ FAIL" }
        Write-Log -Message "  $($test.Key): $status" -Level "DEBUG"
    }
    
    return $successTests -eq $totalTests
}

# Main execution pipeline
Write-Log -Message "🚀 Executing Windows RDP setup pipeline..." -Level "INFO"

$setupPipeline = @(
    @{ Name = "Initialize RDP Configuration"; Function = { Initialize-RDPConfiguration }; Critical = $true },
    @{ Name = "Configure Firewall Rules"; Function = { Initialize-FirewallRules }; Critical = $true },
    @{ Name = "Create RDP User Account"; Function = { New-RDPUserAccount }; Critical = $true },
    @{ Name = "Configure RDP Services"; Function = { Initialize-RDPServices }; Critical = $true },
    @{ Name = "Install Tailscale Client"; Function = { Install-TailscaleClient }; Critical = $true },
    @{ Name = "Connect Tailscale Network"; Function = { Connect-TailscaleNetwork }; Critical = $true },
    @{ Name = "Test RDP Connectivity"; Function = { Test-RDPConnectivity }; Critical = $false }
)

$executionResults = @{
    Successful = @()
    Failed = @()
    Warnings = @()
}

foreach ($step in $setupPipeline) {
    Write-Log -Message "`n--- $($step.Name) ---" -Level "INFO"
    
    try {
        $stepResult = & $step.Function
        
        if ($stepResult) {
            $executionResults.Successful += $step.Name
            Write-Log -Message "✅ $($step.Name) completed successfully" -Level "SUCCESS"
        } else {
            $executionResults.Failed += $step.Name
            Write-Log -Message "❌ $($step.Name) failed" -Level "ERROR"
            
            if ($step.Critical) {
                throw "Critical step failed: $($step.Name)"
            } else {
                $executionResults.Warnings += $step.Name
            }
        }
    }
    catch {
        $executionResults.Failed += $step.Name
        Write-Log -Message "❌ $($step.Name) exception: $($_.Exception.Message)" -Level "ERROR"
        
        if ($step.Critical) {
            Write-Log -Message "🛑 Critical failure - aborting setup" -Level "ERROR"
            break
        }
    }
}

# Final status report
Write-Log -Message "`n===============================================" -Level "INFO"
Write-Log -Message "🏁 Windows RDP Setup Complete!" -Level "SUCCESS"
Write-Log -Message "📊 Execution Summary:" -Level "INFO"
Write-Log -Message "  ✅ Successful: $($executionResults.Successful.Count)" -Level "SUCCESS"
Write-Log -Message "  ❌ Failed: $($executionResults.Failed.Count)" -Level "ERROR"
Write-Log -Message "  ⚠️  Warnings: $($executionResults.Warnings.Count)" -Level "WARN"

# Set final status
if ($executionResults.Failed.Count -eq 0) {
    echo "SETUP_STATUS=SUCCESS" >> $env:GITHUB_ENV
    echo "SETUP_QUALITY=EXCELLENT" >> $env:GITHUB_ENV
} elseif ($executionResults.Successful.Count -gt $executionResults.Failed.Count) {
    echo "SETUP_STATUS=PARTIAL" >> $env:GITHUB_ENV
    echo "SETUP_QUALITY=ACCEPTABLE" >> $env:GITHUB_ENV
} else {
    echo "SETUP_STATUS=FAILED" >> $env:GITHUB_ENV
    echo "SETUP_QUALITY=POOR" >> $env:GITHUB_ENV
}

# Store detailed results
echo "FAILED_STEPS=$($executionResults.Failed -join ',')" >> $env:GITHUB_ENV
echo "SUCCESS_STEPS=$($executionResults.Successful -join ',')" >> $env:GITHUB_ENV
echo "SCRIPT_VERSION=$ScriptVersion" >> $env:GITHUB_ENV

Write-Log -Message "===============================================" -Level "INFO"
