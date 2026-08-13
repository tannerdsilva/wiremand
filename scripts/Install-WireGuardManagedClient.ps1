<#
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  Install-WireGuardManagedClient.ps1                                          ║
║  ───────────────────────────────────                                         ║
║                                                                              ║
║  PURPOSE                                                                     ║
║    Deploys a WireGuard client configuration on a Windows endpoint and         ║
║    integrates it with the WireGuard Manager Service so the end user can       ║
║    see the tunnel in the system tray and start/stop it, but CANNOT remove     ║
║    or edit the configuration.                                                 ║
║                                                                              ║
║  INTENDED USE                                                                ║
║    Use this script for end-user VPN client deployment where the               ║
║    organization provides a pre-configured tunnel and wants the user to        ║
║    have self-service start/stop capability without being able to delete       ║
║    or modify the corporate VPN configuration.                                ║
║                                                                              ║
║  HOW IT WORKS                                                                ║
║    1. Installs WireGuard if not already present (silent MSI).                ║
║    2. Installs the WireGuard Manager Service (system tray).                  ║
║    3. Copies the provided .conf into the managed configurations directory    ║
║       at %ProgramFiles%\WireGuard\Data\Configurations\.                      ║
║    4. The Manager Service automatically encrypts the config to .conf.dpapi   ║
║       and locks it so only SYSTEM can read it.                               ║
║    5. Optionally sets HKLM\Software\WireGuard\LimitedOperatorUI.             ║
║                                                                              ║
║  DRY RUN                                                                     ║
║    Pass -DryRun to see a complete structured breakdown of every action       ║
║    the script would take, without modifying the system. The output is        ║
║    designed for consumption by low-parameter-count models.                   ║
║                                                                              ║
║  PARAMETERS                                                                  ║
║    -ConfigContent      Inline WireGuard config string                        ║
║    -ConfigPath         Path to a .conf file to deploy                       ║
║    -TunnelName         Name for the tunnel (derived from filename if omitted)║
║    -LimitedOperatorUI  Enable non-admin start/stop via system tray           ║
║    -NoStart            Do not start the tunnel after deployment              ║
║    -Remove             Remove a previously deployed managed config           ║
║    -Force              When removing, stop the tunnel service first          ║
║    -DryRun             Preview all actions without executing them            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
#>

param(
    [Parameter(Mandatory = $false, ParameterSetName = "Inline")]
    [string]$ConfigContent = "",

    [Parameter(Mandatory = $false, ParameterSetName = "File")]
    [string]$ConfigPath = "",

    [Parameter(Mandatory = $false)]
    [string]$TunnelName = "",

    [Parameter(Mandatory = $false)]
    [switch]$LimitedOperatorUI,

    [Parameter(Mandatory = $false)]
    [switch]$NoStart,

    [Parameter(Mandatory = $false, ParameterSetName = "Remove")]
    [switch]$Remove,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$script:wgDir = "${env:ProgramFiles}\WireGuard"
$script:wgExe = "$script:wgDir\wireguard.exe"
$script:wgCli = "$script:wgDir\wg.exe"
$script:managedConfigDir = "$script:wgDir\Data\Configurations"

# ---- Dry-run state ----
$script:dryRunActions = @()

function DryTrace {
    param([string]$Section, [string]$Action, [string]$Detail = "", [string]$Condition = "")
    if (-not $DryRun) { return }
    $script:dryRunActions += [PSCustomObject]@{
        Section   = $Section
        Action    = $Action
        Detail    = $Detail
        Condition = $Condition
    }
}

function EmitDryRunReport {
    if (-not $DryRun) { return }
    Write-Host "[DRY-RUN] Script: Install-WireGuardManagedClient.ps1"
    Write-Host "[DRY-RUN] Parameters:"
    Write-Host "[DRY-RUN]   ConfigContent     = $(if ($ConfigContent) { '(provided, N chars)' } else { '(not provided)' })"
    Write-Host "[DRY-RUN]   ConfigPath        = $ConfigPath"
    Write-Host "[DRY-RUN]   TunnelName        = $TunnelName"
    Write-Host "[DRY-RUN]   LimitedOperatorUI = $LimitedOperatorUI"
    Write-Host "[DRY-RUN]   NoStart           = $NoStart"
    Write-Host "[DRY-RUN]   Remove            = $Remove"
    Write-Host "[DRY-RUN]   Force             = $Force"
    Write-Host "[DRY-RUN]"
    Write-Host "[DRY-RUN] === PLAN ==="
    if ($Remove) {
        Write-Host "[DRY-RUN] Mode: REMOVE"
        Write-Host "[DRY-RUN] Step 1: Verify WireGuard installation"
        Write-Host "[DRY-RUN] Step 2: Stop and uninstall tunnel service (if exists)"
        Write-Host "[DRY-RUN] Step 3: Remove encrypted config (.conf.dpapi) and plaintext (.conf)"
    } else {
        Write-Host "[DRY-RUN] Mode: DEPLOY"
        Write-Host "[DRY-RUN] Step 1: Install WireGuard product (if missing)"
        Write-Host "[DRY-RUN] Step 2: Install Manager Service (if missing)"
        Write-Host "[DRY-RUN] Step 3: Deploy config to managed directory"
        Write-Host "[DRY-RUN] Step 4: Set LimitedOperatorUI registry key (if requested)"
        Write-Host "[DRY-RUN] Step 5: Start tunnel (unless -NoStart)"
    }
    Write-Host "[DRY-RUN]"

    $currentSection = ""
    foreach ($a in $script:dryRunActions) {
        if ($a.Section -ne $currentSection) {
            $currentSection = $a.Section
            Write-Host "[DRY-RUN]"
            Write-Host "[DRY-RUN] --- $($a.Section) ---"
        }
        $cond = if ($a.Condition) { " [IF: $($a.Condition)]" } else { "" }
        Write-Host "[DRY-RUN]   $($a.Action)$cond"
        if ($a.Detail) {
            foreach ($line in ($a.Detail -split "`n")) {
                Write-Host "[DRY-RUN]     $line"
            }
        }
    }

    Write-Host "[DRY-RUN]"
    Write-Host "[DRY-RUN] === DRY-RUN COMPLETE ==="
    Write-Host "[DRY-RUN] No changes were made to the system."
    exit 0
}

# ---- Helper functions ----

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-WireGuardProduct {
    if (Test-Path $script:wgExe) {
        Write-Log "WireGuard is already installed at $($script:wgExe)"
        DryTrace -Section "Step 1: Install WireGuard" -Action "Skip MSI download/install" `
            -Condition "WireGuard already present at $script:wgExe"
        return
    }
    Write-Log "WireGuard not found. Downloading and installing..."
    $url = "https://download.wireguard.com/windows-client/wireguard-amd64-0.5.3.msi"
    $msi = "$env:TEMP\wireguard-client-install-$(Get-Random).msi"

    DryTrace -Section "Step 1: Install WireGuard" -Action "Download MSI" `
        -Detail "URL: $url`nDestination: $msi" -Condition "WireGuard not found at $script:wgExe"
    DryTrace -Section "Step 1: Install WireGuard" -Action "Install MSI silently" `
        -Detail "msiexec /i `"$msi`" /qn DO_NOT_LAUNCH=1 /norestart" `
        -Condition "After download"

    if (-not $DryRun) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object System.Net.WebClient).DownloadFile($url, $msi)
            Write-Log "Downloaded $((Get-Item $msi).Length) bytes"
            Write-Log "Installing WireGuard silently (DO_NOT_LAUNCH)..."
            $proc = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" /qn DO_NOT_LAUNCH=1 /norestart"
            if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
                throw "MSI installer exited with code $($proc.ExitCode)"
            }
            Write-Log "WireGuard installed successfully."
        } finally {
            if (Test-Path $msi) { Remove-Item $msi -Force -ErrorAction SilentlyContinue }
        }
        if (-not (Test-Path $script:wgExe)) {
            throw "WireGuard installation completed but wireguard.exe not found at $($script:wgExe)"
        }
    }
}

function Install-ManagerService {
    $svc = Get-Service "WireGuardManager" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Log "WireGuard Manager Service already exists (Status: $($svc.Status))."
        DryTrace -Section "Step 2: Manager Service" -Action "Skip install" `
            -Condition "Manager Service already exists (Status: $($svc.Status))"
        if ($svc.Status -ne "Running" -and -not $DryRun) {
            Start-Service -Name "WireGuardManager" -ErrorAction SilentlyContinue
            Write-Log "WireGuard Manager Service started."
        }
        return
    }

    DryTrace -Section "Step 2: Manager Service" -Action "Install Manager Service" `
        -Detail "Command: wireguard /installmanagerservice`nResulting service: WireGuardManager (Automatic start)"

    if (-not $DryRun) {
        Write-Log "Installing WireGuard Manager Service..."
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList "/installmanagerservice" -Wait -PassThru -NoNewWindow
        Start-Sleep -Seconds 3
        $svc = Get-Service "WireGuardManager" -ErrorAction SilentlyContinue
        if (-not $svc) {
            throw "WireGuard Manager Service was not installed (exit code $($proc.ExitCode))."
        }
        Write-Log "WireGuard Manager Service installed (Status: $($svc.Status))."
        if ($svc.Status -ne "Running") {
            Start-Service -Name "WireGuardManager" -ErrorAction SilentlyContinue
            Write-Log "WireGuard Manager Service started."
        }
    }
}

function Deploy-ManagedConfig {
    param([string]$ConfigContent, [string]$TunnelName)

    if (-not (Test-Path $script:managedConfigDir)) {
        DryTrace -Section "Step 3: Deploy Config" -Action "Create managed config directory" -Detail $script:managedConfigDir
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path $script:managedConfigDir -Force | Out-Null
            Write-Log "Created managed configurations directory: $script:managedConfigDir"
        }
    }

    if (-not $TunnelName) {
        if ($ConfigContent -match '\[Interface\]\s*#\s*(\S+)') {
            $TunnelName = $matches[1]
        } elseif ($ConfigContent -match 'Address\s*=\s*([^\r\n]+)') {
            $addrPart = $matches[1].Trim() -replace '[\\/:]', '-'
            $TunnelName = "wg-$addrPart"
        } else {
            $TunnelName = "wireguard-client-$([System.IO.Path]::GetRandomFileName() -replace '\.','')"
        }
    }

    $configPath = "$script:managedConfigDir\$TunnelName.conf"
    $dpapiPath = "$script:managedConfigDir\$TunnelName.conf.dpapi"

    if (Test-Path $dpapiPath) {
        DryTrace -Section "Step 3: Deploy Config" -Action "BLOCKED: Config already exists" `
            -Detail "Encrypted config already present at: $dpapiPath`nUse -Remove -TunnelName $TunnelName to remove it first." `
            -Condition "Existing encrypted config detected"
        Write-Log "A managed configuration for '$TunnelName' already exists (encrypted)." -Level "WARN"
        Write-Log "Use -Remove -TunnelName $TunnelName to remove it first, or specify a different TunnelName." -Level "WARN"
        throw "Configuration '$TunnelName' already exists in the managed store."
    }

    DryTrace -Section "Step 3: Deploy Config" -Action "Write config to managed directory" -Detail @"
Source config length: $($ConfigContent.Length) chars
Destination: $configPath
Post-write: Manager Service will:
  1. Encrypt to $dpapiPath (CryptProtectData, Local System scope)
  2. Delete plaintext $configPath
  3. Lock encrypted file (SYSTEM-only read)
Result: Users can start/stop tunnel via system tray but cannot remove/edit config
"@

    if (-not $DryRun) {
        if (Test-Path $configPath) {
            Write-Log "A pending configuration for '$TunnelName' already exists. Overwriting..." -Level "WARN"
        }
        Write-Log "Writing client configuration to managed directory: $configPath"
        Set-Content -Path $configPath -Value $ConfigContent -Encoding ASCII
        Write-Log "Configuration placed in managed directory."
        Write-Log "The Manager Service will encrypt this config (.conf.dpapi) and lock it."
        Write-Log "Users can start/stop the tunnel from the system tray but cannot remove or edit it."
    }

    return $TunnelName
}

function Remove-ManagedConfig {
    param([string]$TunnelName)
    if (-not $TunnelName) {
        throw "-TunnelName is required when using -Remove."
    }

    $serviceName = "WireGuardTunnel`$$TunnelName"
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($svc) {
        DryTrace -Section "Remove: Tunnel Service" -Action "Uninstall tunnel service" `
            -Detail "Service: $serviceName`nCommand: wireguard /uninstalltunnelservice $TunnelName" `
            -Condition "Tunnel service exists (Status: $($svc.Status))"

        if ($Force) {
            DryTrace -Section "Remove: Tunnel Service" -Action "Stop tunnel service (forced)" `
                -Detail "Command: Stop-Service -Name $serviceName -Force" `
                -Condition "-Force specified"
        }

        if (-not $DryRun) {
            if ($Force) {
                Write-Log "Stopping tunnel service: $serviceName"
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            if ($svc.Status -eq "Running") {
                Write-Log "Tunnel service '$serviceName' is still running. Use -Force to stop it." -Level "WARN"
                throw "Cannot remove: tunnel service is running."
            }
            Write-Log "Uninstalling tunnel service: $serviceName"
            $proc = Start-Process -FilePath $script:wgExe -ArgumentList @("/uninstalltunnelservice", $TunnelName) -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                Write-Log "Uninstall returned exit code $($proc.ExitCode); continuing..." -Level "WARN"
            }
        }
    }

    $configPath = "$script:managedConfigDir\$TunnelName.conf"
    $dpapiPath = "$script:managedConfigDir\$TunnelName.conf.dpapi"

    DryTrace -Section "Remove: Config Files" -Action "Remove config files" -Detail @"
Files to remove:
  $configPath (if exists)
  $dpapiPath (if exists)
"@

    if (-not $DryRun) {
        if (Test-Path $configPath) {
            Remove-Item $configPath -Force -ErrorAction SilentlyContinue
            Write-Log "Removed: $configPath"
        }
        if (Test-Path $dpapiPath) {
            Remove-Item $dpapiPath -Force -ErrorAction SilentlyContinue
            Write-Log "Removed: $dpapiPath"
        }
        Write-Log "Managed configuration '$TunnelName' has been removed."
    }
}

function Set-LimitedOperatorUIRegistry {
    DryTrace -Section "Step 4: Registry" -Action "Set LimitedOperatorUI registry key" -Detail @"
Path: HKLM:\Software\WireGuard
Name: LimitedOperatorUI
Type: REG_DWORD
Value: 1
Effect: Network Configuration Operators can start/stop tunnels via system tray
         without full admin rights. They CANNOT add, remove, edit, import, or
         export configurations.
"@

    if (-not $DryRun) {
        Write-Log "Setting LimitedOperatorUI registry key..."
        $regPath = "HKLM:\Software\WireGuard"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "LimitedOperatorUI" -Value 1 -Type DWord -Force
        Write-Log "LimitedOperatorUI enabled. Network Configuration Operators can now start/stop tunnels via the system tray."
    }
}

# ---- Main ----

function Main {
    Write-Log "=== WireGuard Managed Client Deployment ==="

    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator."
    }

    # ---- Remove mode ----
    if ($Remove) {
        Write-Log "Operating in REMOVE mode."
        Install-WireGuardProduct
        Remove-ManagedConfig -TunnelName $TunnelName
        EmitDryRunReport
        if (-not $DryRun) {
            Write-Log "=== Removal Complete ==="
        }
        return
    }

    # ---- Deploy mode ----
    Write-Log "Deploying managed client configuration with Manager Service integration."

    # 1. Resolve config content
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        Write-Log "Reading configuration from: $ConfigPath"
        $resolvedContent = Get-Content -Path $ConfigPath -Raw
        if (-not $TunnelName) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ConfigPath)
            if ($baseName) { $TunnelName = $baseName }
        }
    } elseif ($ConfigContent) {
        $resolvedContent = $ConfigContent
    } else {
        throw "Either -ConfigContent or -ConfigPath must be provided."
    }

    if (-not $resolvedContent.Trim()) {
        throw "Configuration content is empty."
    }

    DryTrace -Section "Input" -Action "Resolved configuration" -Detail @"
Source: $(if ($ConfigPath) { $ConfigPath } else { 'Inline (-ConfigContent)' })
Tunnel name: $(if ($TunnelName) { $TunnelName } else { '(to be derived)' })
Config length: $($resolvedContent.Length) chars
"@

    # 2. Install WireGuard if needed
    Install-WireGuardProduct

    # 3. Install the Manager Service
    Install-ManagerService

    # 4. Deploy config to managed directory
    $finalTunnelName = Deploy-ManagedConfig -ConfigContent $resolvedContent -TunnelName $TunnelName

    # 5. Optionally enable LimitedOperatorUI
    if ($LimitedOperatorUI) {
        Set-LimitedOperatorUIRegistry
    } else {
        DryTrace -Section "Step 4: Registry" -Action "Skip LimitedOperatorUI" -Condition "-LimitedOperatorUI not specified"
    }

    # 6. Optionally start the tunnel
    if (-not $NoStart) {
        $serviceName = "WireGuardTunnel`$$finalTunnelName"
        DryTrace -Section "Step 5: Start Tunnel" -Action "Wait for Manager Service to process config" `
            -Detail "Sleep 5 seconds, then check for service: $serviceName" `
            -Condition "-NoStart not specified"
        DryTrace -Section "Step 5: Start Tunnel" -Action "Start tunnel service (if created)" `
            -Detail "Command: Start-Service -Name $serviceName" `
            -Condition "Service exists after Manager Service processing"

        if (-not $DryRun) {
            Write-Log "Waiting for Manager Service to process the configuration..."
            Start-Sleep -Seconds 5
            $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($svc) {
                Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                Write-Log "Tunnel service '$serviceName' started."
            } else {
                Write-Log "Tunnel service not yet created. The Manager Service will pick up the config shortly." -Level "WARN"
                Write-Log "The user can start the tunnel from the system tray."
            }
        }
    } else {
        DryTrace -Section "Step 5: Start Tunnel" -Action "Skip tunnel start" -Condition "-NoStart specified"
    }

    # ---- Emit dry-run report and exit if dry run ----
    EmitDryRunReport

    # 7. Summary
    Write-Log "=== Deployment Summary ==="
    Write-Log "Tunnel Name       : $finalTunnelName"
    Write-Log "Config Location   : $script:managedConfigDir\$finalTunnelName.conf"
    Write-Log "Manager Service   : Installed and running"
    Write-Log "LimitedOperatorUI : $(if ($LimitedOperatorUI) { 'Enabled' } else { 'Not enabled' })"
    Write-Log ""
    Write-Log "The user can now start/stop their VPN tunnel from the WireGuard system tray icon."
    Write-Log "The configuration is encrypted and locked - it cannot be removed or edited via the GUI."

    return @{
        TunnelName     = $finalTunnelName
        ConfigPath     = "$script:managedConfigDir\$finalTunnelName.conf"
        ManagerService = "WireGuardManager"
    }
}

# Run
Main
