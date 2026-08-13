<#
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  Install-WireGuardTunnel.ps1                                                 ║
║  ─────────────────────────                                                   ║
║                                                                              ║
║  PURPOSE                                                                     ║
║    Deploys a persistent, headless WireGuard tunnel service on Windows.       ║
║    The tunnel runs as a standalone Windows service (WireGuardTunnel$<name>)  ║
║    that starts at boot and is invisible to the WireGuard GUI. No Manager     ║
║    Service is installed or required.                                         ║
║                                                                              ║
║  INTENDED USE                                                                ║
║    Use this script for "server-side" or "infrastructure" WireGuard           ║
║    interfaces that should always be connected and never touched by end       ║
║    users. Common scenarios:                                                  ║
║      - Site-to-site VPN tunnels                                              ║
║      - Infrastructure monitoring / management links                          ║
║      - Always-on gateway interfaces on routers or jump boxes                 ║
║      - Any WireGuard peer that should not appear in the system tray GUI      ║
║                                                                              ║
║  HOW IT WORKS                                                                ║
║    1. Installs WireGuard if not already present (silent MSI).                ║
║    2. Generates a fresh server key pair (always; does not reuse existing).   ║
║    3. Builds a .conf file with [Interface] + optional [Peer] sections.       ║
║    4. Installs a tunnel service via `wireguard /installtunnelservice`.       ║
║    5. Creates a Windows Firewall allow rule for the listen port.             ║
║    6. Enables IP forwarding (registry, requires reboot).                     ║
║    7. Optionally generates ready-to-deploy client .conf files for each peer. ║
║                                                                              ║
║  DRY-RUN MODE (DEFAULT)                                                        ║
║    By default the script runs in dry-run mode: it produces a structured         ║
║    breakdown of every action it would take without modifying the system.        ║
║    Pass -NoDry to execute changes for real. The output is designed for          ║
║    consumption by low-parameter-count models.                                   ║
║                                                                              ║
║  PARAMETERS                                                                  ║
║    -InterfaceName       Name for the tunnel (default: "wg0")                 ║
║    -ListenPort          UDP listen port (default: 51820)                     ║
║    -Address             Comma-separated IPs for the interface (REQUIRED)     ║
║    -PeerConfigPath      Path to a file with [Peer] sections                  ║
║    -DnsServers          DNS servers for the interface                        ║
║    -ConfigOutputDir     Where to write configs (default: %ProgramData%\WireGuard\Configs)║
║    -NoFirewall          Skip Windows Firewall rule creation                  ║
║    -NoForwarding        Skip IP forwarding enablement                        ║
║    -GenerateClientConfigs  Emit a ready-to-use .conf per peer                ║
║    -Endpoint            Public address for client configs                    ║
║    -Force               Remove and re-create an existing tunnel service      ║
║    -NoDry               Execute changes for real (default is dry-run)        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$InterfaceName = "wg0",

    [Parameter(Mandatory = $false)]
    [uint16]$ListenPort = 51820,

    [Parameter(Mandatory = $true)]
    [string]$Address,

    [Parameter(Mandatory = $false)]
    [string]$PeerConfigPath = "",

    [Parameter(Mandatory = $false)]
    [string]$DnsServers = "",

    [Parameter(Mandatory = $false)]
    [string]$ConfigOutputDir = "$env:ProgramData\WireGuard\Configs",

    [Parameter(Mandatory = $false)]
    [switch]$NoFirewall,

    [Parameter(Mandatory = $false)]
    [switch]$NoForwarding,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateClientConfigs,

    [Parameter(Mandatory = $false)]
    [string]$Endpoint = "",

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$NoDry
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$script:wgDir = "${env:ProgramFiles}\WireGuard"
$script:wgExe = "$script:wgDir\wireguard.exe"
$script:wgCli = "$script:wgDir\wg.exe"

# ---- Dry-run state ----
$script:dryRunActions = @()

function DryTrace {
    param([string]$Section, [string]$Action, [string]$Detail = "", [string]$Condition = "")
    if ($NoDry) { return }
    $script:dryRunActions += [PSCustomObject]@{
        Section   = $Section
        Action    = $Action
        Detail    = $Detail
        Condition = $Condition
    }
}

function EmitDryRunReport {
    if ($NoDry) { return }
    Write-Host "[DRY-RUN] Script: Install-WireGuardTunnel.ps1"
    Write-Host "[DRY-RUN] Parameters:"
    Write-Host "[DRY-RUN]   InterfaceName       = $InterfaceName"
    Write-Host "[DRY-RUN]   ListenPort          = $ListenPort"
    Write-Host "[DRY-RUN]   Address             = $Address"
    Write-Host "[DRY-RUN]   PeerConfigPath      = $PeerConfigPath"
    Write-Host "[DRY-RUN]   DnsServers          = $DnsServers"
    Write-Host "[DRY-RUN]   ConfigOutputDir     = $ConfigOutputDir"
    Write-Host "[DRY-RUN]   NoFirewall          = $NoFirewall"
    Write-Host "[DRY-RUN]   NoForwarding        = $NoForwarding"
    Write-Host "[DRY-RUN]   GenerateClientConfigs = $GenerateClientConfigs"
    Write-Host "[DRY-RUN]   Endpoint            = $Endpoint"
    Write-Host "[DRY-RUN]   Force               = $Force"
    Write-Host "[DRY-RUN]"
    Write-Host "[DRY-RUN] === PLAN ==="
    Write-Host "[DRY-RUN] Step 1: Install WireGuard product (if missing)"
    Write-Host "[DRY-RUN] Step 2: Generate server key pair"
    Write-Host "[DRY-RUN] Step 3: Build server configuration"
    Write-Host "[DRY-RUN] Step 4: Install tunnel service"
    Write-Host "[DRY-RUN] Step 5: Configure Windows Firewall"
    Write-Host "[DRY-RUN] Step 6: Enable IP forwarding"
    Write-Host "[DRY-RUN] Step 7: Start tunnel service"
    if ($GenerateClientConfigs) {
        Write-Host "[DRY-RUN] Step 8: Generate client configuration files"
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
    Write-Host "[DRY-RUN] No changes were made to the system. Pass -NoDry to execute."
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
    $msi = "$env:TEMP\wireguard-server-install-$(Get-Random).msi"

    DryTrace -Section "Step 1: Install WireGuard" -Action "Download MSI" `
        -Detail "URL: $url`nDestination: $msi" -Condition "WireGuard not found at $script:wgExe"
    DryTrace -Section "Step 1: Install WireGuard" -Action "Install MSI silently" `
        -Detail "msiexec /i `"$msi`" /qn DO_NOT_LAUNCH=1 /norestart" `
        -Condition "After download"

    if ($NoDry) {
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

function New-WireGuardKeyPair {
    DryTrace -Section "Step 2: Generate Keys" -Action "Generate private key" -Detail "Run: wg genkey"
    DryTrace -Section "Step 2: Generate Keys" -Action "Derive public key" -Detail "Run: wg pubkey (stdin pipe)"

    if (-not $NoDry) {
        return @{ PrivateKey = "(would-generate)"; PublicKey = "(would-derive)" }
    }

    $privRaw = & $script:wgCli genkey
    if (-not $privRaw) { throw "Failed to generate private key" }
    $privateKey = ($privRaw -join "").Trim()
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:wgCli
    $psi.Arguments = "pubkey"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.WriteLine($privateKey)
    $p.StandardInput.Close()
    $publicKey = $p.StandardOutput.ReadToEnd().Trim()
    $p.WaitForExit()
    if (-not $publicKey) { throw "Failed to derive public key" }
    return @{ PrivateKey = $privateKey; PublicKey = $publicKey }
}

function Enable-IPForwarding {
    DryTrace -Section "Step 6: IP Forwarding" -Action "Enable IP forwarding" -Detail @"
Registry paths:
  HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter = 1
  HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\IPEnableRouter = 1
Note: Requires reboot to take effect.
"@
    if ($NoDry) {
        Write-Log "Enabling IP forwarding..."
        $paths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        )
        foreach ($p in $paths) {
            Set-ItemProperty -Path $p -Name "IPEnableRouter" -Value 1 -Type DWord -Force
        }
        Write-Log "IP forwarding enabled. A reboot is required for this to take effect."
    }
}

function Add-WireGuardFirewallRule {
    param([string]$DisplayName, [uint16]$Port)
    $ruleName = "WireGuard ($DisplayName - UDP $Port)"
    DryTrace -Section "Step 5: Firewall" -Action "Create firewall rule" `
        -Detail "Name: $ruleName`nDirection: Inbound`nProtocol: UDP`nLocalPort: $Port`nAction: Allow`nProfile: Any"

    if ($NoDry) {
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "Firewall rule '$ruleName' already exists."
            return
        }
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol UDP -LocalPort $Port -Action Allow -Profile Any | Out-Null
        Write-Log "Created firewall rule: $ruleName"
    }
}

function Remove-ExistingTunnelService {
    param([string]$Name)
    $serviceName = "WireGuardTunnel`$$Name"
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) { return }

    DryTrace -Section "Step 4 (pre): Remove Existing" -Action "Remove existing tunnel service" `
        -Detail "Service: $serviceName`nCommand: wireguard /uninstalltunnelservice $Name" `
        -Condition "Existing tunnel service found"

    if ($NoDry) {
        Write-Log "Removing existing tunnel service: $serviceName"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList @("/uninstalltunnelservice", $Name) -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Log "Uninstall returned exit code $($proc.ExitCode); continuing..." -Level "WARN"
        }
        Start-Sleep -Seconds 2
    }
}

function Parse-Peers {
    param([string]$Content)
    $peers = [System.Collections.ArrayList]@()
    foreach ($line in $Content -split "`r`n|`n") {
        $trimmed = $line.Trim()
        if ($trimmed -eq "") { continue }
        if ($trimmed -eq "[Peer]") {
            [void]$peers.Add(@{ RawLines = @(); PublicKey = ""; Comment = "" })
        } elseif ($peers.Count -gt 0) {
            $last = $peers[$peers.Count - 1]
            $last.RawLines = $last.RawLines + @($line)
            if ($trimmed -match '^PublicKey\s*=\s*(\S+)') {
                $last.PublicKey = $matches[1]
            } elseif ($trimmed -match '^#\s*(.+)') {
                $last.Comment = $matches[1].Trim()
            }
        }
    }
    return ,$peers.ToArray()
}

function New-ClientConfig {
    param(
        [string]$ClientPrivateKey,
        [string]$ClientAddress,
        [string]$ServerPublicKey,
        [string]$ServerEndpoint,
        [string]$DnsServers,
        [string]$PresharedKey,
        [string]$AllowedIPs,
        [int]$PersistentKeepalive = 25
    )
    $cfg = @(
        "[Interface]",
        "PrivateKey = $ClientPrivateKey",
        "Address = $ClientAddress"
    )
    if ($DnsServers) { $cfg += "DNS = $DnsServers" }
    $cfg += ""
    $cfg += "[Peer]"
    $cfg += "PublicKey = $ServerPublicKey"
    $cfg += "Endpoint = $ServerEndpoint"
    $cfg += "AllowedIPs = $AllowedIPs"
    if ($PresharedKey) { $cfg += "PresharedKey = $PresharedKey" }
    $cfg += "PersistentKeepalive = $PersistentKeepalive"
    return ($cfg -join "`r`n")
}

# ---- Main ----

function Main {
    Write-Log "=== WireGuard Tunnel Service Installation ==="
    Write-Log "Interface: $InterfaceName | Port: $ListenPort | Address: $Address"

    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator."
    }

    # 1. Install WireGuard if needed
    Install-WireGuardProduct

    # 2. If -Force, remove existing tunnel service
    if ($Force) {
        Remove-ExistingTunnelService -Name $InterfaceName
    }

    # 3. Generate server keys
    Write-Log "Generating server key pair..."
    $keys = New-WireGuardKeyPair
    if ($NoDry) {
        Write-Log "Server Public Key: $($keys.PublicKey)"
    } else {
        Write-Log "(preview) Server Public Key: would generate new key pair"
    }

    # 4. Build server configuration
    Write-Log "Building server configuration..."
    $configLines = @(
        "[Interface]",
        "PrivateKey = $($keys.PrivateKey)",
        "Address = $Address",
        "ListenPort = $ListenPort"
    )

    if ($DnsServers) {
        $configLines += "DNS = $DnsServers"
    }

    # Parse and append peer sections from file if provided
    $parsedPeers = @()
    if ($PeerConfigPath -and (Test-Path $PeerConfigPath)) {
        Write-Log "Reading peer sections from: $PeerConfigPath"
        $peerFileContent = Get-Content -Path $PeerConfigPath -Raw
        $parsedPeers = Parse-Peers -Content $peerFileContent
        Write-Log "Found $($parsedPeers.Count) peer(s) in config."

        DryTrace -Section "Step 3: Configuration" -Action "Read peer config" `
            -Detail "Path: $PeerConfigPath`nPeers found: $($parsedPeers.Count)"

        if ($peerFileContent.Trim()) {
            $configLines += ""
            $configLines += $peerFileContent.Trim()
        }
    }

    $configContent = $configLines -join "`r`n"

    # 5. Write config and install tunnel service
    if (-not (Test-Path $ConfigOutputDir)) {
        DryTrace -Section "Step 3: Configuration" -Action "Create config directory" -Detail $ConfigOutputDir
        if ($NoDry) {
            New-Item -ItemType Directory -Path $ConfigOutputDir -Force | Out-Null
        }
    }
    $configPath = "$ConfigOutputDir\$InterfaceName.conf"
    $publicConfigPath = "$ConfigOutputDir\$InterfaceName.public.conf"

    DryTrace -Section "Step 3: Configuration" -Action "Write server config" -Detail @"
Config file: $configPath
Public config: $publicConfigPath
Config content:
$($configLines -join "`n")
"@

    if ($NoDry) {
        Write-Log "Writing server configuration to: $configPath"
        Set-Content -Path $configPath -Value $configContent -Encoding ASCII

        $publicConfigLines = $configLines -replace "^PrivateKey = .*$", "; PrivateKey = (hidden in server config)"
        Set-Content -Path $publicConfigPath -Value ($publicConfigLines -join "`r`n") -Encoding ASCII
        Write-Log "Public config (no private key) saved to: $publicConfigPath"
    }

    DryTrace -Section "Step 4: Install Tunnel Service" -Action "Install tunnel service" `
        -Detail "Command: wireguard /installtunnelservice `"$configPath`"`nResulting service: WireGuardTunnel`$$InterfaceName (Automatic start)"

    if ($NoDry) {
        Write-Log "Installing tunnel service..."
        $installArgs = @("/installtunnelservice", "`"$configPath`"")
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            throw "Tunnel service installation failed with exit code $($proc.ExitCode)."
        }
        # Give SCM time to register the new service before attempting to start it
        Start-Sleep -Seconds 3
    }

    # 6. Configure firewall
    if (-not $NoFirewall) {
        Add-WireGuardFirewallRule -DisplayName $InterfaceName -Port $ListenPort
    } else {
        DryTrace -Section "Step 5: Firewall" -Action "Skip firewall rule" -Condition "-NoFirewall specified"
    }

    # 7. Enable IP forwarding
    if (-not $NoForwarding) {
        Enable-IPForwarding
    } else {
        DryTrace -Section "Step 6: IP Forwarding" -Action "Skip IP forwarding" -Condition "-NoForwarding specified"
    }

    # 8. Start the tunnel service
    $serviceName = "WireGuardTunnel`$$InterfaceName"
    DryTrace -Section "Step 7: Start Service" -Action "Start tunnel service" `
        -Detail "Command: Start-Service -Name $serviceName" `
        -Condition "After tunnel service installation"

    if ($NoDry) {
        Write-Log "Starting tunnel service: $serviceName"
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Log "Tunnel service '$serviceName' is running."
        } else {
            Write-Log "Tunnel service '$serviceName' could not be started. Check the configuration." -Level "WARN"
        }
    }

    # 9. Generate client configs if requested
    if ($GenerateClientConfigs -and $parsedPeers.Count -gt 0) {
        if (-not $Endpoint) {
            Write-Log "Cannot generate client configs: -Endpoint was not specified." -Level "WARN"
        } else {
            Write-Log "Generating client configuration files..."
            $clientDir = "$ConfigOutputDir\clients"
            DryTrace -Section "Step 8: Client Configs" -Action "Generate client configs" `
                -Detail "Output directory: $clientDir`nEndpoint: $Endpoint`nPeers: $($parsedPeers.Count)"

            if ($NoDry) {
                if (-not (Test-Path $clientDir)) {
                    New-Item -ItemType Directory -Path $clientDir -Force | Out-Null
                }
            }

            foreach ($peer in $parsedPeers) {
                $peerName = if ($peer.Comment) { $peer.Comment } else { "peer-$($peer.Index)" }
                $peerNameSafe = $peerName -replace '[^\w.-]', '_'

                $peerAllowedIPs = "0.0.0.0/0, ::/0"
                foreach ($rawLine in $peer.RawLines) {
                    if ($rawLine -match 'AllowedIPs\s*=\s*(.+)') {
                        $peerAllowedIPs = $matches[1].Trim()
                    }
                }

                $clientKeys = New-WireGuardKeyPair

                $clientAddress = ""
                if ($peerAllowedIPs -match '([\d.]+/\d+|[\da-f:]+/\d+)') {
                    $clientAddress = $matches[1]
                }

                $clientConfig = New-ClientConfig `
                    -ClientPrivateKey $clientKeys.PrivateKey `
                    -ClientAddress $clientAddress `
                    -ServerPublicKey $keys.PublicKey `
                    -ServerEndpoint $Endpoint `
                    -DnsServers $DnsServers `
                    -AllowedIPs $peerAllowedIPs

                $clientConfigPath = "$clientDir\$peerNameSafe.conf"
                DryTrace -Section "Step 8: Client Configs" -Action "Write client config" `
                    -Detail "File: $clientConfigPath`nPeer: $peerName`nPublicKey: $($clientKeys.PublicKey)"

                if ($NoDry) {
                    Set-Content -Path $clientConfigPath -Value $clientConfig -Encoding ASCII
                    Write-Log "  Generated client config: $clientConfigPath (PublicKey: $($clientKeys.PublicKey))"
                }
            }
            if ($NoDry) {
                Write-Log "Client configs written to: $clientDir"
            }
        }
    }

    # ---- Emit dry-run report and exit if dry run ----
    EmitDryRunReport

    # 10. Summary
    Write-Log "=== Deployment Summary ==="
    Write-Log "Interface Name     : $InterfaceName"
    Write-Log "Listen Port        : $ListenPort"
    Write-Log "Server Address     : $Address"
    Write-Log "Server Public Key  : $($keys.PublicKey)"
    Write-Log "Config File        : $configPath"
    Write-Log "Public Config      : $publicConfigPath"
    Write-Log "Tunnel Service     : $serviceName"
    if ($parsedPeers.Count -gt 0) {
        Write-Log "Peers Configured   : $($parsedPeers.Count)"
    }
    Write-Log ""

    return @{
        InterfaceName  = $InterfaceName
        ListenPort     = $ListenPort
        Address        = $Address
        PublicKey      = $keys.PublicKey
        ConfigPath     = $configPath
        ServiceName    = $serviceName
        PeerCount      = $parsedPeers.Count
    }
}

# Run
Main
