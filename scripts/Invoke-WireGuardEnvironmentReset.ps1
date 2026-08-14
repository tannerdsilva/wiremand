<#
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  Invoke-WireGuardEnvironmentReset.ps1                                        ║
║  ─────────────────────────────────────                                       ║
║                                                                              ║
║  PURPOSE                                                                     ║
║    Forcefully removes all traces of WireGuard from a Windows system.         ║
║    Designed for environments where WireGuard was installed or configured     ║
║    manually across many machines and you need a clean, verifiable reset.     ║
║                                                                              ║
║  SCAN STRATEGY                                                               ║
║    The script performs a two-tier filesystem scan from root (C:\) to         ║
║    depth 3, matching file and directory names against WireGuard-related      ║
║    patterns. Tier 1 matches *[Ww]ire[Gg]uard* (high confidence). Tier 2      ║
║    matches *wg* (broader, catches wg.exe and similar) but excludes known     ║
║    Windows system components (WinSxS, System32, Boot fonts, etc.) to         ║
║    avoid false positives.                                                    ║
║                                                                              ║
║  WHAT IT REMOVES                                                             ║
║    - All WireGuard tunnel services and the Manager Service                   ║
║    - WireGuard kernel driver (wireguard.sys)                                 ║
║    - WireGuard MSI product (full binary uninstall)                           ║
║    - HKLM\Software\WireGuard registry key                                    ║
║    - All files/directories matching *[Ww]ire[Gg]uard* (high confidence)      ║
║    - Tier 2 artifacts (*wg*.exe, *wg*.sys, *wg*.conf, *wg*.dll outside      ║
║      system paths) are reported but NOT automatically removed (see SCAN      ║
║      STRATEGY above for rationale)                                           ║
║    - WireGuard Windows Firewall rules                                        ║
║                                                                              ║
║  DRY-RUN MODE (DEFAULT)                                                        ║
║    By default the script runs in dry-run mode: it produces a structured         ║
║    breakdown of every action it would take without modifying the system.        ║
║    Pass -NoDry to execute changes for real. The output is designed for          ║
║    consumption by low-parameter-count models.                                   ║
║                                                                              ║
║  PARAMETERS                                                                  ║
║    -NoDry           Execute changes for real (default is dry-run)            ║
║    -Force           Skip confirmation prompts                                ║
║    -ScanOnly        Only scan and report findings, do not remove anything    ║
║    -PreserveConfigs Do not delete configuration/data directories             ║
║                                                                              ║
║  EXAMPLES                                                                    ║
║    # Preview what would be removed (default, no flag needed)                 ║
║    .\Invoke-WireGuardEnvironmentReset.ps1                                    ║
║                                                                              ║
║    # Full reset without prompts                                              ║
║    .\Invoke-WireGuardEnvironmentReset.ps1 -Force -NoDry                      ║
║                                                                              ║
║    # Just scan and report                                                    ║
║    .\Invoke-WireGuardEnvironmentReset.ps1 -ScanOnly                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
#>

param(
    [Parameter(Mandatory = $false)]
    [switch]$NoDry,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$ScanOnly,

    [Parameter(Mandatory = $false)]
    [switch]$PreserveConfigs
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
    Write-Host "[DRY-RUN] Script: Invoke-WireGuardEnvironmentReset.ps1"
    Write-Host "[DRY-RUN] Parameters:"
    Write-Host "[DRY-RUN]   NoDry           = $NoDry"
    Write-Host "[DRY-RUN]   Force           = $Force"
    Write-Host "[DRY-RUN]   ScanOnly        = $ScanOnly"
    Write-Host "[DRY-RUN]   PreserveConfigs = $PreserveConfigs"
    Write-Host "[DRY-RUN]"
    Write-Host "[DRY-RUN] === PLAN ==="
    Write-Host "[DRY-RUN] Phase 1: Filesystem scan (root depth 3, two-tier)"
    Write-Host "[DRY-RUN] Phase 2: Service enumeration and uninstall"
    Write-Host "[DRY-RUN] Phase 3: Driver removal"
    Write-Host "[DRY-RUN] Phase 4: MSI product uninstall"
    Write-Host "[DRY-RUN] Phase 5: Registry cleanup"
    Write-Host "[DRY-RUN] Phase 6: Filesystem artifact removal (tier-1 only)"
    Write-Host "[DRY-RUN] Phase 7: Firewall rule cleanup"
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

# ---- Paths that are definitely NOT WireGuard (system components with 'wg' in name) ----
$script:excludedSystemPaths = @(
    'WinSxS',
    'System32',
    'SysWOW64',
    'Boot',
    'Fonts',
    'Fonts_EX',
    'en-US',
    'Manifests'
)

function Test-IsSystemPath {
    param([string]$Path)
    foreach ($excl in $script:excludedSystemPaths) {
        if ($Path -match [regex]::Escape($excl)) {
            return $true
        }
    }
    return $false
}

# ---- Phase 1: Filesystem scan (root depth 3, two-tier pattern matching) ----

function Invoke-FastFileScan {
    Write-Log "Scanning filesystem from root (C:\) to depth 3 for WireGuard artifacts..."

    # Tier 1: High-confidence patterns (definitely WireGuard)
    $tier1Patterns = @(
        '*[Ww]ire[Gg]uard*'
    )

    # Tier 2: Broader patterns (may include non-WireGuard system files)
    $tier2Patterns = @(
        '*wg*.exe',
        '*wg*.sys',
        '*wg*.conf',
        '*wg*.dll'
    )

    $results = @{
        Tier1Directories = @()
        Tier1Files       = @()
        Tier2Directories = @()
        Tier2Files       = @()
    }

    # Known WireGuard paths to always include
    $knownPaths = @(
        "$env:ProgramFiles\WireGuard",
        "$env:ProgramFiles(x86)\WireGuard",
        "$env:ProgramData\WireGuard",
        "$env:ProgramData\WireGuard\Configs",
        "$env:AppData\WireGuard",
        "$env:LOCALAPPDATA\WireGuard",
        "${env:ProgramFiles}\WireGuard\Data\Configurations"
    )
    foreach ($p in $knownPaths) {
        $expanded = [System.Environment]::ExpandEnvironmentVariables($p)
        if (Test-Path $expanded) {
            $item = Get-Item $expanded -ErrorAction SilentlyContinue
            if ($item -and $item.PSIsContainer) {
                $results.Tier1Directories += $expanded
            }
        }
    }

    # Depth-first scan to depth 3
    $roots = @(Get-ChildItem "C:\" -Directory -ErrorAction SilentlyContinue)
    $depth = 0
    $currentLevel = $roots

    while ($depth -le 3 -and $currentLevel.Count -gt 0) {
        $nextLevel = @()
        foreach ($item in $currentLevel) {
            $isSystem = Test-IsSystemPath -Path $item.FullName

            # Check directory name against patterns
            $matchedTier1 = $false
            $matchedTier2 = $false
            foreach ($pat in $tier1Patterns) {
                if ($item.Name -like $pat) { $matchedTier1 = $true; break }
            }
            if (-not $matchedTier1 -and -not $isSystem) {
                foreach ($pat in $tier2Patterns) {
                    if ($item.Name -like $pat) { $matchedTier2 = $true; break }
                }
            }

            if ($matchedTier1) {
                if ($results.Tier1Directories -notcontains $item.FullName) {
                    $results.Tier1Directories += $item.FullName
                }
            } elseif ($matchedTier2) {
                if ($results.Tier2Directories -notcontains $item.FullName) {
                    $results.Tier2Directories += $item.FullName
                }
            }

            # Check files in this directory
            if ($depth -lt 3) {
                $files = Get-ChildItem $item.FullName -File -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    $fIsSystem = Test-IsSystemPath -Path $f.FullName
                    $fMatchedTier1 = $false
                    $fMatchedTier2 = $false

                    foreach ($pat in $tier1Patterns) {
                        if ($f.Name -like $pat) { $fMatchedTier1 = $true; break }
                    }
                    if (-not $fMatchedTier1 -and -not $fIsSystem) {
                        foreach ($pat in $tier2Patterns) {
                            if ($f.Name -like $pat) { $fMatchedTier2 = $true; break }
                        }
                    }

                    if ($fMatchedTier1) {
                        $results.Tier1Files += $f.FullName
                    } elseif ($fMatchedTier2) {
                        $results.Tier2Files += $f.FullName
                    }
                }
            }

            # Collect subdirectories for next level
            if ($depth -lt 3) {
                $subdirs = Get-ChildItem $item.FullName -Directory -ErrorAction SilentlyContinue
                $nextLevel += $subdirs
            }
        }
        $currentLevel = $nextLevel
        $depth++
    }

    # Deduplicate: if a path is in Tier1, remove it from Tier2
    $results.Tier2Directories = $results.Tier2Directories | Where-Object {
        $results.Tier1Directories -notcontains $_
    }
    $results.Tier2Files = $results.Tier2Files | Where-Object {
        $results.Tier1Files -notcontains $_
    }

    return $results
}

# ---- Phase 2: Service enumeration ----

function Get-WireGuardServices {
    $services = @()
    $all = Get-Service -Name "WireGuard*" -ErrorAction SilentlyContinue
    foreach ($s in $all) {
        $services += [PSCustomObject]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            Status      = $s.Status
            StartType   = $s.StartType
            ServiceType = if ($s.Name -eq "WireGuardManager") { "Manager" } else { "Tunnel" }
            TunnelName  = if ($s.Name -match 'WireGuardTunnel\$(.+)') { $matches[1] } else { "" }
        }
    }
    return $services
}

# ---- Phase 3: MSI product lookup ----

function Get-WireGuardMsiProduct {
    $wgProducts = [System.Collections.ArrayList]@()
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*WireGuard*"
        }
        foreach ($item in $items) {
            $wgProducts.Add([PSCustomObject]@{
                Name = $item.DisplayName
                ProductCode = $item.PSChildName
                Version = $item.DisplayVersion
            }) | Out-Null
        }
    }
    return @($wgProducts.ToArray())
}

# ---- Phase 4: Registry scan ----

function Get-WireGuardRegistryKeys {
    $keys = @()
    $paths = @(
        "HKLM:\SOFTWARE\WireGuard",
        "HKLM:\SOFTWARE\WOW6432Node\WireGuard"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $keys += $p
        }
    }
    return $keys
}

# ---- Phase 5: Firewall rules ----

function Get-WireGuardFirewallRules {
    $rules = Get-NetFirewallRule -DisplayName "WireGuard *" -ErrorAction SilentlyContinue
    return $rules
}

# ---- Execution functions ----

function Stop-WireGuardServices {
    param([array]$Services)
    foreach ($s in $Services) {
        if ($s.Status -eq "Running") {
            if ($NoDry) {
                Write-Log "Stopping service: $($s.Name)"
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
    }
}

function Uninstall-WireGuardTunnelService {
    param([string]$TunnelName)
    if ($NoDry) {
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList @("/uninstalltunnelservice", $TunnelName) -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Log "Uninstall tunnel '$TunnelName' returned $($proc.ExitCode); continuing..." -Level "WARN"
        }
    }
}

function Uninstall-WireGuardManagerService {
    if ($NoDry) {
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList "/uninstallmanagerservice" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Log "Uninstall manager service returned $($proc.ExitCode); continuing..." -Level "WARN"
        }
    }
}

function Uninstall-WireGuardDriver {
    if ($NoDry) {
        $proc = Start-Process -FilePath $script:wgExe -ArgumentList "/removedriver" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Log "Driver removal returned $($proc.ExitCode); continuing..." -Level "WARN"
        }
    }
}

function Uninstall-WireGuardMsi {
    param([array]$Products)
    foreach ($p in $Products) {
        if ($p.ProductCode) {
            if ($NoDry) {
                Write-Log "Uninstalling MSI: $($p.Name) ($($p.ProductCode))"
                $proc = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x $($p.ProductCode) /qn /norestart"
                if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010 -and $proc.ExitCode -ne 1605) {
                    Write-Log "MSI uninstall returned $($proc.ExitCode)" -Level "WARN"
                }
            }
        }
    }
}

function Remove-WireGuardRegistryKeys {
    param([array]$Keys)
    foreach ($k in $Keys) {
        if ($NoDry) {
            Write-Log "Removing registry key: $k"
            Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-WireGuardFirewallRules {
    param([array]$Rules)
    foreach ($r in $Rules) {
        if ($NoDry) {
            Write-Log "Removing firewall rule: $($r.DisplayName)"
            Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction SilentlyContinue
        }
    }
}

function Remove-WireGuardFileArtifacts {
    param([hashtable]$ScanResults)

    # Only remove Tier 1 (high-confidence) artifacts automatically.
    # Tier 2 items are reported but not removed (they may be system files).
    $allPaths = $ScanResults.Tier1Directories + $ScanResults.Tier1Files
    $allPaths = $allPaths | Sort-Object -Descending { $_.Length }

    foreach ($p in $allPaths) {
        if (Test-Path $p) {
            if ($NoDry) {
                Write-Log "Removing: $p"
                if ((Get-Item $p).PSIsContainer) {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # Report Tier 2 items that were NOT removed
    if ($ScanResults.Tier2Directories.Count -gt 0 -or $ScanResults.Tier2Files.Count -gt 0) {
        Write-Log "Tier 2 artifacts found (broader *wg* match, not automatically removed):" -Level "WARN"
        foreach ($d in $ScanResults.Tier2Directories) {
            Write-Log "  (SKIPPED) DIR: $d" -Level "WARN"
        }
        foreach ($f in $ScanResults.Tier2Files) {
            Write-Log "  (SKIPPED) FILE: $f" -Level "WARN"
        }
    }
}

# ---- Main ----

function Main {
    Write-Log "=== WireGuard Environment Reset ==="

    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator."
    }

    # ---- Phase 1: Filesystem scan ----
    Write-Log "Phase 1: Scanning filesystem for WireGuard artifacts..."
    $scanResults = Invoke-FastFileScan
    DryTrace -Section "Phase 1: Filesystem Scan" -Action "Scan root C:\ to depth 3 (two-tier)" `
        -Detail "Tier 1 (*[Ww]ire[Gg]uard*): $($scanResults.Tier1Directories.Count) dirs, $($scanResults.Tier1Files.Count) files`nTier 2 (*wg* non-system): $($scanResults.Tier2Directories.Count) dirs, $($scanResults.Tier2Files.Count) files"

    $totalTier1 = $scanResults.Tier1Directories.Count + $scanResults.Tier1Files.Count
    $totalTier2 = $scanResults.Tier2Directories.Count + $scanResults.Tier2Files.Count

    if ($totalTier1 -gt 0) {
        Write-Log "Tier 1 (high confidence - will be removed):"
        foreach ($d in $scanResults.Tier1Directories) { Write-Log "  DIR: $d" }
        foreach ($f in $scanResults.Tier1Files) { Write-Log "  FILE: $f" }
        DryTrace -Section "Phase 1: Filesystem Scan" -Action "Tier 1 items to remove" `
            -Detail (($scanResults.Tier1Directories + $scanResults.Tier1Files) -join "`n")
    }
    if ($totalTier2 -gt 0) {
        Write-Log "Tier 2 (broader *wg* match - reported but NOT auto-removed):"
        foreach ($d in $scanResults.Tier2Directories) { Write-Log "  (INFO) DIR: $d" }
        foreach ($f in $scanResults.Tier2Files) { Write-Log "  (INFO) FILE: $f" }
        DryTrace -Section "Phase 1: Filesystem Scan" -Action "Tier 2 items (reported only, not removed)" `
            -Detail (($scanResults.Tier2Directories + $scanResults.Tier2Files) -join "`n")
    }

    # ---- Phase 2: Services ----
    Write-Log "`nPhase 2: Enumerating WireGuard services..."
    $services = Get-WireGuardServices
    DryTrace -Section "Phase 2: Service Enumeration" -Action "Enumerate WireGuard services" `
        -Detail "Found $($services.Count) service(s)"

    $tunnelServices = $services | Where-Object { $_.ServiceType -eq "Tunnel" }
    $managerService = $services | Where-Object { $_.ServiceType -eq "Manager" }

    if ($tunnelServices.Count -gt 0) {
        Write-Log "Found $($tunnelServices.Count) tunnel service(s):"
        $tunnelServices | ForEach-Object { Write-Log "  TUNNEL: $($_.Name) ($($_.Status))" }
        DryTrace -Section "Phase 2: Service Enumeration" -Action "Tunnel services to uninstall" `
            -Detail (($tunnelServices | ForEach-Object { "$($_.Name) -> $($_.TunnelName)" }) -join "`n")
    }
    if ($managerService.Count -gt 0) {
        Write-Log "Found Manager Service: $($managerService[0].Name) ($($managerService[0].Status))"
        DryTrace -Section "Phase 2: Service Enumeration" -Action "Manager service to uninstall"
    }

    # ---- Phase 3: MSI product ----
    Write-Log "`nPhase 3: Checking for WireGuard MSI product..."
    $msiProducts = Get-WireGuardMsiProduct
    DryTrace -Section "Phase 3: MSI Product" -Action "Check for installed WireGuard MSI" `
        -Detail "Found $($msiProducts.Count) product(s)"

    foreach ($p in $msiProducts) {
        Write-Log "  MSI: $($p.Name) v$($p.Version) ($($p.ProductCode))"
        DryTrace -Section "Phase 3: MSI Product" -Action "Uninstall MSI product" `
            -Detail "$($p.Name) / ProductCode: $($p.ProductCode)"
    }

    # ---- Phase 4: Registry ----
    Write-Log "`nPhase 4: Checking registry..."
    $regKeys = Get-WireGuardRegistryKeys
    DryTrace -Section "Phase 4: Registry" -Action "Check for WireGuard registry keys" `
        -Detail "Found $($regKeys.Count) key(s)"

    foreach ($k in $regKeys) {
        Write-Log "  REG: $k"
        DryTrace -Section "Phase 4: Registry" -Action "Remove registry key" -Detail $k
    }

    # ---- Phase 5: Firewall ----
    Write-Log "`nPhase 5: Checking firewall rules..."
    $fwRules = Get-WireGuardFirewallRules
    DryTrace -Section "Phase 5: Firewall Rules" -Action "Check for WireGuard firewall rules" `
        -Detail "Found $($fwRules.Count) rule(s)"

    foreach ($r in $fwRules) {
        Write-Log "  FIREWALL: $($r.DisplayName)"
        DryTrace -Section "Phase 5: Firewall Rules" -Action "Remove firewall rule" -Detail $r.DisplayName
    }

    # ---- If ScanOnly, stop here (before dry-run report, since ScanOnly implies we want real scan output) ----
    if ($ScanOnly) {
        Write-Log "`n=== Scan complete. Use -Force to remove all artifacts. ==="
        return
    }

    # ---- Emit dry-run report and exit if dry run ----
    EmitDryRunReport

    # ---- Confirmation ----
    if (-not $Force) {
        Write-Host "`nWARNING: This will permanently remove all WireGuard components from this system."
        Write-Host "Are you sure? [y/N] " -NoNewline
        $confirm = Read-Host
        if ($confirm -notin @("y", "Y", "yes", "YES")) {
            Write-Log "Reset cancelled by user."
            return
        }
    }

    # ---- Execute removal ----
    Write-Log "`n=== Executing removal ==="

    # Stop services first
    if ($services.Count -gt 0) {
        Write-Log "Stopping all WireGuard services..."
        Stop-WireGuardServices -Services $services
    }

    # Uninstall tunnel services via wireguard.exe
    foreach ($ts in $tunnelServices) {
        Write-Log "Uninstalling tunnel service: $($ts.TunnelName)"
        Uninstall-WireGuardTunnelService -TunnelName $ts.TunnelName
    }

    # Uninstall manager service (via wireguard.exe or sc.exe fallback)
    $mgrSvc = Get-Service "WireGuardManager" -ErrorAction SilentlyContinue
    if ($mgrSvc) {
        Write-Log "Uninstalling Manager Service..."
        if (Test-Path $script:wgExe) {
            Uninstall-WireGuardManagerService
        } else {
            Write-Log "wireguard.exe not available; using sc.exe fallback..." -Level "WARN"
            if ($NoDry) {
                $proc = Start-Process sc.exe -Wait -PassThru -NoNewWindow -ArgumentList "delete", "WireGuardManager"
                if ($proc.ExitCode -ne 0) {
                    Write-Log "sc.exe delete returned $($proc.ExitCode); continuing..." -Level "WARN"
                }
            }
        }
    }

    # Remove driver
    if (Test-Path $script:wgExe) {
        Write-Log "Removing WireGuard driver..."
        Uninstall-WireGuardDriver
    }

    # Uninstall MSI
    Write-Log "DEBUG: Before MSI uninstall, msiProducts type=$($msiProducts.GetType().Name), count=$($msiProducts.Count), isNull=$($msiProducts -eq $null)" -Level "INFO"
    if ($msiProducts.Count -gt 0) {
        Write-Log "Uninstalling WireGuard MSI product..."
        Uninstall-WireGuardMsi -Products $msiProducts
    }

    # Remove registry keys
    if ($regKeys.Count -gt 0) {
        Write-Log "Removing registry keys..."
        Remove-WireGuardRegistryKeys -Keys $regKeys
    }

    # Remove firewall rules (re-query to catch MSI uninstall side effects)
    $fwRules = Get-WireGuardFirewallRules
    if ($fwRules.Count -gt 0) {
        Write-Log "Removing firewall rules..."
        Remove-WireGuardFirewallRules -Rules $fwRules
    }

    # Remove filesystem artifacts (Tier 1 only)
    if (-not $PreserveConfigs) {
        Write-Log "Removing filesystem artifacts (Tier 1 high-confidence)..."
        Remove-WireGuardFileArtifacts -ScanResults $scanResults
    } else {
        Write-Log "Preserving config directories (as requested)."
    }

    Write-Log "=== WireGuard Environment Reset Complete ==="
}

# Run
Main
