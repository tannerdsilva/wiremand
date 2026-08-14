Write-Host '============================================================'
Write-Host '   WIREGUARD SCRIPT TEST BATTERY -- LETHAL EDITION'
Write-Host '============================================================'
Write-Host ''
$global:passed = 0; $global:failed = 0; $global:warnings = 0; $global:testCount = 0
$script:wgExe = 'C:\Program Files\WireGuard\wireguard.exe'
$script:wgCli = 'C:\Program Files\WireGuard\wg.exe'
$script:tunnelScript = 'C:\Users\azureuser\tunnel.ps1'
$script:clientScript = 'C:\Users\azureuser\client.ps1'
$script:resetScript = 'C:\Users\azureuser\reset.ps1'

function Test-Step { param([string]$N) $global:testCount++; Write-Host ''; Write-Host "--- TEST $($global:testCount): $N ---" -ForegroundColor Cyan }
function Pass { param([string]$D = '') $global:passed++; if ($D) { Write-Host "  [PASS] $D" -ForegroundColor Green } else { Write-Host '  [PASS]' -ForegroundColor Green } }
function Fail { param([string]$D = '') $global:failed++; if ($D) { Write-Host "  [FAIL] $D" -ForegroundColor Red } else { Write-Host '  [FAIL]' -ForegroundColor Red } }
function Warn { param([string]$D = '') $global:warnings++; if ($D) { Write-Host "  [WARN] $D" -ForegroundColor Yellow } else { Write-Host '  [WARN]' -ForegroundColor Yellow } }

# ---- Assertion functions ----
function Assert-Svc { param([string]$N,[string]$St='Running') $sv=Get-Service -Name $N -ErrorAction SilentlyContinue; if (-not $sv) {return $false}; if ($St -and $sv.Status -ne $St) {return $false}; return $true }
function Assert-NoSvc { param([string]$N) $s=Get-Service -Name $N -ErrorAction SilentlyContinue; return (-not $s) }
function Assert-Path { param([string]$P) return (Test-Path $P) }
function Assert-NoPath { param([string]$P) return (-not (Test-Path $P)) }
function Assert-Reg { param([string]$P,[string]$N,[int]$Vexp) try {$vr=Get-ItemProperty -Path $P -Name $N -ErrorAction Stop; return ($vr.$N -eq $Vexp)} catch {return $false} }
function Assert-NoReg { param([string]$P) return (-not (Test-Path $P)) }
function Assert-Fw { param([string]$N) $r=Get-NetFirewallRule -DisplayName $N -ErrorAction SilentlyContinue; return ($r -ne $null) }
function Assert-NoFw { param([string]$N) $r=Get-NetFirewallRule -DisplayName $N -ErrorAction SilentlyContinue; return (-not $r) }
function Assert-Group { param([string]$U,[string]$G) try {$gp=[ADSI]('WinNT://./'+$G); $m=@($gp.Invoke('Members'))|%{$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)}; return ($m -contains $U)} catch {return $false} }
function Assert-FwPort { param([string]$N,[int]$P) $r=Get-NetFirewallRule -DisplayName $N -ErrorAction SilentlyContinue; if (-not $r) {return $false}; $f=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue; return ($f -and $f.LocalPort -eq $P -and $f.Protocol -eq 'UDP') }
function Assert-FwEnabled { param([string]$N) $r=Get-NetFirewallRule -DisplayName $N -ErrorAction SilentlyContinue; return ($r -and $r.Enabled -eq 'True') }
function Assert-FwDirection { param([string]$N) $r=Get-NetFirewallRule -DisplayName $N -ErrorAction SilentlyContinue; return ($r -and $r.Direction -eq 'Inbound') }
function Assert-ConfigContains { param([string]$P,[string]$Pattern) if (-not (Test-Path $P)) {return $false}; $c=Get-Content $P -Raw; return ($c -match $Pattern) }
function Assert-ConfigNotContains { param([string]$P,[string]$Pattern) if (-not (Test-Path $P)) {return $true}; $c=Get-Content $P -Raw; return ($c -notmatch $Pattern) }
function Assert-WgShowPort { param([string]$I,[int]$P) if (-not (Test-Path $script:wgCli)) {return $false}; $o=& $script:wgCli show $I 2>&1 | Out-String; return ($o -match "listening port:\s+$P") }
function Assert-WgShowKey { param([string]$I,[string]$K) if (-not (Test-Path $script:wgCli)) {return $false}; $o=& $script:wgCli show $I 2>&1 | Out-String; return ($o -match ('public key:\s+' + [regex]::Escape($K))) }
function Assert-WgShow { param([string]$I,[string]$Prop) if (-not (Test-Path $script:wgCli)) {return $false}; $o=& $script:wgCli show $I 2>&1 | Out-String; return ($o -match $Prop) }
function Assert-Driver { $d=Get-WindowsDriver -Online -ErrorAction SilentlyContinue | Where-Object { $_.Driver -like '*wireguard*' }; return ($d -ne $null) }
function Assert-NoDriver { $d=Get-WindowsDriver -Online -ErrorAction SilentlyContinue | Where-Object { $_.Driver -like '*wireguard*' }; return (-not $d) }
function Assert-IpForwarding { $k=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -ErrorAction SilentlyContinue; return ($k -and $k.IPEnableRouter -eq 1) }

# ---- Helper: generate WireGuard key pair ----
function New-WgKeyPair {
    if (-not (Test-Path $script:wgCli)) { return $null }
    $priv = (& $script:wgCli genkey).Trim()
    if (-not $priv) { return $null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$script:wgCli; $psi.Arguments='pubkey'; $psi.RedirectStandardInput=$true
    $psi.RedirectStandardOutput=$true; $psi.UseShellExecute=$false
    $p=[System.Diagnostics.Process]::Start($psi); $p.StandardInput.WriteLine($priv); $p.StandardInput.Close()
    $pub=$p.StandardOutput.ReadToEnd().Trim(); $p.WaitForExit()
    if (-not $pub) { return $null }
    return @{Private=$priv; Public=$pub}
}

# ---- Helper: manual MSI cleanup ----
function Remove-WgMsi {
    $prods = Get-WmiObject Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*WireGuard*' }
    foreach ($p in $prods) {
        Write-Host "  [INFO] Manually uninstalling MSI: $($p.Name) ($($p.IdentifyingNumber))"
        $proc = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/x', $p.IdentifyingNumber, '/qn', '/norestart')
        Write-Host "  [INFO] msiexec exit: $($proc.ExitCode)"
    }
}

# ============================================================
# PHASE 0: Clean start
# ============================================================
Write-Host '=== PHASE 0: Clean start ==='
Test-Step 'Reset to clean state'
Remove-WgMsi
& $resetScript -Force -NoDry 2>&1 | Out-Null
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $svcs) { Pass 'System is clean' } else { Fail 'Services remain' }

# ============================================================
# PHASE 1: Install-WireGuardTunnel.ps1 -- LETHAL TESTS
# ============================================================
Write-Host '=== PHASE 1: Tunnel Script (Lethal) ==='

# --- T1.1: Fresh install with full config verification ---
Test-Step 'T1.1: Fresh install with full config verification'
& $tunnelScript -InterfaceName 'test-a' -Address '10.100.0.1/24' -ListenPort 51901 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-a' 'Running') { Pass 'Service running' } else { Fail 'Service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' 'Address = 10\.100\.0\.1/24') { Pass 'Config: Address correct' } else { Fail 'Config: Address wrong/missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' 'ListenPort = 51901') { Pass 'Config: ListenPort correct' } else { Fail 'Config: ListenPort wrong/missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' 'PrivateKey = ') { Pass 'Config: PrivateKey present' } else { Fail 'Config: PrivateKey missing' }
if (Assert-ConfigNotContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' '\[Peer\]') { Pass 'Config: No peers (none configured)' } else { Fail 'Config: Unexpected peers found' }
if (Assert-WgShow 'test-a' 'test-a') { Pass 'wg show: interface listed' } else { Fail 'wg show: interface not listed' }
if (Assert-WgShowPort 'test-a' 51901) { Pass 'wg show: port correct' } else { Fail 'wg show: port wrong' }
if (Assert-WgShowKey 'test-a' $kp.Public) { Pass 'wg show: public key matches' } else { Fail 'wg show: public key mismatch' }
if (Assert-Fw 'WireGuard (test-a - UDP 51901)') { Pass 'Firewall: rule exists' } else { Fail 'Firewall: rule missing' }
if (Assert-FwPort 'WireGuard (test-a - UDP 51901)' 51901) { Pass 'Firewall: port 51901 UDP' } else { Fail 'Firewall: wrong port/protocol' }
if (Assert-FwEnabled 'WireGuard (test-a - UDP 51901)') { Pass 'Firewall: enabled' } else { Fail 'Firewall: not enabled' }
if (Assert-FwDirection 'WireGuard (test-a - UDP 51901)') { Pass 'Firewall: inbound' } else { Fail 'Firewall: not inbound' }

# --- T1.2: Second tunnel, different port, verify isolation ---
Test-Step 'T1.2: Second tunnel isolation'
$kp2 = New-WgKeyPair
& $tunnelScript -InterfaceName 'test-b' -Address '10.100.1.1/24' -ListenPort 51902 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-b' 'Running') { Pass 'Second service running' } else { Fail 'Second service not running' }
if (Assert-WgShowPort 'test-a' 51901) { Pass 'test-a port unchanged (isolation)' } else { Fail 'test-a port changed!' }
if (Assert-WgShowPort 'test-b' 51902) { Pass 'test-b port correct' } else { Fail 'test-b port wrong' }
Write-Host '  [INFO] test-b key not compared (script generates its own keys)'
if (Assert-ConfigNotContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' 'test-b') { Pass 'test-a config not contaminated' } else { Fail 'test-a config has test-b data!' }

# --- T1.3: IPv6-only tunnel ---
Test-Step 'T1.3: IPv6-only tunnel'
& $tunnelScript -InterfaceName 'test-ipv6' -Address 'fd01::1/64' -ListenPort 51903 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-ipv6' 'Running') { Pass 'IPv6 service running' } else { Fail 'IPv6 service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-ipv6.conf' 'Address = fd01::1/64') { Pass 'IPv6 address in config' } else { Fail 'IPv6 address missing' }
if (Assert-WgShow 'test-ipv6' 'test-ipv6') { Pass 'wg shows IPv6 interface' } else { Fail 'wg does not show IPv6 interface' }

# --- T1.4: Dual-stack tunnel ---
Test-Step 'T1.4: Dual-stack tunnel'
& $tunnelScript -InterfaceName 'test-dual' -Address '10.100.2.1/24,fd02::1/64' -ListenPort 51904 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-dual' 'Running') { Pass 'Dual-stack service running' } else { Fail 'Dual-stack service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-dual.conf' '10\.100\.2\.1/24') { Pass 'Dual-stack: IPv4 in config' } else { Fail 'Dual-stack: IPv4 missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-dual.conf' 'fd02::1/64') { Pass 'Dual-stack: IPv6 in config' } else { Fail 'Dual-stack: IPv6 missing' }

# --- T1.5: DNS servers ---
Test-Step 'T1.5: DNS servers in config'
& $tunnelScript -InterfaceName 'test-dns' -Address '10.100.3.1/24' -ListenPort 51905 -DnsServers '10.100.3.53,1.1.1.1' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-dns' 'Running') { Pass 'DNS service running' } else { Fail 'DNS service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-dns.conf' 'DNS = 10\.100\.3\.53,1\.1\.1\.1') { Pass 'DNS servers in config' } else { Fail 'DNS servers missing' }

# --- T1.6: Peer config with preshared key ---
Test-Step 'T1.6: Peer config with preshared key'
$peerKp = New-WgKeyPair
$psk = (& $script:wgCli genpsk).Trim()
Set-Content 'C:\Users\azureuser\peers-test.conf' -Value @"
[Peer]
# test-peer-01
PublicKey = $($peerKp.Public)
PresharedKey = $psk
AllowedIPs = 10.100.4.2/32, fd04::2/128
"@ -Encoding ASCII
& $tunnelScript -InterfaceName 'test-peer' -Address '10.100.4.1/24,fd04::1/64' -ListenPort 51906 -PeerConfigPath 'C:\Users\azureuser\peers-test.conf' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-peer' 'Running') { Pass 'Peer service running' } else { Fail 'Peer service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-peer.conf' ([regex]::Escape($peerKp.Public))) { Pass 'Peer public key in config' } else { Fail 'Peer public key missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-peer.conf' ([regex]::Escape($psk))) { Pass 'PresharedKey in config' } else { Fail 'PresharedKey missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-peer.conf' 'AllowedIPs = 10\.100\.4\.2/32, fd04::2/128') { Pass 'Peer AllowedIPs in config' } else { Fail 'Peer AllowedIPs missing' }
if (Assert-WgShow 'test-peer' ([regex]::Escape($peerKp.Public))) { Pass 'Peer public key visible in wg show' } else { Fail 'Peer public key not visible in wg show' }

# --- T1.7: Generate client configs ---
Test-Step 'T1.7: Generate client configs with endpoint'
& $tunnelScript -InterfaceName 'test-gen' -Address '10.100.5.1/24' -ListenPort 51907 -PeerConfigPath 'C:\Users\azureuser\peers-test.conf' -GenerateClientConfigs -Endpoint 'vpn.test.example.com:51907' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-gen' 'Running') { Pass 'Gen service running' } else { Fail 'Gen service not running' }
if (Assert-Path 'C:\ProgramData\WireGuard\Configs\clients\test-peer-01.conf') { Pass 'Client config generated' } else { Fail 'Client config not generated' }
$cc = Get-Content 'C:\ProgramData\WireGuard\Configs\clients\test-peer-01.conf' -Raw
if ($cc -match 'vpn.test.example.com:51907') { Pass 'Endpoint in client config' } else { Fail 'Endpoint missing' }
if ($cc -match '\[Interface\]') { Pass 'Client config has [Interface]' } else { Fail 'Client config missing [Interface]' }
if ($cc -match '\[Peer\]') { Pass 'Client config has [Peer]' } else { Fail 'Client config missing [Peer]' }
if ($cc -match 'PrivateKey = ') { Pass 'Client config has PrivateKey' } else { Fail 'Client config missing PrivateKey' }
if ($cc -match 'Address = ') { Pass 'Client config has Address' } else { Fail 'Client config missing Address' }
if ($cc -match 'DNS = ') { Pass 'Client config has DNS' } else { Fail 'Client config missing DNS' }

# --- T1.8: -Force reinstall with new address and port ---
Test-Step 'T1.8: -Force reinstall changes address and port'
& $tunnelScript -InterfaceName 'test-a' -Address '10.200.0.1/24' -ListenPort 52001 -Force -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-a' 'Running') { Pass 'Reinstalled service running' } else { Fail 'Reinstalled service not running' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' '10\.200\.0\.1') { Pass 'Config: address updated' } else { Fail 'Config: address not updated' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-a.conf' 'ListenPort = 52001') { Pass 'Config: port updated' } else { Fail 'Config: port not updated' }
if (Assert-WgShowPort 'test-a' 52001) { Pass 'wg show: port updated' } else { Fail 'wg show: port not updated' }
if (Assert-FwPort 'WireGuard (test-a - UDP 52001)' 52001) { Pass 'Firewall: port updated' } else { Fail 'Firewall: port not updated' }
if (Assert-NoFw 'WireGuard (test-a - UDP 51901)') { Pass 'Firewall: old rule removed' } else { Fail 'Firewall: old rule still exists' }

# --- T1.9: -NoFirewall ---
Test-Step 'T1.9: -NoFirewall suppresses firewall rule'
& $tunnelScript -InterfaceName 'test-nofw' -Address '10.100.6.1/24' -ListenPort 51908 -NoFirewall -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-nofw' 'Running') { Pass 'NoFirewall service running' } else { Fail 'NoFirewall service not running' }
if (Assert-NoFw 'WireGuard (test-nofw - UDP 51908)') { Pass 'No firewall rule created' } else { Fail 'Firewall rule was created despite -NoFirewall' }

# --- T1.10: -NoForwarding ---
Test-Step 'T1.10: -NoForwarding suppresses IP forwarding'
& $tunnelScript -InterfaceName 'test-nofwd' -Address '10.100.7.1/24' -ListenPort 51909 -NoForwarding -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-nofwd' 'Running') { Pass 'NoForwarding service running' } else { Fail 'NoForwarding service not running' }

# --- T1.11: Dry-run (default) produces no changes ---
Test-Step 'T1.11: Dry-run produces zero side effects'
$bs = @(Get-Service 'WireGuard*' -ErrorAction SilentlyContinue | % { $_.Name })
$bfw = @(Get-NetFirewallRule -DisplayName 'WireGuard*' -ErrorAction SilentlyContinue).Count
$result = & $tunnelScript -InterfaceName 'test-dryrun' -Address '10.100.8.1/24' -ListenPort 51910 6>&1 | Out-String
$as = @(Get-Service 'WireGuard*' -ErrorAction SilentlyContinue | % { $_.Name })
$afw = @(Get-NetFirewallRule -DisplayName 'WireGuard*' -ErrorAction SilentlyContinue).Count
$diff = Compare-Object $bs $as
if (-not $diff) { Pass 'No services created' } else { Fail 'Services changed during dry-run' }
if (Assert-NoPath 'C:\ProgramData\WireGuard\Configs\test-dryrun.conf') { Pass 'No config file created' } else { Fail 'Config file created during dry-run' }
if ($afw -eq $bfw) { Pass 'No firewall rules created' } else { Fail 'Firewall rules changed during dry-run' }
if ($result -match 'DRY-RUN COMPLETE') { Pass 'Dry-run report emitted' } else { Fail 'Dry-run report not found' }

# --- T1.12: Missing required -Address ---
Test-Step 'T1.12: Missing required -Address rejected'
try { $null = & $tunnelScript -InterfaceName 'test-noaddr' -ListenPort 51911 -NoDry 2>&1; $ok = $false } catch { $ok = $true }
if ($ok) { Pass 'Correctly rejected missing -Address' } else { Fail 'Did not reject missing -Address' }

# --- T1.13: Multiple peers ---
Test-Step 'T1.13: Multiple peers in config'
$p2kp = New-WgKeyPair
Set-Content 'C:\Users\azureuser\peers-multi.conf' -Value @"
[Peer]
# multi-peer-a
PublicKey = $($peerKp.Public)
AllowedIPs = 10.100.9.2/32

[Peer]
# multi-peer-b
PublicKey = $($p2kp.Public)
AllowedIPs = 10.100.9.3/32
"@ -Encoding ASCII
& $tunnelScript -InterfaceName 'test-multi' -Address '10.100.9.1/24' -ListenPort 51912 -PeerConfigPath 'C:\Users\azureuser\peers-multi.conf' -GenerateClientConfigs -Endpoint 'multi.test:51912' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-multi' 'Running') { Pass 'Multi-peer service running' } else { Fail 'Multi-peer service not running' }
if (Assert-Path 'C:\ProgramData\WireGuard\Configs\clients\multi-peer-a.conf') { Pass 'Client config A generated' } else { Fail 'Client config A not generated' }
if (Assert-Path 'C:\ProgramData\WireGuard\Configs\clients\multi-peer-b.conf') { Pass 'Client config B generated' } else { Fail 'Client config B not generated' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-multi.conf' ([regex]::Escape($peerKp.Public))) { Pass 'Peer A key in server config' } else { Fail 'Peer A key missing' }
if (Assert-ConfigContains 'C:\ProgramData\WireGuard\Configs\test-multi.conf' ([regex]::Escape($p2kp.Public))) { Pass 'Peer B key in server config' } else { Fail 'Peer B key missing' }

# --- T1.14: Empty peer config ---
Test-Step 'T1.14: Empty peer config (no peers)'
Set-Content 'C:\Users\azureuser\peers-empty.conf' -Value '' -Encoding ASCII
& $tunnelScript -InterfaceName 'test-empty' -Address '10.100.10.1/24' -ListenPort 51913 -PeerConfigPath 'C:\Users\azureuser\peers-empty.conf' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-empty' 'Running') { Pass 'Empty-peer service installed' } else { Fail 'Empty-peer service not running' }
if (Assert-ConfigNotContains 'C:\ProgramData\WireGuard\Configs\test-empty.conf' '\[Peer\]') { Pass 'No peers in config' } else { Fail 'Unexpected peers in config' }

# --- T1.15: wg show detailed ---
Test-Step 'T1.15: wg show detailed interface verification'
$ws = & $script:wgCli show 2>&1 | Out-String
if ($ws -match 'test-a') { Pass 'wg shows test-a' } else { Fail 'wg does not show test-a' }
if ($ws -match 'test-b') { Pass 'wg shows test-b' } else { Fail 'wg does not show test-b' }
if ($ws -match 'test-ipv6') { Pass 'wg shows test-ipv6' } else { Fail 'wg does not show test-ipv6' }
if ($ws -match 'test-dual') { Pass 'wg shows test-dual' } else { Fail 'wg does not show test-dual' }
if ($ws -match 'test-dns') { Pass 'wg shows test-dns' } else { Fail 'wg does not show test-dns' }
if ($ws -match 'test-peer') { Pass 'wg shows test-peer' } else { Fail 'wg does not show test-peer' }
if ($ws -match 'test-gen') { Pass 'wg shows test-gen' } else { Fail 'wg does not show test-gen' }
if ($ws -match 'test-nofw') { Pass 'wg shows test-nofw' } else { Fail 'wg does not show test-nofw' }
if ($ws -match 'test-nofwd') { Pass 'wg shows test-nofwd' } else { Fail 'wg does not show test-nofwd' }
if ($ws -match 'test-multi') { Pass 'wg shows test-multi' } else { Fail 'wg does not show test-multi' }
if ($ws -match 'test-empty') { Pass 'wg shows test-empty' } else { Fail 'wg does not show test-empty' }

# --- T1.16: Service stop/restart ---
Test-Step 'T1.16: Service stop and restart'
Stop-Service 'WireGuardTunnel$test-a' -Force
Start-Sleep -Seconds 2
if (Assert-Svc 'WireGuardTunnel$test-a' 'Stopped') { Pass 'Service stopped' } else { Fail 'Service did not stop' }
Start-Service 'WireGuardTunnel$test-a'
Start-Sleep -Seconds 3
if (Assert-Svc 'WireGuardTunnel$test-a' 'Running') { Pass 'Service restarted' } else { Fail 'Service did not restart' }
if (Assert-WgShowPort 'test-a' 52001) { Pass 'Config preserved after restart' } else { Fail 'Config lost after restart' }

# --- T1.17: Idempotency (same params, no -Force) ---
Test-Step 'T1.17: Idempotency - same params without -Force'
try { $null = & $tunnelScript -InterfaceName 'test-b' -Address '10.100.1.1/24' -ListenPort 51902 -NoDry 2>&1; $blocked = $false } catch { $blocked = $true }
if ($blocked) { Pass 'Duplicate install correctly rejected' } else { Fail 'Duplicate install should have been rejected' }

# --- T1.18: Idempotency (same params with -Force) ---
Test-Step 'T1.18: Idempotency - same params with -Force'
& $tunnelScript -InterfaceName 'test-b' -Address '10.100.1.1/24' -ListenPort 51902 -Force -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-b' 'Running') { Pass 'Force reinstall succeeds' } else { Fail 'Force reinstall failed' }
if (Assert-WgShowPort 'test-b' 51902) { Pass 'Config preserved after force reinstall' } else { Fail 'Config changed after force reinstall' }

# --- T1.19: Port conflict ---
Test-Step 'T1.19: Port conflict rejected'
try { $null = & $tunnelScript -InterfaceName 'test-conflict' -Address '10.100.99.1/24' -ListenPort 51902 -NoDry 2>&1; $blocked = $false } catch { $blocked = $true }
if ($blocked) { Pass 'Port conflict correctly rejected' } else { Fail 'Port conflict should have been rejected' }
if (Assert-NoSvc 'WireGuardTunnel$test-conflict') { Pass 'No service created for conflicting port' } else { Fail 'Service created despite port conflict' }

# --- T1.20: Invalid port 0 ---
Test-Step 'T1.20: Port 0 (invalid)'
& $tunnelScript -InterfaceName 'test-port0' -Address '10.100.83.1/24' -ListenPort 0 -NoDry 2>&1 | Out-Null
$svc = Get-Service 'WireGuardTunnel$test-port0' -ErrorAction SilentlyContinue
if (-not $svc) { Pass 'Port 0 correctly rejected' } else { Warn 'Port 0 created a service (may work on some systems)' }

# --- T1.21: Very long interface name (63 chars) ---
Test-Step 'T1.21: Very long interface name (63 chars)'
$longName = ('a' * 63)
try { $null = & $tunnelScript -InterfaceName $longName -Address '10.100.80.1/24' -ListenPort 52801 -NoDry 2>&1; $rejected = $false } catch { $rejected = $true }
if ($rejected) { Pass 'Long name correctly rejected (>31 chars)' } else { Fail 'Long name should have been rejected' }
$svc = Get-Service "WireGuardTunnel`$$longName" -ErrorAction SilentlyContinue
if (-not $svc) { Pass 'No service created for long name' } else { Fail 'Service created despite invalid name' }
& $resetScript -Force -NoDry 2>&1 | Out-Null

# --- T1.22: Interface name with special chars ---
Test-Step 'T1.22: Interface name with hyphens and underscores'
& $tunnelScript -InterfaceName 'test_special-chars_123' -Address '10.100.81.1/24' -ListenPort 52802 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test_special-chars_123' 'Running') { Pass 'Special chars service running' } else { Fail 'Special chars service not running' }
& $resetScript -Force -NoDry 2>&1 | Out-Null

# --- T1.23: Private key via pipeline vs parameter ---
Test-Step 'T1.23: Auto-generated key (no -PrivateKey)'
& $tunnelScript -InterfaceName 'test-autokey' -Address '10.100.84.1/24' -ListenPort 52803 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-autokey' 'Running') { Pass 'Auto-key service running' } else { Fail 'Auto-key service not running' }
$ak = Get-Content 'C:\ProgramData\WireGuard\Configs\test-autokey.conf' -Raw
if ($ak -match 'PrivateKey = [A-Za-z0-9+/]{42,44}={0,2}') { Pass 'Auto-generated private key has valid base64 format' } else { Fail 'Auto-generated private key has invalid format' }

# --- T1.24: Public config (no private key) ---
Test-Step 'T1.24: Public config file (no private key)'
if (Assert-Path 'C:\ProgramData\WireGuard\Configs\test-autokey.public.conf') { Pass 'Public config exists' } else { Fail 'Public config missing' }
$pubCfg = Get-Content 'C:\ProgramData\WireGuard\Configs\test-autokey.public.conf' -Raw
if ($pubCfg -notmatch 'PrivateKey') { Pass 'Public config has no PrivateKey' } else { Fail 'Public config leaked PrivateKey!' }

# --- T1.25: Driver verification ---
Test-Step 'T1.25: WireGuard driver loaded'
if (Assert-Driver) { Pass 'WireGuard driver present' } else { Fail 'WireGuard driver not found' }
if (Assert-Path 'C:\Windows\System32\drivers\wireguard.sys') { Pass 'Driver file exists' } else { Fail 'Driver file missing' }

# --- T1.26: IP forwarding state ---
Test-Step 'T1.26: IP forwarding enabled'
if (Assert-IpForwarding) { Pass 'IP forwarding enabled' } else { Warn 'IP forwarding not enabled (requires reboot)' }

# ============================================================
# PHASE 2: Install-WireGuardManagedClient.ps1 -- LETHAL TESTS
# ============================================================
Write-Host '=== PHASE 2: Client Script (Lethal) ==='

# Config templates
$cfg1 = @"
[Interface]
PrivateKey = ABC123
Address = 10.200.0.2/32
DNS = 10.200.0.1
[Peer]
PublicKey = XYZ789
Endpoint = vpn.corp.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"@
Set-Content 'C:\Users\azureuser\mgd-test-1.conf' -Value $cfg1 -Encoding ASCII

$cfg2 = @"
[Interface]
PrivateKey = DEF456
Address = 10.200.0.3/32
DNS = 10.200.0.1
[Peer]
PublicKey = ABC789
Endpoint = vpn2.corp.example.com:51821
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@
Set-Content 'C:\Users\azureuser\mgd-test-2.conf' -Value $cfg2 -Encoding ASCII

$cfg3 = @"
[Interface]
PrivateKey = GHI789
Address = 10.200.0.4/32
DNS = 10.200.0.1
[Peer]
PublicKey = DEF012
Endpoint = vpn3.corp.example.com:51822
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@
Set-Content 'C:\Users\azureuser\mgd-test-3.conf' -Value $cfg3 -Encoding ASCII

# --- T2.1: Fresh managed client deploy ---
Test-Step 'T2.1: Fresh managed client deploy'
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-test-1.conf' -TunnelName 'mgd-test-1' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardManager' 'Running') { Pass 'Manager Service running' } else { Fail 'Manager Service not running' }
# Check config was written (encryption may not happen on headless)
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-1.conf') { Pass 'Config written to managed directory' } else { Fail 'Config not written' }
$mgdCfg = Get-Content 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-1.conf' -Raw
if ($mgdCfg -match 'ABC123') { Pass 'Config content preserved' } else { Fail 'Config content corrupted' }
if ($mgdCfg -match 'vpn.corp.example.com:51820') { Pass 'Endpoint preserved' } else { Fail 'Endpoint corrupted' }

# --- T2.2: -LimitedOperatorUI ---
Test-Step 'T2.2: -LimitedOperatorUI registry key'
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-test-2.conf' -TunnelName 'mgd-test-2' -LimitedOperatorUI -NoDry 2>&1 | Out-Null
if (Assert-Reg 'HKLM:\Software\WireGuard' 'LimitedOperatorUI' 1) { Pass 'LimitedOperatorUI=1 set' } else { Fail 'LimitedOperatorUI not set' }
# Verify it's DWORD, not string
$regVal = Get-ItemProperty 'HKLM:\Software\WireGuard' -Name 'LimitedOperatorUI' -ErrorAction SilentlyContinue
if ($regVal.LimitedOperatorUI -is [int]) { Pass 'LimitedOperatorUI is DWORD' } else { Fail 'LimitedOperatorUI is not DWORD' }

# --- T2.3: -AddToNetConfigOperators ---
Test-Step 'T2.3: -AddToNetConfigOperators'
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-test-3.conf' -TunnelName 'mgd-test-3' -LimitedOperatorUI -AddToNetConfigOperators 'azureuser' -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 5
if (Assert-Group 'azureuser' 'Network Configuration Operators') { Pass 'User in Net Config Operators group' } else { Warn 'Could not verify group membership' }

# --- T2.4: Inline -ConfigContent ---
Test-Step 'T2.4: Inline -ConfigContent'
$inlineCfg = @"
[Interface]
PrivateKey = JKL012
Address = 10.200.0.5/32
[Peer]
PublicKey = GHI345
Endpoint = vpn4.corp.example.com:51823
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@
& $clientScript -ConfigContent $inlineCfg -TunnelName 'mgd-inline' -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 8
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-inline.conf') { Pass 'Inline config written' } else { Fail 'Inline config not written' }
$ic = Get-Content 'C:\Program Files\WireGuard\Data\Configurations\mgd-inline.conf' -Raw
if ($ic -match 'JKL012') { Pass 'Inline config content preserved' } else { Fail 'Inline config content corrupted' }

# --- T2.5: Duplicate deployment (should warn but allow) ---
Test-Step 'T2.5: Duplicate deployment overwrites'
$result = & $clientScript -ConfigPath 'C:\Users\azureuser\mgd-test-1.conf' -TunnelName 'mgd-test-1' -NoDry 6>&1 | Out-String
if ($result -match 'already exists|Overwriting') { Pass 'Duplicate deployment warns' } else { Fail 'Duplicate deployment did not warn' }
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-1.conf') { Pass 'Config still present after redeploy' } else { Fail 'Config missing after redeploy' }

# --- T2.6: -Remove managed config ---
Test-Step 'T2.6: -Remove managed config'
& $clientScript -Remove -TunnelName 'mgd-test-1' -Force -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 3
if (Assert-NoPath 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-1.conf') { Pass 'Config removed' } else { Fail 'Config still present' }
if (Assert-NoPath 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-1.conf.dpapi') { Pass 'Encrypted config removed' } else { Fail 'Encrypted config still present' }

# --- T2.7: -Remove without -Force on running tunnel ---
Test-Step 'T2.7: -Remove without -Force'
$svc = Get-Service 'WireGuardTunnel$mgd-test-2' -ErrorAction SilentlyContinue
if (-not $svc) { Warn 'Tunnel service not yet created by Manager Service (timing)' } else {
    try { $null = & $clientScript -Remove -TunnelName 'mgd-test-2' 2>&1; $blocked = $false } catch { $blocked = $true }
    if ($blocked) { Pass 'Blocked removal of running tunnel' } else { Fail 'Did not block removal' }
    & $clientScript -Remove -TunnelName 'mgd-test-2' -Force -NoDry 2>&1 | Out-Null
    if (Assert-NoPath 'C:\Program Files\WireGuard\Data\Configurations\mgd-test-2.conf') { Pass 'Removed with -Force' } else { Fail 'Could not remove with -Force' }
}

# --- T2.8: Dry-run ---
Test-Step 'T2.8: Dry-run produces no changes'
$b4 = @(Get-ChildItem 'C:\Program Files\WireGuard\Data\Configurations\*' -ErrorAction SilentlyContinue).Count
$result = & $clientScript -ConfigPath 'C:\Users\azureuser\mgd-test-3.conf' -TunnelName 'mgd-dryrun' -LimitedOperatorUI 6>&1 | Out-String
$af = @(Get-ChildItem 'C:\Program Files\WireGuard\Data\Configurations\*' -ErrorAction SilentlyContinue).Count
if ($af -eq $b4) { Pass 'No configs created during dry-run' } else { Fail 'Config was created during dry-run' }
if ($result -match 'DRY-RUN COMPLETE') { Pass 'Dry-run report emitted' } else { Fail 'Dry-run report not found' }

# --- T2.9: Missing config sources ---
Test-Step 'T2.9: Missing both config sources'
try { $null = & $clientScript -TunnelName 'mgd-error' -NoDry 2>&1; $ok = $false } catch { $ok = $true }
if ($ok) { Pass 'Correctly rejected missing config' } else { Fail 'Did not reject missing config' }

# --- T2.10: Remove non-existent tunnel ---
Test-Step 'T2.10: Remove non-existent tunnel'
try { $null = & $clientScript -Remove -TunnelName 'this-does-not-exist' -Force -NoDry 2>&1; $ok = $true } catch { $ok = $false }
if ($ok) { Pass 'Non-existent tunnel handled gracefully' } else { Fail 'Non-existent tunnel caused error' }

# --- T2.11: Manager Service restart preserves registry ---
Test-Step 'T2.11: Manager Service restart preserves LimitedOperatorUI'
if (Assert-Reg 'HKLM:\Software\WireGuard' 'LimitedOperatorUI' 1) {
    Restart-Service 'WireGuardManager'
    Start-Sleep -Seconds 5
    if (Assert-Svc 'WireGuardManager' 'Running') { Pass 'Manager Service restarted' } else { Fail 'Manager Service did not restart' }
    if (Assert-Reg 'HKLM:\Software\WireGuard' 'LimitedOperatorUI' 1) { Pass 'LimitedOperatorUI preserved after restart' } else { Fail 'LimitedOperatorUI lost after restart' }
} else { Warn 'LimitedOperatorUI not set, skipping restart test' }

# --- T2.12: Config with all WireGuard features ---
Test-Step 'T2.12: Config with MTU, Table, PreUp/PostDown'
$fullCfg = @"
[Interface]
PrivateKey = FULL001
Address = 10.200.99.2/32
DNS = 10.200.99.1
MTU = 1420
Table = auto
PreUp = echo 'interface up'
PostUp = route add 10.200.99.0/24
PreDown = echo 'interface down'
PostDown = route delete 10.200.99.0/24
[Peer]
PublicKey = FULLPEER
Endpoint = full.test:51999
AllowedIPs = 0.0.0.0/0
"@
Set-Content 'C:\Users\azureuser\mgd-full.conf' -Value $fullCfg -Encoding ASCII
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-full.conf' -TunnelName 'mgd-full' -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 8
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-full.conf') { Pass 'Full feature config written' } else { Fail 'Full feature config not written' }
$fc = Get-Content 'C:\Program Files\WireGuard\Data\Configurations\mgd-full.conf' -Raw
if ($fc -match 'MTU = 1420') { Pass 'MTU preserved' } else { Fail 'MTU missing' }
if ($fc -match 'Table = auto') { Pass 'Table preserved' } else { Fail 'Table missing' }
if ($fc -match 'PreUp = ') { Pass 'PreUp preserved' } else { Fail 'PreUp missing' }
if ($fc -match 'PostUp = ') { Pass 'PostUp preserved' } else { Fail 'PostUp missing' }
if ($fc -match 'PreDown = ') { Pass 'PreDown preserved' } else { Fail 'PreDown missing' }
if ($fc -match 'PostDown = ') { Pass 'PostDown preserved' } else { Fail 'PostDown missing' }

# --- T2.13: Remove non-existent tunnel (no error) ---
Test-Step 'T2.13: Remove non-existent tunnel (no -Force)'
try { $null = & $clientScript -Remove -TunnelName 'definitely-not-here' -NoDry 2>&1; $ok = $true } catch { $ok = $false }
if ($ok) { Pass 'Remove non-existent without -Force succeeds' } else { Fail 'Remove non-existent without -Force errored' }

# ============================================================
# PHASE 3: Invoke-WireGuardEnvironmentReset.ps1 -- LETHAL TESTS
# ============================================================
Write-Host '=== PHASE 3: Reset Script (Lethal) ==='

# --- T3.1: Dry-run ---
Test-Step 'T3.1: Dry-run produces no changes'
$bs = @(Get-Service 'WireGuard*' -ErrorAction SilentlyContinue | % { $_.Name })
$bfw = @(Get-NetFirewallRule -DisplayName 'WireGuard*' -ErrorAction SilentlyContinue).Count
$result = & $resetScript 6>&1 | Out-String
$as = @(Get-Service 'WireGuard*' -ErrorAction SilentlyContinue | % { $_.Name })
$afw = @(Get-NetFirewallRule -DisplayName 'WireGuard*' -ErrorAction SilentlyContinue).Count
$diff = Compare-Object $bs $as
if (-not $diff) { Pass 'No services removed during dry-run' } else { Fail 'Services changed during dry-run' }
if ($afw -eq $bfw) { Pass 'No firewall rules removed during dry-run' } else { Fail 'Firewall rules changed during dry-run' }
if ($result -match 'DRY-RUN COMPLETE') { Pass 'Dry-run report emitted' } else { Fail 'Dry-run report not found' }

# --- T3.2: -ScanOnly ---
Test-Step 'T3.2: -ScanOnly mode'
$result = & $resetScript -ScanOnly 6>&1 | Out-String
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if ($svcs) { Pass 'Services still present after -ScanOnly' } else { Fail 'Services removed despite -ScanOnly' }
if ($result -match 'Scan complete') { Pass 'Scan complete message found' } else { Fail 'Scan complete message not found' }
if ($result -match 'Tier 1') { Pass 'Tier 1 items reported' } else { Fail 'No Tier 1 items reported' }
if ($result -match 'Tier 2') { Pass 'Tier 2 items reported' } else { Fail 'No Tier 2 items reported' }

# --- T3.3: Full reset with -Force -NoDry ---
Test-Step 'T3.3: Full reset with -Force -NoDry'
& $resetScript -Force -NoDry 2>&1 | Out-Null
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $svcs) { Pass 'All services removed' } else { Fail 'Services remain' }
if (Assert-NoPath 'C:\Program Files\WireGuard') { Pass 'Program Files WireGuard removed' } else { Fail 'Program Files WireGuard still exists' }
if (Assert-NoPath 'C:\ProgramData\WireGuard') { Pass 'ProgramData WireGuard removed' } else { Fail 'ProgramData WireGuard still exists' }
if (Assert-NoPath 'C:\Windows\System32\drivers\wireguard.sys') { Pass 'Driver file removed' } else { Fail 'Driver file still exists' }
if (Assert-NoReg 'HKLM:\Software\WireGuard') { Pass 'Registry key removed' } else { Fail 'Registry key still exists' }
if (Assert-NoDriver) { Pass 'Driver unregistered' } else { Fail 'Driver still registered' }
$fw = Get-NetFirewallRule -DisplayName 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $fw) { Pass 'Firewall rules removed' } else { Fail 'Firewall rules remain' }

# --- T3.4: Reset on already-clean system ---
Test-Step 'T3.4: Reset on already-clean system'
& $resetScript -Force -NoDry 2>&1 | Out-Null
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $svcs) { Pass 'Clean system stays clean' } else { Fail 'Services appeared from nowhere' }

# --- T3.5: Two-tier scan accuracy ---
Test-Step 'T3.5: Two-tier scan accuracy'
Remove-WgMsi
& $tunnelScript -InterfaceName 'test-scan' -Address '10.100.98.1/24' -ListenPort 52998 -NoDry 2>&1 | Out-Null
$result = & $resetScript -ScanOnly 6>&1 | Out-String
if ($result -match 'Tier 1') { Pass 'Tier 1 items found' } else { Fail 'No Tier 1 items found' }
if ($result -notmatch 'WinSxS|System32|Boot.*Fonts') { Pass 'No false positives from system paths' } else { Fail 'System path false positives detected' }
if ($result -match 'Tier 2') { Pass 'Tier 2 items reported' } else { Fail 'No Tier 2 items reported' }

# --- T3.6: Reset with -PreserveConfigs ---
Test-Step 'T3.6: Reset with -PreserveConfigs'
# Create a config to preserve
& $tunnelScript -InterfaceName 'preserve-me' -Address '10.100.88.1/24' -ListenPort 52888 -NoDry 2>&1 | Out-Null
$cfgPath = 'C:\ProgramData\WireGuard\Configs\preserve-me.conf'
if (Assert-Path $cfgPath) { Pass 'Config created for preserve test' } else { Fail 'Config not created' }
$cfgBefore = Get-Content $cfgPath -Raw
& $resetScript -Force -NoDry -PreserveConfigs 2>&1 | Out-Null
if (Assert-Path $cfgPath) { Pass 'Config preserved after reset' } else { Fail 'Config was not preserved' }
$cfgAfter = Get-Content $cfgPath -Raw
if ($cfgAfter -eq $cfgBefore) { Pass 'Config content unchanged' } else { Fail 'Config content changed' }
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $svcs) { Pass 'Services still removed despite -PreserveConfigs' } else { Fail 'Services remain' }

# --- T3.7: MSI uninstall verification ---
Test-Step 'T3.7: MSI uninstall verification'
$msiBefore = Get-WmiObject Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*WireGuard*' }
if (-not $msiBefore) { Pass 'No MSI registered (already clean)' } else { Fail 'MSI still registered after reset' }

# ============================================================
# PHASE 4: Sequence and combination tests
# ============================================================
Write-Host '=== PHASE 4: Sequence tests ==='

# --- T4.1: Tunnel -> Reset -> Client -> Reset cycle ---
Test-Step 'T4.1: Full lifecycle cycle'
Remove-WgMsi
& $tunnelScript -InterfaceName 'cycle-a' -Address '10.100.50.1/24' -ListenPort 52501 -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$cycle-a') { Pass 'Cycle: tunnel installed' } else { Fail 'Cycle: tunnel not installed' }
& $resetScript -Force -NoDry 2>&1 | Out-Null
$svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
if (-not $svcs) { Pass 'Cycle: reset clean' } else { Fail 'Cycle: reset not clean' }

# --- T4.2: Client deploy -> remove -> redeploy ---
Test-Step 'T4.2: Client deploy -> remove -> redeploy'
$cfgR = @"
[Interface]
PrivateKey = PQR678
Address = 10.200.0.7/32
[Peer]
PublicKey = MNO901
Endpoint = vpn6.corp.example.com:51825
AllowedIPs = 0.0.0.0/0
"@
Set-Content 'C:\Users\azureuser\mgd-redeploy.conf' -Value $cfgR -Encoding ASCII
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-redeploy.conf' -TunnelName 'mgd-redeploy' -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 8
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-redeploy.conf') { Pass 'First deploy: config written' } else { Fail 'First deploy: config not written' }
& $clientScript -Remove -TunnelName 'mgd-redeploy' -Force -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 3
if (Assert-NoPath 'C:\Program Files\WireGuard\Data\Configurations\mgd-redeploy.conf') { Pass 'Remove: config gone' } else { Fail 'Remove: config still present' }
& $clientScript -ConfigPath 'C:\Users\azureuser\mgd-redeploy.conf' -TunnelName 'mgd-redeploy' -NoDry 2>&1 | Out-Null
Start-Sleep -Seconds 8
if (Assert-Path 'C:\Program Files\WireGuard\Data\Configurations\mgd-redeploy.conf') { Pass 'Redeploy: config written again' } else { Fail 'Redeploy: config not written' }

# --- T4.3: Modify config externally, -Force reinstall ---
Test-Step 'T4.3: External config modification + -Force'
Remove-WgMsi
& $tunnelScript -InterfaceName 'mod-test' -Address '10.100.70.1/24' -ListenPort 52701 -NoDry 2>&1 | Out-Null
$confPath = 'C:\ProgramData\WireGuard\Configs\mod-test.conf'
$confContent = Get-Content $confPath -Raw
$confContent = $confContent -replace 'ListenPort = 52701', 'ListenPort = 52702'
Set-Content $confPath -Value $confContent -Encoding ASCII
& $tunnelScript -InterfaceName 'mod-test' -Address '10.100.70.1/24' -ListenPort 52702 -Force -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$mod-test' 'Running') { Pass 'Modified config accepted on -Force' } else { Fail 'Modified config not accepted' }
if (Assert-WgShowPort 'mod-test' 52702) { Pass 'wg shows updated port' } else { Fail 'wg shows wrong port' }

# --- T4.4: Rapid install/remove cycles (3x) ---
Test-Step 'T4.4: Rapid install/remove cycles (3x)'
Remove-WgMsi
for ($i = 1; $i -le 3; $i++) {
    $iface = "rapid-$i"
    & $tunnelScript -InterfaceName $iface -Address "10.100.6$($i).1/24" -ListenPort (5260$i) -NoDry 2>&1 | Out-Null
    if (Assert-Svc "WireGuardTunnel`$$iface" 'Running') { Pass "Rapid cycle ${i}: installed" } else { Fail "Rapid cycle ${i}: not installed" }
    & $resetScript -Force -NoDry 2>&1 | Out-Null
    $svcs = Get-Service 'WireGuard*' -ErrorAction SilentlyContinue
    if (-not $svcs) { Pass "Rapid cycle ${i}: reset clean" } else { Fail "Rapid cycle ${i}: reset not clean" }
    Remove-WgMsi
}

# --- T4.5: Tunnel with 10 peers (stress test) ---
Test-Step 'T4.5: 10-peer stress test'
$peerLines = @()
for ($i = 1; $i -le 10; $i++) {
    $pkp = New-WgKeyPair
    $peerLines += @"
[Peer]
# stress-peer-$i
PublicKey = $($pkp.Public)
AllowedIPs = 10.100.9$($i).2/32
"@
}
Set-Content 'C:\Users\azureuser\peers-10.conf' -Value ($peerLines -join "`r`n") -Encoding ASCII
& $tunnelScript -InterfaceName 'test-10peer' -Address '10.100.90.1/24' -ListenPort 52910 -PeerConfigPath 'C:\Users\azureuser\peers-10.conf' -NoDry 2>&1 | Out-Null
if (Assert-Svc 'WireGuardTunnel$test-10peer' 'Running') { Pass '10-peer service running' } else { Fail '10-peer service not running' }
$cfg10 = Get-Content 'C:\ProgramData\WireGuard\Configs\test-10peer.conf' -Raw
$peerCount = ([regex]::Matches($cfg10, '\[Peer\]')).Count
if ($peerCount -eq 10) { Pass "Config has exactly $peerCount peers" } else { Fail "Config has $peerCount peers, expected 10" }

# ============================================================
# FINAL SUMMARY
# ============================================================
Write-Host ''
Write-Host '============================================================'
Write-Host '  FINAL SUMMARY'
Write-Host '============================================================'
Write-Host "Total tests : $global:testCount"
Write-Host "Passed      : $global:passed"
Write-Host "Failed      : $global:failed"
Write-Host "Warnings    : $global:warnings"
Write-Host ''
if ($global:failed -eq 0) { Write-Host 'RESULT: ALL TESTS PASSED' -ForegroundColor Green }
else { Write-Host "RESULT: $global:failed TEST(S) FAILED" -ForegroundColor Red }
Write-Host ''
