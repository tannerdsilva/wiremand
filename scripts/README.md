# WireGuard for Windows -- Enterprise Deployment Scripts

A suite of PowerShell scripts for deploying, managing, and removing WireGuard
on Windows Server and Windows client machines in enterprise environments.

These scripts are designed for organizations that manage Windows endpoints
standalone (no Active Directory / Domain Controller) with consistent local
administrator credentials, and need to deploy WireGuard at scale across a
fleet of machines that may have been set up manually with varying degrees
of consistency.

---

## Scripts

### `Install-WireGuardTunnel.ps1`
**Headless tunnel service.** Installs a persistent WireGuard tunnel that runs
as a standalone Windows service. No Manager Service, no GUI visibility. The
tunnel starts at boot and is managed via `services.msc` or `sc.exe`.

**Use when:** You need an always-on infrastructure link -- site-to-site VPN,
management plane, monitoring backhaul, or any WireGuard peer that should
never appear in the system tray and never be touched by an end user.

Key parameters:

| Parameter | Purpose |
|-----------|---------|
| `-InterfaceName` | Tunnel name (default: `wg0`) |
| `-Address` | Comma-separated IPs for the interface (REQUIRED) |
| `-ListenPort` | UDP port (default: `51820`) |
| `-PeerConfigPath` | Path to a file containing `[Peer]` sections |
| `-GenerateClientConfigs` | Emit a ready-to-deploy `.conf` per peer |
| `-Endpoint` | Public address for generated client configs |
|| `-Force` | Remove and re-create an existing tunnel service (also cleans up stale firewall rules) |
|| `-NoFirewall` | Skip firewall rule creation |
|| `-NoForwarding` | Skip enabling IP forwarding |
|| `-NoDry` | Execute changes for real (default is dry-run) |

**Input validation:**

The script validates all parameters before making any changes:

| Check | Behavior |
|-------|----------|
| `-InterfaceName` length | Rejected if > 31 characters (WireGuard service name limit) |
| `-InterfaceName` characters | Only `[a-zA-Z0-9_-]` allowed |
| `-ListenPort` range | Rejected if 0 or > 65535 |
| Duplicate tunnel | Rejected unless `-Force` is passed |
| Port conflict | Rejected if another tunnel already uses the same UDP port |

Example:
```powershell
.\Install-WireGuardTunnel.ps1 `
    -InterfaceName "corp-infra" `
    -Address "10.99.0.1/24,fd00:1::1/64" `
    -ListenPort 51820 `
    -PeerConfigPath ".\peers.conf" `
    -Endpoint "vpn.corp.example.com:51820" `
    -GenerateClientConfigs
```

---

### `Install-WireGuardManagedClient.ps1`
**Managed client with locked configuration.** Deploys a WireGuard client
configuration and integrates it with the WireGuard Manager Service. The end
user sees the tunnel in the system tray and can start/stop it, but **cannot
remove or edit** the configuration.

**Use when:** You need to deploy a corporate VPN profile to end users who
should have self-service start/stop capability without being able to
delete or modify the configuration.

Key parameters:

| Parameter | Purpose |
|-----------|---------|
| `-ConfigPath` | Path to a `.conf` file to deploy |
| `-ConfigContent` | Inline WireGuard config string (alternative to `-ConfigPath`) |
| `-TunnelName` | Name for the tunnel (derived from filename if omitted) |
| `-LimitedOperatorUI` | Enable restricted system-tray UI for members of the Network Configuration Operators group |
| `-AddToNetConfigOperators` | Add a user to the Network Configuration Operators group (defaults to current user when `-LimitedOperatorUI` is passed) |
| `-Remove` | Remove a previously deployed managed config |
| `-Force` | When removing, stop the tunnel service first |
| `-NoDry` | Execute changes for real (default is dry-run) |

Example:
```powershell
.\Install-WireGuardManagedClient.ps1 `
    -ConfigPath ".\corp-user-01.conf" `
    -TunnelName "corp-vpn" `
    -LimitedOperatorUI `
    -AddToNetConfigOperators "CONTOSO\jdoe"
```

**About the `LimitedOperatorUI` registry key:**

This script sets `HKLM\Software\WireGuard\LimitedOperatorUI` (REG_DWORD=1)
when `-LimitedOperatorUI` is passed. The key is read by the WireGuard Manager
Service at startup (cached via `sync.Once` in the Go source). It enables a
restricted system-tray UI for users who are members of the builtin **Network
Configuration Operators** group (S-1-5-32-556). The restricted UI allows
starting and stopping tunnels but forbids adding, removing, editing,
importing, or exporting configurations.

Critical details:
- **Scope:** Machine-wide (HKLM). Affects ALL tunnels for ALL qualifying users.
- **Group dependency:** The key has NO effect unless the user is a member of
  the Network Configuration Operators group. This group exists on every
  Windows machine (no DC required) but is empty by default.
- **Administrators are unaffected:** Admins always see the full UI.
- **Caching:** The Manager Service caches the key at process start. The script
  restarts the service after setting the key so the change takes effect
  immediately.
- **No `DisableRemove` key exists:** Config locking is handled by the Manager
  Service's DPAPI encryption (`.conf.dpapi`), not by a registry setting.

---

### `Invoke-WireGuardEnvironmentReset.ps1`
**Full environment reset.** Forcefully removes every trace of WireGuard from
a Windows system. Stops and uninstalls all tunnel services and the Manager
Service, removes the kernel driver, uninstalls the MSI product, deletes
registry keys, removes firewall rules, and scans the filesystem for
WireGuard artifacts.

**Use when:** You need to clean a machine that was set up manually or by a
previous deployment, before applying a fresh configuration. Also useful for
testing and validation workflows.

Key parameters:

| Parameter | Purpose |
|-----------|---------|
| `-Force` | Skip confirmation prompts |
| `-NoDry` | Execute changes for real (default is dry-run) |
| `-ScanOnly` | Only scan and report findings, do not remove anything |
| `-PreserveConfigs` | Do not delete configuration/data directories |

**Two-tier filesystem scan:**

The script scans `C:\` to depth 2 using two tiers of pattern matching:

- **Tier 1** (`*[Ww]ire[Gg]uard*`): High-confidence matches. These are
  automatically removed. Catches `WireGuard` directories, `wireguard.exe`,
  `wireguard.sys`, and any file or directory with "WireGuard" in its name.
- **Tier 2** (`*wg*.exe`, `*wg*.sys`, `*wg*.conf`, `*wg*.dll`): Broader
  matches that could include non-WireGuard system files (e.g., `wgl4_boot.ttf`,
  `slwga.dll`, `AuthFWGP.dll`). These are **reported but NOT automatically
  removed**. Known Windows system paths (WinSxS, System32, SysWOW64, Boot,
  Fonts, Manifests) are excluded from Tier 2 matching entirely.

Example:
```powershell
# Preview what would be removed (default, no flag needed)
.\Invoke-WireGuardEnvironmentReset.ps1

# Full reset without prompts
.\Invoke-WireGuardEnvironmentReset.ps1 -Force -NoDry

# Just scan and report
.\Invoke-WireGuardEnvironmentReset.ps1 -ScanOnly
```

---

## Dry-run mode (default, all three scripts)

By default, every script runs in **dry-run mode**: it produces a structured
`[DRY-RUN]`-prefixed output showing all parameters, the full execution plan,
every action with its condition, and detailed information about each action.
No system modifications are made.

Pass `-NoDry` to execute changes for real.

The output is designed to be parsable by low-parameter-count models and
readable by humans.

---

## Deployment workflow

For a typical enterprise deployment across a fleet of standalone machines:

1. **Reset** each machine to a known state:
   ```powershell
   .\Invoke-WireGuardEnvironmentReset.ps1 -Force -NoDry
   ```

2. **Deploy the server/infrastructure tunnel** on gateway machines:
   ```powershell
   .\Install-WireGuardTunnel.ps1 -InterfaceName "site-a" -Address "10.0.0.1/24" -PeerConfigPath ".\peers.conf"
   ```

3. **Deploy the managed client** on end-user machines:
   ```powershell
   .\Install-WireGuardManagedClient.ps1 -ConfigPath ".\user-profile.conf" -TunnelName "corp-vpn" -LimitedOperatorUI
   ```

4. **Verify** with `wg show` and `Get-Service "WireGuard*"`.

---

## Testing

A comprehensive test battery is included at `test_battery_lethal.ps1`. It runs
against a live Windows VM over SSH and covers:

- **Phase 1 (20 tests):** Tunnel script -- fresh install, isolation, IPv6,
  dual-stack, DNS, peer configs, client config generation, force reinstall,
  NoFirewall, NoForwarding, dry-run, missing parameters, multiple peers, empty
  peers, wg show verification, service stop/restart, duplicate rejection, port
  conflict, port 0 rejection
- **Phase 2 (10 tests):** Managed client script
- **Phase 3 (5 tests):** Environment reset script
- **Phase 4 (4 tests):** End-to-end sequences
- **Phase 5 (4 tests):** Edge cases (rapid cycles, long names, special chars,
  concurrent installs)

See `TEST_RESULTS.md` for the latest test results.

---

## Notes

- All scripts require **Administrator** privileges.
- WireGuard MSI is downloaded automatically from
  `download.wireguard.com/windows-client/` if not already installed.
- The MSI version is pinned to `0.5.3` (latest stable at time of writing).
  Update the `$url` variable in each script to change the version.
- Scripts are tested on **Windows Server 2022** and **Windows 11**.
- Dual-stack (IPv4 + IPv6) is supported throughout.
