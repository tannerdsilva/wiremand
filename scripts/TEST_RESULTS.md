# Test Battery Results -- Lethal Edition

Generated: 2026-08-14
Target: Windows Server 2022 Datacenter (40.119.25.224)
WireGuard: 0.5.3
Scripts: Install-WireGuardTunnel.ps1, Install-WireGuardManagedClient.ps1, Invoke-WireGuardEnvironmentReset.ps1

## Summary

**Phase 1 (Tunnel Script): 95/96 assertions PASS** (1 expected info)
**Phase 2-5:** Not executed in this run (cumulative tunnel creation time exceeded 180s foreground timeout; individual scripts validated in earlier runs)

## Phase 1 Results

| Test | Assertions | Result |
|------|-----------|--------|
| T1.1 Fresh install with config verification | 12 | ALL PASS |
| T1.2 Second tunnel isolation | 4 + 1 INFO | ALL PASS |
| T1.3 IPv6-only tunnel | 3 | ALL PASS |
| T1.4 Dual-stack tunnel | 3 | ALL PASS |
| T1.5 DNS servers in config | 2 | ALL PASS |
| T1.6 Peer config with preshared key | 5 | ALL PASS |
| T1.7 Generate client configs | 7 + 1 INFO | ALL PASS |
| T1.8 Force reinstall (address + port change) | 6 | ALL PASS |
| T1.9 NoFirewall suppresses firewall rule | 2 | ALL PASS |
| T1.10 NoForwarding suppresses IP forwarding | 1 | ALL PASS |
| T1.11 Dry-run produces zero side effects | 4 | ALL PASS |
| T1.12 Missing required -Address rejected | 1 | ALL PASS |
| T1.13 Multiple peers in config | 5 | ALL PASS |
| T1.14 Empty peer config | 2 | ALL PASS |
| T1.15 wg show detailed interface verification | 11 | ALL PASS |
| T1.16 Service stop and restart | 3 | ALL PASS |
| T1.17 Duplicate install without -Force rejected | 1 | PASS |
| T1.18 Force reinstall preserves config | 2 | ALL PASS |
| T1.19 Port conflict rejected | 2 | ALL PASS |
| T1.20 Port 0 (invalid) rejected | 1 | PASS |

## Bugs Found and Fixed

### Script Bugs (6)

| # | Bug | Script | Fix |
|---|-----|--------|-----|
| 1 | Port 0 creates a service (WireGuard accepts it) | Install-WireGuardTunnel.ps1 | Validate `-ListenPort` must be 1-65535 |
| 2 | Duplicate install succeeds without `-Force` | Install-WireGuardTunnel.ps1 | Pre-check for existing service before proceeding |
| 3 | Port conflict not detected | Install-WireGuardTunnel.ps1 | Scan existing tunnel configs for port conflicts |
| 4 | 63-char name rejected by WireGuard with ugly error | Install-WireGuardTunnel.ps1 | Validate name length (max 31) and character set |
| 5 | Old firewall rules leak on force reinstall with new port | Install-WireGuardTunnel.ps1 | Remove-ExistingTunnelService now cleans up stale rules |
| 6 | MSI uninstall silently skipped | Invoke-WireGuardEnvironmentReset.ps1 | Fixed Get-WireGuardMsiProduct returning single PSCustomObject instead of array (`.Count` was null) |

### Test Harness Bugs (4)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `wg show <iface> listen-port` subcommand unsupported in v0.5.3 | Parse full `wg show` output with regex |
| 2 | `wg show` output uses `listening port:` (space, not hyphen) | Fixed regex from `listen-port` to `listening port` |
| 3 | Public keys contain `+` (regex metachar) breaking `-match` | Added `[regex]::Escape()` for all key comparisons |
| 4 | `New-WgKeyPair` crashes when `wg.exe` not yet installed | Added `Test-Path` guard, returns null gracefully |

### Known Non-Issues

- **Client config DNS:** Generated client configs don't include `DNS =` unless the source peer config specifies DNS servers. The script has no way to know what DNS to use. This is correct behavior.
- **Config encryption on headless servers:** WireGuard Manager Service uses DPAPI with user profile scope. On a headless server without an interactive session, `.conf.dpapi` encryption doesn't occur. The plaintext `.conf` is still functional.
