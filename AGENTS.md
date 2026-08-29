# AGENTS.md

Guidance for autonomous agents working on the **wiremand** codebase.

## What this project is

Wiremand is a **Linux-only**, Swift 6 command-line tool and systemd daemon that manages the full lifecycle of a WireGuard VPN server: client provisioning and revocation, logical domain segmentation, per-client nftables whitelisting, dnsmasq DNS integration, automatic handshake-based revocation, and optional ipstack.com geolocation.

It is a root-managed system daemon. The `install` subcommand mutates the host (systemd units, `/etc/wireguard`, `/etc/dnsmasq.conf`, sudoers, sysctl, self-signed TLS). The `run` subcommand is the long-lived daemon process.

Platform: **Linux only**. It builds against `libnftables` and raw netlink; it does not build or run on macOS in its current form.

## Build environment (read this first)

1. **Toolchain.** `Package.swift` is `// swift-tools-version:6.3` — requires a Swift 6.3+ toolchain. Build/test from the repo root: `swift build`, `swift test`.
2. **Dependencies resolve from GitHub** — there are no active local paths in the manifest except `swift-mcp` (`//.package(path: ...)` lines are commented out and historical). Pinned as: swift-argument-parser (`1.5.1..<2.0.0`), SwiftSlash (`4.0.5..<5.0.0`), QuickLMDB (branch `master`), bedrock (branch `compare_amend`), Hummingbird 2 (`2.9.0..<3.0.0`), rawdog (`20.0.0..<21.0.0`), async-http-client, swift-log, swift-service-lifecycle (`2.6.3..<3.0.0`), swift-nio, **swift-mcp (local path `../swift-mcp`)**. The swift-mcp dependency is local because wiremand's MCP integration depends on swift-mcp API additions (public transport initializer + accessResolver hook + instance-tool access guard) that are **not yet in a tagged release** — a follow-up swift-mcp release must be cut and the URL form restored before this can be pinned publicly. Resolution requires outbound access to github.com — do not assume anything is vendored or fetched automatically.
3. **System library.** `Clibnftables` is a Swift `systemLibrary` with `pkgConfig: "libnftables"` and the apt provider `libnftables-dev`. You must `apt-get install libnftables-dev` (plus the netlink/`linux-headers` headers for `Crtnetlink`) before building. The daemon talks to nftables in-process via the C API, not by shelling out to the `nft` binary.
4. Because of (2) and (3), the package cannot be built inside a stock macOS or non-Linux container environment. On macOS the `Clibnftables` systemLibrary fails resolution before compilation. Verify the toolchain (`swift --version`, `pkg-config libnftables`) before promising a build.
5. **Release builds** go through the repo `Makefile` (release-only, no debug target): `make` = `swift build -c release`, `make install` / `make update` delegate to the binary's own `install`/`update` subcommands (giving `/opt/wiremand`, systemd, sudoers, certs). The binary copies `argv[0]` to `/opt/wiremand`, so the build product must not be moved before these run.

## Repository layout

```
Sources/
  wiremand/                    # executable target: CLI + daemon + execute layer
    CLI/                       # Swift ArgumentParser subcommands
      MainProgram.swift        # entrypoint, subcommand registry, reset-public-addresses
      Installer.swift          # install + update (root; daemon unit hardening lives here)
      Daemon.swift             # `run` daemon: firewall bootstrap + ServiceGroup
      Domain.swift             # domain make/remove/list
      Client.swift             # client make/list/rename/revoke/punt/add-domain [--public-key]/remove-domain [--public-key]/mcp-access
      Firewall.swift           # firewall add-rule/delete-rules/list
      IPStack.swift            # ipstack get/set API key
      ArgumentExtensions.swift # Path:ExpressibleByArgument etc.
    Services/
      FirewallService.swift       # renders + tears down the nftables ruleset (Service)
      HandshakeChecker.swift   # 10s poll of `wg show`; updates DB, revokes, resolves IPs
      IPStacker.swift          # 10m geolocation resolution loop
      Webserver.swift          # Hummingbird HTTPS provisioning API (wg_makekey / wg_getkey)
      MCPAccessServer.swift    # builds the internal MCP admin server (accessResolver + tool registration)
    Execute/
      WireguardExecute.swift   # wg genkey/genpsk/pubkey, wg set peer, wg-quick save, ip addr
      MCP/
        MCPAuth.swift          # MCPDeps, caller-identity resolution, argument helpers
        MCPDomainTools.swift   # domain_make / domain_list tools
        MCPClientTools.swift   # client make/list/rename/revoke/punt/add-domain/remove-domain tools
        MCPFirewallTools.swift # firewall add-rule/delete-rules/list tools
        MCPSystemTools.swift   # ipstack get/set + reset-public-addresses tools
      NFTables/
        NFTablesExecutor.swift # in-process libnftables context wrapper
        FirewallExecute.swift  # builds nft tables/chains for whitelist + domain isolation
        FirewallSync.swift     # incremental per-chain sync (mirror-based delta)
      DNSmasq.swift            # exports hosts-auto entries, reloads dnsmasq
      RTNetlink.swift          # Swift wrapper over Crtnetlink for addr/route/iface dumps
      SelfSignedCertExecutor.swift
    Colors.swift               # ANSI 8-bit color helpers for informational output
  wiremand_databases/          # library target: all LMDB persistence
    WGDB/WGDB.swift            # core: WireguardDatabase, domain/client model, handshake engine
    WGDB/RandomAddress.swift   # random address allocation within a subnet
    FirewallDB/FirewallDB.swift# per-network nft rules
    IPDatabase/                # ipstack cache + ResolvedIPInfo
    Scheduler/                 # Scheduler (interval runner) + DateUTC
    Extensions/                # Date/String/URL/BedrockDate helpers
  Clibnftables/                # systemLibrary (modulemap only; pkg-config libnftables)
  Crtnetlink/                  # C module: raw netlink socket helpers (Ctrnetlink.c + include/)
Tests/wiremandTests/           # Swift Testing (@Suite/@Test)
scripts/                       # Windows PowerShell deployment scripts + lethal test battery
docs/security-verification.md  # systemd unit hardening verification procedure + residual exposure notes
```

## Architecture

The daemon (`wiremand run`) runs five Swift ServiceLifecycle services under one `ServiceGroup` (graceful shutdown on SIGTERM/SIGINT). The firewall is itself a service (`FirewallService`): it renders the ruleset on start and deletes the `ip_filter`/`ip6_filter` tables it owns on graceful shutdown. It is declared *first* in the group so the `ServiceGroup` tears it down *last* (services shut down in reverse declaration order), after the traffic-serving services have stopped. The MCP server (a single swift-mcp `MCPServer`, itself a `Service`) is registered directly in the group between the webserver and the handshake checker.

| Service | Cadence | Responsibility |
|---------|---------|----------------|
| `FirewallService` | start + shutdown | Renders custom rules + managed tables/chains (whitelist, isolation, trace) on start; `delete table` teardown on graceful shutdown. |
| `HandshakeChecker` | 10 s | Runs `sudo wg show <iface> latest-handshakes` and `endpoints`, parses tab-separated output, feeds `WireguardDatabase.processHandshakes`, enqueues IP resolutions, uninstalls revoked peers. |
| `IPStacker` | 600 s | Pulls pending endpoint IPs from `IPDatabase`, calls ipstack.com, stores resolved geolocation or moves failures to a failed table. |
| `PublicHTTPWebServer` | n/a | Hummingbird 2 TLS server bound to both public IPv4 and IPv6. Serves the self-service provisioning API. |
| MCP `MCPServer` (built by `MCPAccessServer`) | n/a | swift-mcp server bound to the server's own wireguard interface address (default port 8095, `--mcp-port`). Authorizes peers by source-IP → public key → MCP grant bit. |

All external effects go through the `Execute/` layer using the user's **SwiftSlash** library (`Command(sh: "...")` with `sudo`), or the in-process C bindings for nftables and netlink.

## MCP admin server

`wiremand run --mcp-port <port>` (default 8095) hosts a swift-mcp server bound to the server's own wireguard interface address (`wg_serverPrimarySubnet` `.addressString`). There is **no public-interface binding**: reachability requires passing through the authenticated tunnel.

Authorization is two-layered:

1. **accept time** — the `TCPTransport` access resolver remote address reverse-maps the connection's source IP to a client public key (`ip_clientPub`) and requires the grant bit in `wgdb_clientPub_mcpAccess` (presence = granted). Anything else resolves to `.public`, below every tool's `.admin` requirement — a non-granted peer gets an empty `tools/list` and `-32000 Access denied` on `tools/call`.
2. **per call** — every tool is a hand-written `MCPTool` conformance under `Execute/MCP/` (deliberately **not** `@MCPCommand`), and each `invoke(context:)` re-resolves the caller's public key from `MCPContext.callerInfo.sourceAddress` and re-checks the grant. Revoking a grant (or removing the client) takes effect immediately on already-open connections.

The tool surface mirrors the CLI except `install`, `update`, `run`, and `domain remove`, which are deliberately absent. One boolean, mapped to `.admin`, is the only tier. Grant/revoke with `wiremand client mcp-access --domain <d> --name <n> --grant|--revoke` (`client list` shows granted keys with an `[mcp]` tag).

## Domain & client data model (the heart of the system)

The whole design is an LMDB key-value model in `WireguardDatabase`. Internal identifiers are **BLAKE2 hashes**, not strings: domain names become `DomainHash` (8 bytes), client names become `ClientNameHash` (16 bytes). Public keys are raw Curve25519 `PublicKey` (32 bytes). `SecurityKey` is 512 random bytes issued per domain to gate the public make-key API.

Core invariants to preserve when editing `WGDB.swift`:

- **A client (public key) can belong to multiple domains.** `clientPub_ip` is a DupSort (key = pubkey, dup = address). Removing a client from its *only* domain revokes it entirely (`_clientRemove`); removing from one of several only detaches that domain's address/name entries.
- **The server's own key (`localhost`) is immutable.** All mutation paths guard `serverPublicKey != publicKey` and throw `WGDBError.immutableClient`.
- **Every cross-reference has a reverse index** (e.g. `clientPub_ip` ↔ `ip_clientPub`, `domainHash_network` ↔ `network_domainHash`, `domainHash_clientPub` ↔ `clientPub_domainHash`). When you add/delete a row, update both directions or the read paths (`allClients`, `domainRemove`) corrupt.
- **Address allocation is random** within a domain subnet and must not collide (`RandomAddress` + a `containsEntry` re-roll loop). The allocation loop is bounded (2048 attempts in `_allocateAddress`) and throws `WGDBError.addressSpaceExhausted` rather than spinning on a full subnet.
- **Domain membership is keyed by public key.** `clientAssignDomain` / `clientRemoveDomain` are key-addressable, deterministic cores (`clientAssignDomain(domain:publicKey:)` / `clientRemoveDomain(domain:publicKey:)`) enforcing `immutableClient` (server key), existence, and actual membership (`_domainContainsClient`) before mutating. The name-based overloads exist for interactive convenience and resolve name → key first (`_resolveClientPublicKey` requires the name to be registered *in the target domain* — correct for removal; the add path uses `_resolveClientPublicKeyAnywhere` because the client is by definition not yet a member). Names are only unique per-domain, so name-based resolution is ambiguous when identical names exist in different domains: prefer `--public-key` in scripts and on the MCP surface.
- **Invalidation drives revocation.** Two intervals from metadata: `noHandshakeInvalidationInterval` (until first handshake) and `handshakeInvalidationInterval` (reset on each handshake). `processHandshakes` advances the invalidation date on a newer handshake, or removes the client when `invalidationDate < now`.
- `clientRename` only touches the name DBs and must also re-hash the old/new `ClientNameHash` in the domain index.
- `domainMake` allocates the domain subnet at creation (`domainMake(name:subnet:)` returns the freshly-issued `SecurityKey`). `install` no longer takes a server domain name — it records the primary interface, server public addresses/port, and the server `serverIPBlock: Network` in the metadata db.

### Key databases (see `Databases` enum in `WGDB.swift`)
`wgdb_metadata_db`, `addrName_hostSubnet`, `pub_ip`/`ip_pub`, `pub_name`, `pub_createDate`, `domainHash_domainName`, `pub_domainNameHash`, `wgdb_clientPub_handshakeDate`, `wgdb_clientPub_endpointAddr`, `wgdb_clientPub_invalidDate`, `wgdb_domainHash_network`, `wgdb_networkV6_domainName` (the reverse index — note the stored property is `network_domainHash` but the DB name string says v6), `wgdb_domainHash_securityKey`, `wgdb_domainHash_clientPub`, `wgdb_domainHash_clientNameHash`, `wgdb_ip_domainHash`, `wgdb___webserve_clientPub_configData`.

## Daemon hardening (current work: `docs/security-verification.md`)

The installer writes a hardened unit: `User=wiremand` / `Group=wiremand`, `AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN` (fully dropped to the single capability), `NoNewPrivileges=yes`, `PrivateTmp=yes`, plus a fixed umask. `docs/security-verification.md` is the runbook for verifying this on a live host:

1. **static** — `systemctl cat` unit matches the installer string; `systemd-analyze verify`; `systemd-analyze security` exposure score (record it, treat regressions as failures).
2. **runtime** — `/proc/<pid>/status` shows `CapEff`/`CapAmb` = `0x1000`, `CapBnd` = `0x1000`, `NoNewPrivs: 1`; a child `wg` process retains `CapEff 0x1000` (exercises the file-cap/ambient interplay under `NoNewPrivileges`).
3. **functional smoke** — firewall render + first handshake poll in the journal, throwaway client create/revoke, `/var/lib/wiremand/hosts-auto` regeneration.

Do **not** chase a near-zero exposure score by enabling `SystemCallFilter` / `MemoryDenyWriteExecute` / `ProtectSystem` — the daemon spawns `wg`/`ip`/`wg-quick`/sh children and mmaps LMDB; those switches break the runtime. Residual exposure is a deliberate, documented decision (the doc says exactly this).

## Conventions

- **Tabs for indentation** (do not reformat to spaces).
- **Dual-stack throughout**: IPv4 (`/24`) and IPv6 (`/64`). Every domain, client config, firewall chain, and DNS entry handles both. `Network.isV4` / `Address.isV4` switches are the norm. Preserve this.
- **`EncodedString`** is the opaque UTF-8 DB key/value type (via `@RAW_convertible_string_type<UTF8>`), not `Swift.String`. You generally convert with `String(x)` for display and wrap input with `EncodedString(...)`. Domain/client names passed to the DB must be `EncodedString`. `EncodedTimeInterval` / `EncodedUInt16` follow the same pattern for their types.
- **Logging** uses swift-log `Logger`; every file makes its own logger and sets `logLevel`. `#if DEBUG` toggles trace vs info/error levels. Use metadata dictionaries, not string interpolation in the message body where practical (the codebase is inconsistent here, match the surrounding file).
- **Errors** are nested `enum Error: Swift.Error` per type. Custom structs are `Sendable`. Raw pointer / `SystemPackage.FileDescriptor` work is common in `Execute/` and `Crtnetlink`; free `malloc`/`strcpy`/`mkstemp` buffers with `defer`.
- **Force unwraps** are used liberally (`.first!`, `try!`-style patterns) throughout the existing code, especially after `guard`/validation. Prefer keeping new code safer, but match local style when editing an existing function.
- **Shell-out via SwiftSlash** with `sudo`. The installer grants the `wiremand` user NOPASSWD sudo for `wg`, `wg-quick`, `certbot`, `systemctl reload`, and `/opt/wiremand`. Sensitive material (PSKs) is written to a `mkstemp` file and passed by path rather than on the command line.

## Testing

Framework: **Swift Testing** (`import Testing`, `@Suite`, `@Test`, `#expect`).

**Current state: the test target does not compile against `vX-dev`.** `Tests/wiremandTests/wiremandTests.swift` calls `WireguardDatabase.install(...)` with a stale signature (`wg_serverPublicDomainName:`, separate `serverIPv6Block:`/`serverIPv4Block:`, `serverIPv6BlockName:`) — the live `install(...)` takes `wg_primaryInterfaceName:`, `wg_resolvedServerPublicIPv4:`, `wg_resolvedServerPublicIPv6:`, `wg_serverPublicListenPort:`, `serverIPBlock: Network`, `serverBlockName:`, `publicKey:`, `defaultDomainMask:`. The test target should not be treated as a live contract until fixed. Netlink tests shell out to `ip` on the host (Linux-only). Treat green tests as an explicit goal, not the baseline.

There is currently **no unit coverage** for the LMDB state machine (`WGDB`), the handshake processing logic, or the firewall command builders, despite those being the highest-risk code. Adding focused tests for `processHandshakes`, `clientAssignDomain`/`clientRemoveDomain`, `domainMake`/`domainRemove`, and `FirewallExecutor.create*` command emission would be high-value work.

## Pitfalls & gotchas

- **Dependency drift**: upstream packages are pinned by branch (`bedrock` = `compare_amend`, `QuickLMDB` = `master`) and SwiftSlash/rawdog by version range. Builds can drift when those branches move. `Package.resolved` is checked in; re-resolve deliberately.
- **Domain names are lowercased at creation** (`domainName.lowercased()` in `Domain.make`). Lookups that don't lowercase the same way will miss.
- **`client add-domain` / `remove-domain` identify by name OR by `--public-key`.** The name-based path resolves by global name and is ambiguous if two clients in different domains share a name; `--public-key` is the deterministic form and takes precedence when both are supplied.
- **`Database.DupSort` has NO value-scoped `containsEntry(key:value:tx:)`** — only the base `Database` and `Strict` wrappers expose it. For dup-sort membership checks use a cursor: `db.cursor(tx:) { $0.makeDupIterator(key:) }`, or the cursor's own `containsEntry(key:value:)`.
- **One read-only LMDB transaction per thread.** LMDB grants a single reader slot per thread; opening a second read `Transaction` while one is still alive throws `LMDBError.badReaderSlot`. Share one transaction across lookups (see `clientAssignDomain(domain:name:)`), never nest read-only transactions.
- **`import MCP` in a CLI/ArgumentParser file is ambiguous.** MCP exports `Option`/`OptionGroup`/`Argument`/`Flag` property wrappers, so `@Option` becomes ambiguous with ArgumentParser. Import just what you need: `import struct MCP.ServerAddress` (as `Daemon.swift` does).
- **`GlobalCLIOptions` must be qualified (`CLI.GlobalCLIOptions`)** in subcommands declared directly in `extension CLI.*` (same rule as `IPStack`); bare resolution only works inside `struct Client`-nested subcommands.
- **`defaultDomainMask` metadata is a single `UInt8`** shared for v4/v6. There is an explicit `TODO` that it should be split into two values. Any new subnet-mask logic should be aware of this simplification.
- **CLI firewall/domain commands assume the base nft tables exist.** `reloadDomainIsolation` / `reloadWhitelist` add rules into `ip_filter`/`ip6_filter`, which are only created by the daemon's `FirewallService.render` (or equivalent `nft` skeletons). With the daemon stopped (e.g. during CLI-only maintenance), these fail with `return_code=-1`/"unable to run commands from buffer". The failure is post-commit, so the DB mutation still lands.
- **HandshakeChecker uses tab (ASCII 9) splitting**, and `wg show ... endpoints` output formats IPv6 as `[addr]:port` while IPv4 is bare `addr:port`. The parser branches on `[`/`.` heuristics; keep that intact if you touch endpoint parsing.
- **The firewall forward chain policy is `drop`.** Whitelist and domain-isolation chains must `accept`; a rule that ends in `drop` locks out the domain. Domain isolation only accepts traffic *within the same domain*, so inter-domain traffic is blocked by design.
- **Two separate db "domains" exist** (same word, unrelated concepts): logical VPN *domains* (`WGDB`) vs. firewall *networks* (`FirewallDB`). Don't conflate them.
- **Firewall tracing**: the `forward` chain jumps a `domain_trace` chain (before `whitelist`/`domain_isolation`) that sets `meta nftrace set 1` on same-domain `saddr`+`daddr` traffic, so inter-client traffic within a domain is visible via `nft monitor trace` with the full rule walk.
- **Incremental firewall sync**: the whitelist, domain_isolation, and domain_trace chains are reconciled incrementally (`FirewallSync.sync`) against a persisted per-chain rule mirror in `FirewallDatabase.chainRuleMirror`. Unchanged chains are no-ops; additions emit only `add rule` for the new rules; removals fall back to a scoped flush+re-render of just that chain. Handles are deliberately NOT cached (kernel-assigned, reassigned on flush, and `nft list` renders live counter counts that break text matching), so additions need no handle and removals re-render the chain. Boot (`FirewallService.render`) uses `force: true` to guarantee a clean slate.
- The webserver binds with a **self-signed cert** at `/etc/wiremand/ssl/{fullchain,privkey}.pem`; clients use `-k`. Port 8080 for the HTTP API, 29300 default for WireGuard.
- DB envs are created with `.noSubDir` and a map size of current-file-size + 16 GB. LMDB transactions must be explicitly committed; every mutation path opens `Transaction(env:, readOnly: false)`, does work, then `commit()`.

## CLI reference (high level)

`install`, `update` (root), `run` (daemon), `reset-public-addresses`, `domain make|remove|list [--api-keys]`, `client make|list [--domain] [--windows-legacy]|rename|revoke|punt|add-domain [--public-key]|remove-domain [--public-key]|mcp-access [--grant|--revoke]`, `firewall add-rule|delete-rules|list [--name]`, `ipstack set-api-key|get-api-key`. Several commands prompt interactively when `--domain`/`--name` are omitted (see `Client.DomainNameGroup.promptInteractivelyIfNecessary`).

---

## Windows PowerShell Scripts (`scripts/`)

The `scripts/` directory contains three PowerShell scripts for enterprise WireGuard deployment on Windows Server 2022 and Windows clients, plus a comprehensive test battery:

| Script | Purpose |
|--------|---------|
| `Install-WireGuardTunnel.ps1` | Headless tunnel service deployment (no GUI dependency) |
| `Install-WireGuardManagedClient.ps1` | Managed client with locked config via Manager Service |
| `Invoke-WireGuardEnvironmentReset.ps1` | Full environment reset with two-tier filesystem scan |
| `test_battery_lethal.ps1` | 43-test lethal battery covering all three scripts |
| `TEST_RESULTS.md` | Test results summary with bug tracker |
| `README.md` | Full documentation for all scripts |

**Key design decisions:**
- All scripts are **dry by default**; pass `-NoDry` to execute
- Server script uses `wg genkey` for key generation (no GUI dependency)
- Client script sets `LimitedOperatorUI` registry key for locked configs
- Config files are ACL-restricted to `BUILTIN\Administrators` and `SYSTEM` only
- A file-based deployment lock (`%TEMP%\WireGuardTunnelLocks\deploy.lock`) prevents concurrent script instances from racing
- MSI download retries up to 3 times with partial-download cleanup
- `wireguard /installtunnelservice` exit code is verified; non-zero exits throw

**Test results (Phase 1):** 95/96 assertions PASS across 29 test groups covering input validation, IPv6, dual-stack, DNS, peer configs, client config generation, force reinstall, firewall cleanup, dry-run, service restart, duplicate rejection, port conflict, port 0, long names, unicode names, ACL verification, and lock file mechanism.

**Known non-issues:**
- Client config DNS is omitted when the source peer config has no DNS servers (correct behavior)
- Config encryption via DPAPI requires an interactive desktop session (plaintext `.conf` is functional)
- Network connectivity verification (ping through tunnel) requires a second VM
