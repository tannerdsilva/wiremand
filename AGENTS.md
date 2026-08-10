# AGENTS.md

Guidance for autonomous agents working on the **wiremand** codebase.

## What this project is

Wiremand is a **Linux-only**, Swift 6 command-line tool and systemd daemon that manages the full lifecycle of a WireGuard VPN server: client provisioning and revocation, logical domain segmentation, per-client nftables whitelisting, dnsmasq DNS integration, automatic handshake-based revocation, and optional ipstack.com geolocation.

It is a root-managed system daemon. The `install` subcommand mutates the host (systemd units, `/etc/wireguard`, `/etc/dnsmasq.conf`, sudoers, sysctl, self-signed TLS). The `run` subcommand is the long-lived daemon process.

Platform: **Linux only**. It builds against `libnftables` and raw netlink; it does not build or run on macOS in its current form.

## Build environment (read this first)

1. **Local dependency path.** `Package.swift` pins `bedrock` to a **local path** `../bedrock` (the GitHub `tannerdsilva/bedrock` URL is present but commented out). SwiftPM resolution **fails** unless `bedrock` exists as a sibling checkout at `../bedrock`. Do not assume it is fetched automatically.
2. **System library.** `Clibnftables` is a Swift `systemLibrary` with `pkgConfig: "libnftables"` and the apt provider `libnftables-dev`. You must `apt-get install libnftables-dev` (and the `linux-headers` / netlink headers) before building. The daemon talks to nftables in-process via the C API, not by shelling out to the `nft` binary.
3. Because of (1) and (2), the package generally cannot be built inside a stock macOS or container environment. Verify the toolchain (`swift --version`, `pkg-config libnftables`) before promising a build.

```bash
# from the repo root (repo must be at .../<parent>/wiremand with bedrock at .../<parent>/bedrock)
swift build
swift test
```

## Repository layout

```
Sources/
  wiremand/                    # executable target: CLI + daemon + execute layer
    CLI/                       # Swift ArgumentParser subcommands
      MainProgram.swift        # entrypoint, subcommand registry, reset-public-addresses
      Installer.swift          # install + update (root, hidden)
      Daemon.swift             # `run` daemon: firewall bootstrap + ServiceGroup
      Domain.swift             # domain make/remove/list
      Client.swift             # client make/list/rename/revoke/punt/add-domain/remove-domain
      Firewall.swift           # firewall add-rule/delete-rules/list
      IPStack.swift            # ipstack get/set API key
      ArgumentExtensions.swift # Path:ExpressibleByArgument etc.
    Services/
      HandshakeChecker.swift   # 10s poll of `wg show`; updates DB, revokes, resolves IPs
      IPStacker.swift          # 10m geolocation resolution loop
      Webserver.swift          # Hummingbird HTTPS provisioning API (wg_makekey / wg_getkey)
    Execute/
      WireguardExecute.swift   # wg genkey/genpsk/pubkey, wg set peer, wg-quick save, ip addr
      NFTables/
        NFTablesExecutor.swift # in-process libnftables context wrapper
        FirewallExecute.swift  # builds nft tables/chains for whitelist + domain isolation
      DNSmasq.swift            # exports hosts-auto entries, reloads dnsmasq
      RTNetlink.swift          # Swift wrapper over Crtnetlink for addr/route/iface dumps
      SelfSignedCertExecutor.swift
  wiremand_databases/          # library target: all LMDB persistence
    WGDB/WGDB.swift            # core: WireguardDatabase, domain/client model, handshake engine
    WGDB/RandomAddress.swift   # random address allocation within a subnet
    FirewallDB/FirewallDB.swift# per-network nft rules
    IPDatabase/                # ipstack cache + ResolvedIPInfo
    Scheduler/                 # Scheduler (interval runner) + DateUTC
    Extensions/                # Date/String/URL/BedrockDate helpers
  Crtnetlink/                  # C module: raw netlink socket helpers (Ctrnetlink.c + include/)
Tests/wiremandTests/           # Swift Testing (@Suite/@Test)
```

## Architecture

The daemon (`wiremand run`) boots the firewall from a rules file + DB state, then runs three Swift ServiceLifecycle services under one `ServiceGroup` (graceful shutdown on SIGTERM/SIGINT):

| Service | Cadence | Responsibility |
|---------|---------|----------------|
| `HandshakeChecker` | 10 s | Runs `sudo wg show <iface> latest-handshakes` and `endpoints`, parses tab-separated output, feeds `WireguardDatabase.processHandshakes`, enqueues IP resolutions, uninstalls revoked peers. |
| `IPStacker` | 600 s | Pulls pending endpoint IPs from `IPDatabase`, calls ipstack.com, stores resolved geolocation or moves failures to a failed table. |
| `PublicHTTPWebServer` | n/a | Hummingbird 2 TLS server bound to both public IPv4 and IPv6. Serves the self-service provisioning API. |

All external effects go through the `Execute/` layer using the user's **SwiftSlash** library (`Command(sh: "...")` with `sudo`), or the in-process C bindings for nftables and netlink.

## Domain & client data model (the heart of the system)

The whole design is an LMDB key-value model in `WireguardDatabase`. Internal identifiers are **BLAKE2 hashes**, not strings: domain names become `DomainHash` (8 bytes), client names become `ClientNameHash` (16 bytes). Public keys are raw Curve25519 `PublicKey` (32 bytes). `SecurityKey` is 512 random bytes issued per domain to gate the public make-key API.

Core invariants to preserve when editing `WGDB.swift`:

- **A client (public key) can belong to multiple domains.** `clientPub_ip` is a DupSort (key = pubkey, dup = address). Removing a client from its *only* domain revokes it entirely (`_clientRemove`); removing from one of several only detaches that domain's address/name entries.
- **The server's own key (`localhost`) is immutable.** All mutation paths guard `serverPublicKey != publicKey` and throw `WGDBError.immutableClient`.
- **Every cross-reference has a reverse index** (e.g. `clientPub_ip` ↔ `ip_clientPub`, `domainHash_network` ↔ `network_domainHash`, `domainHash_clientPub` ↔ `clientPub_domainHash`). When you add/delete a row, update both directions or the read paths (`allClients`, `domainRemove`) corrupt.
- **Address allocation is random** within a domain subnet and must not collide (`RandomAddress` + a `containsEntry` re-roll loop).
- **Invalidation drives revocation.** Two intervals from metadata: `noHandshakeInvalidationInterval` (until first handshake) and `handshakeInvalidationInterval` (reset on each handshake). `processHandshakes` advances the invalidation date on a newer handshake, or removes the client when `invalidationDate < now`.
- `clientRename` only touches the name DBs and must also re-hash the old/new `ClientNameHash` in the domain index.

### Key databases (see `Databases` enum in `WGDB.swift`)
`wgdb_metadata_db`, `addrName_hostSubnet`, `pub_ip`/`ip_pub`, `pub_name`, `pub_createDate`, `domainHash_domainName`, `pub_domainNameHash`, `wgdb_clientPub_handshakeDate`, `wgdb_clientPub_endpointAddr`, `wgdb_clientPub_invalidDate`, `wgdb_domainHash_network`, `wgdb_networkV6_domainName`, `wgdb_domainHash_securityKey`, `wgdb_domainHash_clientPub`, `wgdb_domainHash_clientNameHash`, `wgdb_ip_domainHash`, `wgdb___webserve_clientPub_configData`.

## Conventions

- **Tabs for indentation** (do not reformat to spaces).
- **Dual-stack throughout**: IPv4 (`/24`) and IPv6 (`/64`). Every domain, client config, firewall chain, and DNS entry handles both. `Network.isV4` / `Address.isV4` switches are the norm. Preserve this.
- **`EncodedString`** is the opaque UTF-8 DB key/value type (via `@RAW_convertible_string_type<UTF8>`), not `Swift.String`. You generally convert with `String(x)` for display and wrap input with `EncodedString(...)`. Domain/client names passed to the DB must be `EncodedString`.
- **Logging** uses swift-log `Logger`; every file makes its own logger and sets `logLevel`. `#if DEBUG` toggles trace vs info/error levels. Use metadata dictionaries, not string interpolation in the message body where practical (the codebase is inconsistent here, match the surrounding file).
- **Errors** are nested `enum Error: Swift.Error` per type. Custom structs are `Sendable`. Raw pointer / `SystemPackage.FileDescriptor` work is common in `Execute/` and `Crtnetlink`; free `malloc`/`strcpy`/`mkstemp` buffers with `defer`.
- **Force unwraps** are used liberally (`.first!`, `try!`-style patterns) throughout the existing code, especially after `guard`/validation. Prefer keeping new code safer, but match local style when editing an existing function.
- **Shell-out via SwiftSlash** with `sudo`. The installer grants the `wiremand` user NOPASSWD sudo for `wg`, `wg-quick`, `certbot`, `systemctl reload`, and `/opt/wiremand`. Sensitive material (PSKs) is written to a `mkstemp` file and passed by path rather than on the command line.

## Testing

Framework: **Swift Testing** (`import Testing`, `@Suite`, `@Test`, `#expect`).

**Current state: the test target does not compile against `vX-dev`.** `Tests/wiremandTests/wiremandTests.swift` calls a `WireguardDatabase.install(...)` signature (`wg_serverPublicDomainName`, `serverIPv6Block`, `serverIPv4Block`, etc.) that was removed/reworked in the current code. It is stale relative to the `vX-dev` branch and should not be treated as a live contract. Netlink tests shell out to `ip` on the host. Treat green tests as an explicit goal, not the baseline.

There is currently **no unit coverage** for the LMDB state machine (`WGDB`), the handshake processing logic, or the firewall command builders, despite those being the highest-risk code. Adding focused tests for `processHandshakes`, `clientAssignDomain`/`clientRemoveDomain`, `domainMake`/`domainRemove`, and `FirewallExecutor.create*` command emission would be high-value work.

## Pitfalls & gotchas

- **`../bedrock` local path**: resolution fails without a sibling checkout; the URL is commented out in `Package.swift`. Don't "fix" the missing dep by changing the path unless asked; it is the intended local-dev workflow.
- **Domain names are lowercased at creation** (`domainName.lowercased()` in `Domain.make`). Lookups that don't lowercase the same way will miss.
- **`defaultDomainMask` metadata is a single `UInt8`** shared for v4/v6. There is an explicit `TODO` that it should be split into two values. Any new subnet-mask logic should be aware of this simplification.
- **`HandshakeChecker` uses tab (ASCII 9) splitting**, and `wg show ... endpoints` output formats IPv6 as `[addr]:port` while IPv4 is bare `addr:port`. The parser branches on `[`/`.` heuristics; keep that intact if you touch endpoint parsing.
- **The firewall forward chain policy is `drop`.** Whitelist and domain-isolation chains must `accept`; a rule that ends in `drop` locks out the domain. Domain isolation only accepts traffic *within the same domain*, so inter-domain traffic is blocked by design.
- **Two separate db "domains" exist** (same word, unrelated concepts): logical VPN *domains* (`WGDB`) vs. firewall *networks* (`FirewallDB`). Don't conflate them.
- **Firewall tracing**: the `forward` chain jumps a `domain_trace` chain (before `whitelist`/`domain_isolation`) that sets `meta nftrace set 1` on same-domain `saddr`+`daddr` traffic, so inter-client traffic within a domain is visible via `nft monitor trace` with the full rule walk. `reloadDomainIsolation` flushes and rebuilds both `domain_isolation` and `domain_trace` from the live domain list.
- The webserver binds with a **self-signed cert** at `/etc/wiremand/ssl/{fullchain,privkey}.pem`; clients use `-k`. Port 8080 for the HTTP API, 29300 default for WireGuard.
- DB envs are created with `.noSubDir` and a map size of current-file-size + 16 GB. LMDB transactions must be explicitly committed; every mutation path opens `Transaction(env:, readOnly: false)`, does work, then `commit()`.

## CLI reference (high level)

`install`, `update` (hidden, root), `run` (hidden daemon), `reset-public-addresses`, `domain make|remove|list [--api-keys]`, `client make|list [--domain] [--windows-legacy]|rename|revoke|punt|add-domain|remove-domain`, `firewall add-rule|delete-rules|list [--name]`, `ipstack set-api-key|get-api-key`. Several commands prompt interactively when `--domain`/`--name` are omitted (see `Client.DomainNameGroup.promptInteractivelyIfNecessary`).