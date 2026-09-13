# DEBT-FIX.md — wiremand: the SwiftSlash stdin-EOF situation and the pickup roadmap

Journal of everything learned about the SwiftSlash Linux stdin-EOF deadlock, what
wiremand already contains around it, and exactly what to do once SwiftSlash ships a
corrected release (target: **tag 5.0.1**).

This file is the single source of truth for resuming the work. If you are reading
this in a fresh session, start at [Roadmap](#roadmap-once-swiftslash-501-lands) and
work top to bottom; the [Verification playbook](#verification-playbook) at the bottom
is the exact battery that was run and must be re-run after the fix.

---

## 2026-09-13 — status: release in progress

SwiftSlash **5.0.1** is tagged locally at `c2912e7` (the data-driven write-loop fix,
verified **66/66 tests on macOS and linux** on the box at `/root/src/swift-slash-fix`;
master fast-forwarded). swift-mcp **1.1.0** is being cut from current head (the
fixture server and the raw-socket test helper needed small linux fixes: the C
`stderr` global under Swift 6, and glibc's `SOCK_STREAM` `__socket_type` typing).
wiremand `vX-dev` now pins SwiftSlash `5.0.1..<6.0.0` and swift-mcp `from:1.1.0`
(URL form restored), and `generateClient()` uses the native stdin data channel — the
execute layer is shell-free except the installer's `runShell`. Remaining before ship:
push SwiftSlash 5.0.1 + swift-mcp 1.1.0 + wiremand `vX-dev` (manual — passphrase-keyed
remotes), then the full box verification battery (roadmap steps 3-4) and deploy
(step 5). The roadmap below predates this note.

---

## 1. The problem in one paragraph

SwiftSlash (4.0.5 and 5.0.0 alike) cannot deliver a closing EOF on a child's stdin on
Linux. The stdin payload reaches the child, but the parent never closes the child's
stdin fd, so any child that blocks reading until EOF (`cat`, `sort`, `wg pubkey`, …)
hangs forever and `ChildProcess.run()` never returns — for **every** call-site
ordering of `yield()`, `closeDataChannel()`, and `run()` (verified, 4 patterns × 2
children, all rc=124). macOS is immune (kqueue `EVFILT_WRITE|EV_CLEAR` re-fires).

## 2. Root cause (complete)

The stdin *writer* fd is registered with the Linux event trigger using `EPOLLET`
(edge-triggered):

- `Sources/SwiftSlashEventTrigger/Platforms/LinuxEventTrigger.swift:234–242`
  (`newEvent.events = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET`)
- Identical in 4.0.5 and 5.0.0. Readers use EPOLLET too but are fine, because child
  output arriving is a *transition*; writes are the broken direction.

Edge-triggered epoll delivers an event only on a state transition, and it is
**one-shot**: a fresh, empty pipe is permanently writable, so `EPOLL_CTL_ADD` reports
readiness exactly once and then never again (kernel-verified: second poll = `[]`,
while level-triggered re-fires forever).

The stdin write task (`Sources/SwiftSlash/Logistics.swift:175–245`) only acts inside
an event wake: it blocks on the writer signal FIFO, and on the first (and only)
signal it flushes the queued payload — which is why the shipped piped-input tests
pass. The EOF path — seeing the finished user-data FIFO (`.capped`), breaking the
loop, and running the `defer { deregister; closeFileHandle }` that actually closes
the child's stdin — is only reachable on a **second** wake, which edge-triggering can
never deliver for an always-writable pipe. `closeDataChannel()` therefore only marks
the FIFO finished; the fd close is structurally unreachable on Linux.

macOS registers writers with `EVFILT_WRITE | EV_ADD | EV_CLEAR | EV_EOF`
(`MacOSETImpl.swift:244–245`) — level-triggered and re-issued after `EV_CLEAR`, so the
second signal arrives and EOF is delivered. Which is why a macOS-run test suite never
observes the bug.

**Why the shipped unit tests miss it:** every piped-input test child
(`SwiftSlashProcessTests.swift:141/170`) is `sh -c 'IFS= read … && exit …'` — it exits
after one line and never requires EOF; no test combines `closeDataChannel()` with an
EOF-consuming child. The full suite passes 47/47 on Linux while the bug is live.

Full report with all evidence: `~/workspace/SwiftSlash/LINUX_STDIN_EOF_DEADLOCK.md`
(exact code quotes, kernel checks, pattern matrix, macOS comparison, three fix
options, and a regression test that fails on Linux today).

## 3. What wiremand already contains (as of journaling)

`vX-dev` carries two commits related to this work (verified: full build green, 37/37
tests, live functional smoke on the box):

- **`8e2f0ba` — execute: eliminate `Command(sh:)` shell-outs via posix_spawn.**
  `WireguardExecute`, `SelfSignedCertExecutor` (openssl + chmod), `DNSmasq` (pkill),
  and `HandshakeChecker` (`LC_ALL=C`) now use `Command(absolutePath:arguments:)`.
  Exactly **one** documented `Command(sh:)` exception remains in the execute layer:
  `generateClient()`'s `wg pubkey` step, because of the SwiftSlash bug above. It writes
  the private key to a `mkstemp` file and runs `sh -c "cat '<path>' | /usr/bin/wg
  pubkey"` — the path is generated internally and quoted (no injection surface, no key
  material in argv), matching the codebase's existing PSK-by-path convention. The
  comment in the code documents the EPOLLET mechanism precisely.
- **`2e0a9ee` — fix: declare `Clibnftables` dependency on the wiremand target.**
  Pre-existing build break from the Aug 29 firewall-builder refactor (the executable
  kept `NFTablesExecutor.swift` importing `Clibnftables` without declaring the system
  library dependency; the module was silently dropped at plan time — the executable
  target had not built since that refactor). Fix verified on the box.

Branch state: `vX-dev`, clean tree, **not yet pushed** (Tanner's remotes use
passphrase-encrypted SSH keys — push must be a manual step). The stale August harden
branch is archived locally as `archive/harden-aug2026`.

Also committed but **not yet deployed**: the newly built debug binary is on the box at
`/root/src/wiremand/.build/debug/wiremand`; the live service still runs the old
`/opt/wiremand`.

## 4. Roadmap once SwiftSlash 5.0.1 lands

Tanner ships the SwiftSlash correction as **tag 5.0.1** (fix + regression test;
recommended fix: drop `EPOLLET` from the writer registration = Option A in the report).
When he returns, do these in order:

### Step 0 — verify 5.0.1 actually fixes it (framework gate, on the box)

Before touching wiremand, prove the framework fix on the Linux box:

```bash
ssh -i ~/.ssh/agentkey root@45.79.19.118
cd /tmp && rm -rf sl501 && git clone --depth 1 --branch 5.0.1 https://github.com/tannerdsilva/SwiftSlash.git sl501
cd sl501 && export PATH=/root/.local/share/swiftly/bin:$PATH && swift test       # expect 5.0.1's regression test (EOF-consuming child) to PASS
```

Confirm the new tag exists and the writer registration no longer uses `EPOLLET`
(`grep EPOLLET Sources/SwiftSlashEventTrigger/Platforms/LinuxEventTrigger.swift`).
Gate: tag exists **and** `swift test` green on this box — including the new
stdin-EOF test.

### Step 1 — update the SwiftSlash pin in wiremand

`Package.swift` currently: `.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", "4.0.5"..<"5.0.0")`.
Move to the fixed major: `.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", "5.0.1"..<"6.0.0")`.
Re-resolve deliberately (`swift package resolve`); expect API drift fixes since this
is also a major bump (v5 front-ends: BYO data channels, actor/`Sendable` tightening).
Call sites to audit for 5.0.1 compatibility: every `Command(absolutePath:)` /
`Command("wg", …)` / `ChildProcess` usage across `Execute/`, `Services/`, `CLI/`.

### Step 2 — replace the `wg pubkey` workaround with a native stdin path

Revert the `mkstemp + sh -c "cat … | wg pubkey"` exception in
`WireguardExecute.generateClient()` to the natural SwiftSlash pattern:

```swift
let proc = ChildProcess(Command(absolutePath: "/usr/bin/wg", arguments: ["pubkey"], environment: CurrentEnvironment.environmentVariables()))
try proc.stdin.yield([UInt8](privateKey.utf8))     // or write(); pick per 5.0.1 API
proc.stdin.closeDataChannel()
let exit = try await proc.run()
// collect stdout; expect .code(0) and one base64 line
```

Delete the workaround block (the `malloc/strcpy/mkstemp` dance + the shell call) and
its long EPOLLET comment. After this, the execute layer is **zero** `Command(sh:)`
— the only remaining shelled paths in the whole package are the installer's
`runShell` helper (deliberate: root-only interactive install, redirection/`&&`
chains that posix_spawn cannot express).

### Step 3 — full Linux verification battery

Run the [Verification playbook](#verification-playbook) below. The critical path is
the live smoke test, because `client make` exercises `wg pubkey` through the restored
native stdin path end to end.

### Step 4 — document cleanup

- Remove the now-obsolete "one shelled invocation" wording from the `8e2f0ba` commit
  message narrative (no need to rewrite history — note it in the new commit).
- **AGENTS.md**: add a Conventions line recording that the execute layer is
  shell-free except the installer's `runShell` (and, until 5.0.1, `wg pubkey`).
  AGENTS.md edits are approval-gated in this profile — surface the proposed line and
  get explicit confirmation before editing.
- Cross-reference: `docs/security-verification.md` is unaffected (no unit-string
  change here).

### Step 5 — deploy (only after Tanner's sign-off)

Build release on the box (`swift build -c release`), then `make install` or the
binary's own `install`/`update` (this restarts the service). The current live daemon
is an old binary; deploying this will bring the posix_spawn conversion and the
Clibnftables fix into production for the first time.

### Acceptance criteria

- [ ] 5.0.1 exists and its `swift test` (incl. the stdin-EOF regression test) passes on the box
- [ ] wiremand builds against the 5.0.1 pin; no `Command(sh:)` remains outside the installer
- [ ] 37/37 unit tests pass on the box
- [ ] Live smoke: throwaway `client make` + `client revoke` succeed via the native stdin path; `/etc/wireguard/wg2930.conf` md5 and `hosts-auto` return byte-identical to pre-test state
- [ ] AGENTS.md convention line added (with approval)
- [ ] `vX-dev` pushed (manual — passphrase keys)

## 5. Related open debt (explicitly NOT part of this fix — no scope creep)

- **HSTS** on the web API responses — holds a Hummingbird `HTTPHeaders`
  `.strictTransportSecurity` static that was never compile-verified; low value (self-signed
  cert, `-k` clients). Optional.
- **`SecurityKey` 512→32 bytes, `DomainHash` 8→16** — breaking on-disk LMDB schema
  change (DomainHash is a key type across ~8 dbs); needs a deliberate migration/fresh-
  install decision. Deferred.
- **API rate limiter** — the harden branch's `RateLimiter` was rejected (unbounded
  growth; `evictStale` never scheduled; weak value on an already key-gated endpoint).
  Any future effort needs a bounded/evicting design.
- **Deploy to production** — see Step 5.
- **Push** — manual, passphrase-keyed remotes.

## 6. Verification playbook (re-run after the fix)

All against `root@45.79.19.118` (agentkey at `~/.ssh/agentkey`), source at
`/root/src/wiremand` (rsync mirror, no git). Swift: `/root/.local/share/swiftly/bin`
(Swift 6.3.3). **Critical detail: rsync must use `--delete`** — the mirror is not a
git checkout and stale files from pre-refactor layouts (e.g. the old
`Execute/NFTables/FirewallExecute.swift`) silently accumulate and duplicate symbols
otherwise.

```bash
# sync
cd ~/workspace/wiremand && rsync -a --delete --exclude .build --exclude .git --exclude .DS_Store \
  -e "ssh -i ~/.ssh/agentkey" ./ root@45.79.19.118:/root/src/wiremand/

# build + test (on the box)
cd /root/src/wiremand && export PATH=/root/.local/share/swiftly/bin:$PATH
swift build            # expect: Build complete
swift test             # expect: 37 tests in 7 suites passed

# live smoke (on the box; the daemon keeps running the OLD /opt/wiremand — safe)
BIN=./.build/debug/wiremand; NAME="__smoke$(date +%s)"
timeout 60 $BIN client make --domain default --name "$NAME"     # exercises wg genkey + wg pubkey + wg set + wg-quick save + dnsmasq reload
wg show wg2930 peers                                             # expect the new peer present
grep "$NAME" /var/lib/wiremand/hosts-auto                       # expect a DNS line
timeout 60 $BIN client revoke --domain default --name "$NAME"   # exercises wg set … remove
wg show wg2930 peers                                             # expect empty again
md5sum /etc/wireguard/wg2930.conf                                # expect c022e14a41a753f9792b1ab472e5a521 (pre-test snapshot)
```

Pre-test baseline (recorded this session): interface `wg2930`, domain `default`
(v6 subnet `fd38:9187:48c:20c6::/64`), zero peers, `hosts-auto` empty, conf md5
`c022e14a41a753f9792b1ab472e5a521`.

## 7. Environment & key facts

- Box: `45.79.19.118` — Ubuntu 24.04, kernel `6.8.0-137-generic`, x86_64, Swift 6.3.3
  (swiftly), `libnftables-dev 1.0.9` installed, `pkill` at `/usr/bin/pkill`, `ip` at
  `/sbin/ip` (usrmerge symlinks) — all hardcoded posix_spawn paths in wiremand resolve.
- macOS can't build wiremand (Clibnftables system library fails on macOS) — the Linux
  box is the only real verification host.
- Build gotchas hit this session: stale `.build` descriptions (fix with a clean
  rebuild after manifest changes), the missing-`Clibnftables`-dependency manifest bug,
  and the rsync-without-`--delete` stale-file trap.
- SwiftSlash bug knowledge lives in two places: this file (short form) and
  `~/workspace/SwiftSlash/LINUX_STDIN_EOF_DEADLOCK.md` (full report — code quotes,
  evidence, fix options, regression test).
