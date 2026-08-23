# wiremand security verification

Run on the Linux host where wiremand is installed. These checks must be
re-executed after any change to the installer's systemd unit string, and make
sense as a gate before/after any release. No single check is sufficient: static
analysis (systemd-analyze), runtime capability inspection, and a functional
smoke test each cover a different failure mode.

## 1. static: the unit on disk is the hardened one

```bash
systemctl cat wiremand.service
```

Confirm the on-disk unit matches what the installer writes:

- `User=wiremand` / `Group=wiremand`
- `AmbientCapabilities=CAP_NET_ADMIN`
- `CapabilityBoundingSet=CAP_NET_ADMIN`
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`

A stale binary or a hand-edited unit shows up here.

## 2. static: unit validity

```bash
systemd-analyze verify /etc/systemd/system/wiremand.service
```

Semantic load/validation of the property set. Any warning means a bad or
silently-ignored combination.

## 3. static: exposure score

```bash
systemd-analyze security wiremand.service
systemd-analyze security --json=pretty wiremand.service   # machine-readable
```

Exposure score: 0 = hardened, 10 = exposed, with a per-option table. Record the
score; it must not regress when the unit string or the installer changes. This
is the quantified baseline for deliberate hardening decisions.

## 4. runtime: the process holds what the unit promises

```bash
systemctl restart wiremand.service
systemctl status wiremand.service

WGPID=$(systemctl show -p MainPID --value wiremand.service)
grep -E 'Cap(Eff|Amb|Bnd)' /proc/$WGPID/status
grep 'NoNewPrivs' /proc/$WGPID/status

CHILD=$(pgrep -P $WGPID wg | head -1); grep Cap /proc/$CHILD/status   # if a wg child exists
```

Expectations:

- `CapEff` and `CapAmb` include `CAP_NET_ADMIN` (bit 12 = mask `0x1000`).
- `CapBnd` is exactly the same mask (`0x1000`) — the bounding set is fully
  dropped to just the one capability.
- `NoNewPrivs: 1`.
- A `wg` child spawned by the daemon retains the capability (`CapEff` `0x1000`).
  This exercises the file-cap/ambient interplay that `NoNewPrivileges=yes`
  must not break.

## 5. functional: the daemon still works

- journal shows the firewall render and a successful first handshake poll
  (`wg show <iface> latest-handshakes`) within ~10 s;
- creating and revoking a throwaway client succeeds and uninstalls the peer;
- `/var/lib/wiremand/hosts-auto` regenerates.

## deliberate residual exposure

Do NOT chase a near-zero exposure score by blindly enabling
`SystemCallFilter` / `MemoryDenyWriteExecute` / `ProtectSystem` — the daemon
spawns `wg` / `ip` / `wg-quick` / sh children and mmaps LMDB, and those switches
break the runtime that step 5 exercises. Residual exposure should be a
deliberate, documented decision, not an accident.

## background

The unit hardening relies on two Linux capability mechanisms that interact:

- `NoNewPrivileges=yes` blocks setuid-root UID transitions (full DAC override),
  which `CapabilityBoundingSet` alone cannot stop — the bounding set limits
  capabilities, not euid 0.
- The kernel preserves ambient capabilities across exec under `no_new_privs`;
  they are cleared only by file-cap'd or setuid/setgid targets. The daemon
  already holds `CAP_NET_ADMIN`, so exec'ing file-cap'd `wg` is not a "new"
  privilege and is not downgraded; `ip`, `wg-quick`, and sh have no file caps,
  so the ambient set flows to them unchanged.
