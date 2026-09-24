# CFP — Continuous Fabric Platform 1.0.1

One virtual platform over mobile, cloud and local compute, reached from every device through a
virtual WebSocket (`/vws`) and a virtual terminal. Pure Python 3.10+ standard library; no installs.

> Inherited rule: no item is operational because its source file exists. Status moves
> `STAGED → GATED_PASS/GATED_FAIL → OPERATIONAL` only on native executable evidence from `cfp gate`.

## Quick start (Windows, from this folder)

```
VENDOR.cmd          # copy all stockpiles into .\vendor (skips caches and _1/(1) duplicates) + verify hashes
START.cmd           # atlas + gateway on 127.0.0.1:8740; open the printed console URL
```

In the console: `help`, `nodes`, `layers`, `atoms continuous`, `run echo hi`, `ticket phone-1 mobile`.

**Phone on your LAN:** `python -m cfp up --host 0.0.0.0 --network lan`, then in the console run
`ticket phone-1 mobile` and open the join URL on the phone with your PC's LAN IP in place of 127.0.0.1.
**Cloud VM:** copy this folder there and run
`python -m cfp node --gateway <pc-ip>:8740 --ticket <ticket> --profile "{\"tier\":\"N_LARGE\",\"zone\":\"cloud\"}"`
(`--network wan` on the gateway; put it behind TLS/a tunnel before opening it to the internet).

## Layer map (from the synthesis blueprint)

| Layer | Stockpiles | Seam in CFP |
|---|---|---|
| clients | iOS735_LCTL, LinearAndroid_LCTL, browsers | `cfp/web/index.html` is a browser node agent (mobile-first) |
| session | hermit-ramws | `/vws` socket = session identity; byte credits + RAM ledger per session (`fabric.Session`) |
| unified | DF_Unified, DF_Unified_v1.0.0 | single door: gateway + atlas + promotion ledger |
| control | DF_Fabric, UC32 | `fabric.Fabric` placement, event log, replicated state hub |
| execution | DF_Small/Medium/Large/Xtra_Large, QVM | node tiers `N_SMALL..N_XLARGE` + dialects; jobs lower onto matching dialect, never ship images (F7) |
| continuous | gap01–15, inv02–72, pln01–07, sch01 | admission (GAP-06/13, INV-41/42), scheduling (GAP-02/03/10/11/14), continuity (GAP-04/05/12) |
| model | _model, BOTTLE_ROCKET 61K/110K, RODEO | refinement/reasoning tooling; VM packages behind the DF tiers |

## What each mechanism does

- **Admission** — HMAC-signed, single-use, 10-minute join tickets bind node id + class + capability grant.
  Forged, expired and replayed tickets are rejected. Only `local`-class nodes can issue tickets or run gates.
- **Policy** — deny-by-default: `--network deny` binds loopback only; verbs need capabilities
  (`mobile` has no `run.heavy`/`bulk`).
- **Scheduling** — score = tier − load − thermal penalty − phone-battery penalty + data-gravity bonus + zone affinity;
  hard filters for capability, minimum tier, sealed dialect and accelerator.
- **Continuity** — every node has a vector-clock replica; `offline` queues writes, `online`/`sync` converge (LWW by timestamp, node).
- **Promotion** — `python -m cfp gate <atom>` / `--all` runs the atom's own suite (Python unittest, `node --test`, or VERIFY),
  writes `ledger/evidence/<atom>.json`, and records status in `ledger/PLATFORM_LEDGER.json`.

## Non-claims

- The seams are CFP's own implementations shaped to each gap/inv contract; the vendored atoms' code is not yet
  imported into the hot path — wiring each one in is the promotion work, one atom at a time.
- Partition in the terminal is simulated (`offline`); a dropped browser session resets (RAMWS LOCAL_VOLATILE) and needs a new ticket.
- No physical QPU. No WAN hardening beyond ticketed admission — use TLS/a tunnel for internet exposure.


## Installation and validation

Python 3.10 or newer is required. No runtime dependencies are installed.

```sh
python -m pip install .
python -m unittest discover -s tests -v
python -m cfp --help
```

Runtime data is stored in the current directory, or the directory selected by
`CFP_HOME`. Use `cfp --root /path/to/stockpiles vendor` for an explicit stockpile
source. An installed wheel includes the browser console. The source distribution
also includes tests, launchers, and release documentation.

## Security and trust boundaries

This is a reference gateway for a trusted fabric, not a tenant isolation system.
All admitted nodes share the replicated state namespace and topology. Node
profiles are self-reported; a join ticket is a bearer credential, not hardware
attestation. Local-class tickets authorize administration and trusted code imports.
Only give local tickets to administrators. Gates and `probe` execute local vendor
code; review that code before vendoring or running it. Hash manifests detect changes
but are not publisher signatures. Do not expose this reference gateway directly
to the internet; terminate TLS with a trusted proxy and preserve Host and Origin.

Version 1.0.1 validates WebSocket framing and same-origin browser upgrades, limits
messages to 1 MiB including fragments, checks result ownership, removes disconnected
sessions, limits admission and job retention, and refuses raw client replica writes.
Unauthenticated HTTP metadata endpoints now return 403; use the ticketed terminal.
Tickets expire after ten minutes and are invalidated when the gateway restarts.
Idle joined sockets close after 120 seconds; the supplied agents send heartbeats.
Session byte credits are lifetime budgets and rejoining requires a fresh ticket.

See [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md), and the
[audit report](reports/AUDIT_1.0.1.md) for changes, checks, and remaining limitations.

## License

Copyright 2026 RUSSELL PHILIP SMITHSON.
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
