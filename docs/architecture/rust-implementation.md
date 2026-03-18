# Rust Implementation Direction

This document fixes the initial implementation bias for the project.

## Language choice

The implementation will be Rust-first.

Reasons:

- strong fit for long-running privileged daemons
- memory safety advantages in collector and control-plane code
- good ecosystem for async services and serialization
- viable eBPF support through `aya`
- strong type-driven modeling for policy inputs, audit events, and approval flows

## eBPF stack

Initial direction:

- eBPF programs built and loaded through `aya`
- user space collectors implemented in Rust
- event transport via ring buffer / perf buffer patterns supported by `aya`
- shared event definitions kept in Rust-first crates where practical

`aya` is the preferred initial choice because it keeps the toolchain Rust-native and avoids introducing a hard Go / C dependency just to iterate on kernel telemetry.

## Filesystem monitoring

Initial expectation:

- fanotify integration from Rust user space
- normalized filesystem events emitted into the same event pipeline as eBPF-derived events
- policy decisions made in the control plane or local enforcement path depending on latency requirements

## Control plane stack

Not fully fixed yet, but the project should assume a conventional Rust service stack such as:

- `tokio` for async runtime
- `axum` or equivalent for operator / ingest APIs
- `serde` for schema-backed types
- `sqlx` or equivalent if relational persistence is chosen

These are not yet hard commitments, but they align well with the current architecture.

## Suggested binary split

### `agent-auditor-hostd`

Responsibilities:

- load eBPF programs via `aya`
- subscribe to low-level process / network events
- integrate fanotify watchers
- perform local attribution enrichment
- enforce or hold actions where node-local gating is required
- buffer and forward normalized events

For the exec / exit PoC, the initial internal split is:

- `loader` owns eBPF artifact lifecycle, hook attachment, and raw transport handoff
- `event_path` owns userspace receive / decode / correlate / normalize / publish flow
- `contract` is the only shared seam between them

See [`hostd-exec-exit-poc.md`](hostd-exec-exit-poc.md) for the concrete P1-1 module boundary.

For the filesystem PoC, the initial internal split is:

- `watch` owns fanotify lifecycle, marks, and raw access handoff
- `classify` owns sensitive-path matching and provisional read / write intent
- `emit` owns normalization and publish fanout
- `contract` defines the watch → classify and classify → emit seams

See [`hostd-filesystem-poc.md`](hostd-filesystem-poc.md) for the concrete P2-1 module boundary.

For the network PoC, the initial internal split is:

- `observe` owns outbound-connect eBPF lifecycle and raw socket tuple handoff
- `classify` owns destination semantics plus the seam for lossy domain attribution
- `emit` owns normalization and publish fanout
- `contract` defines the observe → classify and classify → emit seams

See [`hostd-network-poc.md`](hostd-network-poc.md) for the concrete P3-1 module boundary.

### `agent-auditor-controld`

Responsibilities:

- policy evaluation orchestration
- approval request lifecycle
- audit ingest and integrity chaining
- operator API / UI backend
- alert routing

### `agent-auditor-cli`

Responsibilities:

- local diagnostics
- policy dry-run / evaluation helpers
- approval and session inspection commands

## Crate split guidance

A plausible near-term crate layout is:

- `agenta-core` — shared IDs, enums, schema-backed models
- `agenta-policy` — Rego input / output types and evaluation client
- `agenta-audit` — persistence and integrity helpers
- `agenta-linker` — session / container attribution logic
- `agenta-ebpf-types` — shared event structs for eBPF <-> userspace exchange
- `agenta-hostd` — host daemon
- `agenta-controld` — control plane

Exact names can still change, but the split should keep kernel-facing code isolated from policy and product logic.

## Implementation principles

1. Keep privileged host code as small as possible.
2. Treat coverage reporting as part of the product, not a debug-only feature.
3. Keep normalized event types stable even if low-level collection evolves.
4. Prefer explicit unsupported markers over implicit best-effort behavior.
5. Design for replayable local test fixtures from the start.

## Open questions

1. Which kernel hooks are realistic for pre-exec deny semantics in the first Rust + `aya` prototype?
2. How much policy evaluation must happen on-node versus centrally?
3. What is the best strategy for correlating DNS with outbound connections without overpromising precision?
4. Which persistence model is best for the first tamper-evident audit store?
