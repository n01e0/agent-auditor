# hostd exec/exit PoC module boundary

This note fixes the first internal split for the `agent-auditor-hostd` PoC.

## Goal of P1-1

Keep the early exec / exit prototype honest about ownership before the real `aya` loader and event plumbing land.

The immediate rule is:

- **loader** owns eBPF object lifecycle and kernel hook attachment
- **event path** owns userspace receive / decode / correlate / normalize / publish flow
- the only shared seam is a small **loader boundary contract** that describes the raw event transport

## Code layout

`cmd/agent-auditor-hostd/src/poc/`

- `contract.rs`
  - shared seam between loader and event path
  - transport kind + raw event family list
- `loader.rs`
  - PoC-facing loader plan
  - future home for `aya` object loading and attach lifecycle
- `event_path.rs`
  - userspace pipeline plan after the loader handoff
  - future home for ring buffer / perf buffer consumption and normalization
- `mod.rs`
  - assembles the PoC plan and tests the split

## Responsibility split

### Loader

Owns:

- choosing and loading the eBPF artifact
- attaching the kernel hooks for exec / exit coverage
- managing low-level `aya` lifecycle
- exposing the raw transport boundary to userspace

Does **not** own:

- lifecycle correlation logic
- conversion into `agenta-core` envelopes
- sink / logging fanout

### Event path

Owns:

- receiving raw records from the loader handoff
- decoding kernel-facing structs into hostd-side records
- correlating exec / exit lifecycle state
- normalizing records toward `agenta-core`
- publishing to logs and later control-plane sinks

Current PoC milestone notes:

- P1-2 loads the embedded `aya` object without attaching it
- P1-3 decodes a deterministic exec payload into a userspace `process.exec` log line so the receive/decode/logging path stays testable in unprivileged CI
- P1-4 decodes a deterministic exit payload and uses `ProcessLifecycleKey { pid, ppid }` as the minimal exec/exit correlation shape
- P1-5 normalizes the deterministic exec / exit PoC payloads into temporary `agenta-core::EventEnvelope` records before any richer attribution work lands

Does **not** own:

- selecting or loading the eBPF object
- attaching kernel programs
- `aya` object lifecycle

## Why this split now

This keeps the next tasks cleaner:

- **P1-2** can implement a real `aya` loader without dragging event normalization into the same module
- **P1-3 / P1-4** can focus on transport delivery and lifecycle correlation inside the event path
- **P1-5** can plug normalization into the event path without changing the loader boundary

## Explicitly out of scope for P1-1

- actual eBPF bytecode loading
- real ring buffer or perf buffer reads
- full exec / exit schema definition
- `agenta-core` normalization implementation
