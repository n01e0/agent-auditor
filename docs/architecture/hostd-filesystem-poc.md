# hostd filesystem PoC module boundary

This note fixes the first internal split for the `agent-auditor-hostd` filesystem PoC.

## Goal of P2-1

Keep the early fanotify-backed filesystem prototype honest about ownership before real watch setup, path classification, and event normalization land.

The immediate rule is:

- **watch** owns fanotify lifecycle, marks, and raw access signal handoff
- **classify** owns sensitive-path matching and provisional read / write intent
- **emit** owns normalization and publish fanout toward logs and later control-plane sinks
- the shared seams are small **watch** and **classification** boundary contracts that describe what each downstream stage may rely on

## Code layout

`cmd/agent-auditor-hostd/src/poc/filesystem/`

- `contract.rs`
  - shared seams between watch → classify and classify → emit
  - fanotify collector label + handoff field lists
- `watch.rs`
  - PoC-facing fanotify watch plan
  - future home for `fanotify_init`, mark management, and raw event extraction
- `classify.rs`
  - path sensitivity and access-intent classification plan
  - future home for `.ssh` / `.env` / mounted secret heuristics
- `emit.rs`
  - normalization / publish plan after classification
  - future home for `agenta-core` event shaping and sink fanout
- `mod.rs`
  - assembles the filesystem PoC plan and tests the split

## Responsibility split

### Watch

Owns:

- initializing the fanotify instance
- managing fanotify marks for configured sensitive roots
- resolving raw access masks and path handles into watch-side records
- handing off raw filesystem access signals downstream without policy semantics

Does **not** own:

- sensitive-path heuristics
- translating access into `read` / `write` intent
- `agenta-core` normalization
- publish fanout to logs or control-plane sinks

### Classify

Owns:

- translating raw fanotify masks into provisional `read` / `write` intent
- matching accessed paths against hostd sensitive-path rules
- attaching tags and rationale for downstream policy evaluation
- handing off semantic filesystem access candidates downstream

Does **not** own:

- fanotify instance setup or mark lifecycle
- kernel-facing file descriptor / path extraction
- final event emission or transport to sinks

### Emit

Owns:

- normalizing classified filesystem access candidates toward `agenta-core`
- preserving classifier metadata for later policy / audit stages
- publishing structured records to logs and later control-plane sinks

Does **not** own:

- fanotify initialization
- sensitive-path matching logic
- deciding which paths are sensitive

## Why this split now

This keeps the next tasks cleaner:

- **P2-2** can implement sensitive-path classification without entangling fanotify setup or emit-side normalization
- **P2-3** can shape provisional filesystem access events toward `agenta-core` without owning fanotify concerns
- later policy / audit tasks can consume a stable classified-access seam instead of poking directly at raw fanotify details

## Explicitly out of scope for P2-1

- real `fanotify_init` or mark syscalls
- live filesystem event reads from the kernel
- concrete sensitive-path rules beyond documenting the future seam
- `agenta-core` filesystem event normalization
- policy evaluation, approval creation, or persistence wiring

## Related docs

- local runbook: [`../runbooks/hostd-filesystem-poc-local.md`](../runbooks/hostd-filesystem-poc-local.md)
- known constraints: [`hostd-filesystem-known-constraints.md`](hostd-filesystem-known-constraints.md)
