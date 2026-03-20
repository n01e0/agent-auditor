# hostd enforcement foundation: local runbook

This runbook covers the current `agent-auditor-hostd` enforcement preview path after the P5 foundation slice.

It is the cross-cutting runbook for the shared enforcement seam that now sits between:

- normalized filesystem access preview events
- normalized `process.exec` preview events
- policy output (`allow` / `require_approval` / `deny`)
- reflected event / approval / audit records

## What this preview currently proves

The current enforcement path is intentionally narrow:

- `agent-auditor-hostd` can route exact policy output into explicit enforcement directives through the shared `decision -> hold / deny -> audit` seam
- filesystem preview inputs can model:
  - sensitive read -> `require_approval` -> `hold`
  - sensitive write -> `deny`
  - non-sensitive read -> `allow`
- process preview inputs can model:
  - `ssh` exec -> `require_approval` -> `hold`
  - `rm` exec -> `deny`
  - `cargo`-like exec -> `allow`
- the realized preview outcome can be reflected back into:
  - normalized `agenta-core::EventEnvelope`
  - pending `ApprovalRequest`
  - local PoC audit records
- dedicated unit tests and focused smoke tests keep the filesystem/process enforcement preview stable in CI

This is still a **preview-only** enforcement path. It does **not** prove that the host can actually pause or block those actions on a live system.

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today because the enforcement preview operates on normalized PoC records rather than live pre-access / pre-exec interception.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes shared enforcement planning lines:

- `enforcement_decision=...`
- `enforcement_hold=...`
- `enforcement_deny=...`
- `enforcement_audit=...`

Expected preview output also includes filesystem enforcement lines:

- `filesystem_enforcement=...`
- `filesystem_enforcement_allow=...`
- `filesystem_enforcement_deny=...`

And process enforcement lines:

- `process_enforcement_allow=...`
- `process_enforcement_hold=...`
- `process_enforcement_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
enforcement_decision=scopes=filesystem,process input_fields=normalized_event,policy_decision,approval_request,coverage_context,enforcement_capability stages=accept->route->handoff directive_fields=directive,coverage_gap,status_reason,audit_context
enforcement_hold=scopes=filesystem,process directive_fields=directive,coverage_gap,status_reason,audit_context stages=queue->await_decision->release_or_expire directives=hold
enforcement_deny=scopes=filesystem,process directive_fields=directive,coverage_gap,status_reason,audit_context stages=attempt_block->report_outcome directives=deny
enforcement_audit=scopes=filesystem,process record_fields=normalized_event,policy_decision,approval_request,directive,enforcement_status,status_reason,coverage_gap stages=append->publish sinks=structured_log,audit_store,approval_store statuses=allowed,held,denied,observe_only_fallback
filesystem_enforcement={...}
filesystem_enforcement_allow={...}
filesystem_enforcement_deny={...}
process_enforcement_allow={...}
process_enforcement_hold={...}
process_enforcement_deny={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run only enforcement-focused smoke tests

```bash
cargo test -p agent-auditor-hostd --test filesystem_enforcement_smoke
cargo test -p agent-auditor-hostd --test process_enforcement_smoke
```

### Run only the enforcement foundation unit tests

```bash
cargo test -p agent-auditor-hostd poc::enforcement:: --lib
```

### Run only the shared bootstrap smoke test

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
```

## Where the current behavior lives

- shared enforcement seam:
  - `cmd/agent-auditor-hostd/src/poc/enforcement/`
- filesystem preview wiring:
  - `cmd/agent-auditor-hostd/src/poc/filesystem/`
  - `examples/policies/sensitive_fs.rego`
- process preview wiring:
  - `cmd/agent-auditor-hostd/src/poc/event_path.rs`
  - `examples/policies/process_exec.rego`
- enforcement reflection helpers:
  - `crates/agenta-policy/src/lib.rs`
  - `crates/agenta-core/src/lib.rs`
- bootstrap preview output:
  - `cmd/agent-auditor-hostd/src/main.rs`
- focused smoke fixtures/tests:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-filesystem-enforcement-smoke-fixtures.json`
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-process-enforcement-smoke-fixtures.json`
  - `cmd/agent-auditor-hostd/tests/filesystem_enforcement_smoke.rs`
  - `cmd/agent-auditor-hostd/tests/process_enforcement_smoke.rs`

## How to interpret the output

The current preview records are useful for:

- checking that policy output is preserved through the enforcement seam
- checking that filesystem and process previews use the same directive vocabulary
- checking that hold outcomes carry approval ids / expiries into reflected records
- checking that deny outcomes do not invent approval records
- checking that audit-facing metadata is aligned before live runtime hooks land

They are **not** proof of:

- live fanotify hold semantics
- live pre-exec process blocking
- durable approval workflow execution
- fail-closed runtime behavior on a real host

## Known constraints

See [`../architecture/hostd-enforcement-known-constraints.md`](../architecture/hostd-enforcement-known-constraints.md) for the current cross-cutting enforcement limitations.

## When this runbook should change

Update this document when any of the following happens:

- filesystem preview routing becomes live fanotify enforcement
- process preview routing becomes live pre-exec blocking or pausing
- enforcement outcomes stop being preview metadata and become runtime-guaranteed state
- approval resolution can resume or reject held work for real
- the focused smoke fixtures stop being the primary CI proof for the enforcement seam
