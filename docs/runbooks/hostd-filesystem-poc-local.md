# hostd filesystem PoC: local runbook

This runbook covers the current `agent-auditor-hostd` filesystem PoC as it exists after P2-7.

## What this PoC currently proves

The current filesystem PoC is intentionally narrow:

- `agent-auditor-hostd` can assemble a fanotify-shaped watch / classify / emit pipeline without attaching live kernel watchers yet
- sensitive path classification can tag provisional targets for:
  - `.ssh`
  - `.env` / `.env.*`
  - mounted secrets under `/run/secrets`, `/var/run/secrets`, and Kubernetes service-account paths
- classified filesystem access can be normalized into temporary `agenta-core::EventEnvelope` values
- `agenta-policy` can evaluate the normalized event against the checked-in Rego example and return `allow` / `require_approval` / `deny`
- the PoC can derive a pending approval request record from `require_approval`
- the bootstrap preview can route sensitive reads into an approval-hold outcome and sensitive writes into a deny outcome through the new enforcement foundation seam
- the normalized `agenta-core::EventEnvelope` plus persisted approval / audit records now carry the realized enforcement result in a shared `enforcement` field
- the binary bootstrap path can persist a minimal audit record and approval request record to local JSONL files
- the end-to-end preview path is covered by unit tests plus a fixture-backed smoke test

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today because the PoC still uses preview records instead of live `fanotify_init` / mark syscalls.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these categories of lines:

- `filesystem_watch=...`
- `filesystem_classify=...`
- `filesystem_emit=...`
- `event_log_filesystem=...`
- `normalized_filesystem=...`
- `filesystem_policy_decision=...`
- `filesystem_enforcement=...`
- `persisted_audit_record=...`
- `persisted_approval_request=...`

After P5-2, the smoke-oriented bootstrap preview also prints:

- a non-sensitive allow case:
  - `event_log_filesystem_allow=...`
  - `normalized_filesystem_allow=...`
  - `filesystem_policy_decision_allow=...`
  - `filesystem_enforcement_allow=...`
  - `filesystem_approval_request_allow=...`
- a sensitive deny case:
  - `event_log_filesystem_deny=...`
  - `normalized_filesystem_deny=...`
  - `filesystem_policy_decision_deny=...`
  - `filesystem_enforcement_deny=...`
  - `filesystem_approval_request_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
filesystem_watch=collector=fanotify marks=configured sensitive roots,mounted secret directories raw_fields=pid,fd_path,access_mask,mount_id raw_access_kinds=open,access,modify,close_write
filesystem_classify=collector=fanotify input_fields=pid,fd_path,access_mask,mount_id semantic_fields=path,access_verb,sensitivity_tags,classifier_reason verbs=read,write
filesystem_emit=collector=fanotify semantic_fields=path,access_verb,sensitivity_tags,classifier_reason stages=normalize->publish sinks=structured_log,control_plane
event_log_filesystem=event=filesystem.access collector=fanotify pid=4242 mount_id=17 verb=read target=/home/agent/.ssh/id_ed25519 sensitive=true tags=ssh reasons=path is inside a .ssh directory
normalized_filesystem={...}
filesystem_policy_decision={...}
filesystem_enforcement={...}
persisted_audit_record={...}
persisted_approval_request={...}
event_log_filesystem_allow=event=filesystem.access collector=fanotify pid=4343 mount_id=18 verb=read target=/workspace/src/main.rs sensitive=false tags= reasons=
normalized_filesystem_allow={...}
filesystem_policy_decision_allow={...}
filesystem_approval_request_allow=null
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run only the hostd smoke test

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
```

### Run only hostd unit tests

```bash
cargo test -p agent-auditor-hostd --lib
```

### Run only the policy crate tests

```bash
cargo test -p agenta-policy
```

## Where the current filesystem PoC behavior lives

- filesystem module boundary:
  - `docs/architecture/hostd-filesystem-poc.md`
- watch / classify / emit scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/filesystem/`
- policy input + Rego evaluation:
  - `crates/agenta-policy/src/lib.rs`
- example filesystem policy:
  - `examples/policies/sensitive_fs.rego`
- bootstrap preview output:
  - `cmd/agent-auditor-hostd/src/main.rs`
- checked-in smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-smoke-fixtures.json`
- integration smoke test:
  - `cmd/agent-auditor-hostd/tests/poc_smoke.rs`

## Local persistence path

The bootstrap preview currently writes PoC records under:

```text
target/agent-auditor-hostd-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the PoC store is bootstrapped.

## Known constraints

See [`../architecture/hostd-filesystem-known-constraints.md`](../architecture/hostd-filesystem-known-constraints.md) for the filesystem-specific limitations and [`hostd-enforcement-foundation-local.md`](hostd-enforcement-foundation-local.md) for the cross-cutting enforcement preview workflow shared with process events.

## When this runbook should change

Update this document when any of the following happens:

- hostd starts calling real `fanotify_init` / mark syscalls
- the sensitive-path matcher expands beyond the current `.ssh` / `.env` / mounted-secret heuristics
- the checked-in Rego example stops being the default preview policy path
- persisted approval / audit records move away from the current bootstrap JSONL store
- local execution begins requiring elevated privileges or extra kernel setup
