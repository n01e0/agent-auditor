# hostd secret access PoC: local runbook

This runbook covers the current `agent-auditor-hostd` secret-access PoC as it exists after P4-7.

## What this PoC currently proves

The current secret-access PoC is intentionally narrow:

- `agent-auditor-hostd` can assemble a classify / evaluate / record pipeline for secret access without attaching live kernel hooks or broker integrations yet
- secret taxonomy can distinguish:
  - `secret_file`
  - `mounted_secret`
  - `brokered_secret_request`
- the current classifier can recognize:
  - `.ssh` material
  - `.env` / `.env.*` files
  - mounted secrets under `/run/secrets` and `/var/run/secrets`
  - Kubernetes service-account secret mounts
  - broker-adapter requests with redaction-safe locator hints
- classified secret access can be normalized into `agenta-core::EventEnvelope` values with `event_type=secret_access`
- `agenta-policy` can evaluate normalized secret events against the checked-in Rego example and return `allow` / `deny` / `require_approval`
- `require_approval` can derive a pending `ApprovalRequest`
- the bootstrap preview can persist minimal secret audit records and approval requests to local JSONL files
- the end-to-end preview path is covered by unit tests, policy tests, the broad hostd smoke test, and a dedicated secret smoke test

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today because the PoC still uses deterministic preview records instead of live fanotify attachment or broker RPC interception.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these secret-oriented categories of lines:

- `secret_classify=...`
- `secret_evaluate=...`
- `secret_record=...`
- `event_log_secret_allow=...`
- `normalized_secret_allow_observed=...`
- `normalized_secret_allow=...`
- `secret_policy_decision_allow=...`
- `secret_approval_request_allow=...`
- `event_log_secret_require_approval=...`
- `normalized_secret_require_approval_observed=...`
- `normalized_secret_require_approval=...`
- `secret_policy_decision_require_approval=...`
- `secret_approval_request_require_approval=...`
- `event_log_secret_deny=...`
- `normalized_secret_deny_observed=...`
- `normalized_secret_deny=...`
- `secret_policy_decision_deny=...`
- `secret_approval_request_deny=...`
- `persisted_secret_audit_record_allow=...`
- `persisted_secret_audit_record_require_approval=...`
- `persisted_secret_approval_request=...`
- `persisted_secret_audit_record_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
secret_classify=sources=fanotify,broker_adapter input_fields=source_kind,operation,path,mount_id,secret_locator_hint,broker_id,broker_action taxonomy=secret_file,mounted_secret,brokered_secret_request stages=ingest->taxonomy->label->handoff
secret_evaluate=sources=fanotify,broker_adapter classification_fields=source_kind,operation,taxonomy_kind,taxonomy_variant,locator_hint,classifier_labels,classifier_reasons,plaintext_retained stages=normalize->policy->approval_projection
secret_record=sources=fanotify,broker_adapter record_fields=normalized_event,policy_decision,approval_request,redaction_status stages=persist->publish sinks=structured_log,audit_store,approval_store
event_log_secret_allow=event=secret.access source=fanotify operation=read taxonomy_kind=secret_file taxonomy_variant=env_file locator_hint=/workspace/.env.production plaintext_retained=false
normalized_secret_allow_observed={...}
normalized_secret_allow={...}
secret_policy_decision_allow={...}
secret_approval_request_allow=null
event_log_secret_require_approval=event=secret.access source=broker_adapter operation=fetch taxonomy_kind=brokered_secret_request taxonomy_variant=secret_reference locator_hint=kv/prod/db/password plaintext_retained=false
normalized_secret_require_approval_observed={...}
normalized_secret_require_approval={...}
secret_policy_decision_require_approval={...}
secret_approval_request_require_approval={...}
event_log_secret_deny=event=secret.access source=fanotify operation=read taxonomy_kind=mounted_secret taxonomy_variant=kubernetes_service_account locator_hint=/var/run/secrets/kubernetes.io/serviceaccount/token plaintext_retained=false
normalized_secret_deny_observed={...}
normalized_secret_deny={...}
secret_policy_decision_deny={...}
secret_approval_request_deny=null
persisted_secret_audit_record_allow={...}
persisted_secret_audit_record_require_approval={...}
persisted_secret_approval_request={...}
persisted_secret_audit_record_deny={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run only the dedicated secret smoke test

```bash
cargo test -p agent-auditor-hostd --test secret_poc_smoke
```

### Run the broader hostd smoke test

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

## Where the current secret-access PoC behavior lives

- secret-access module boundary:
  - `docs/architecture/hostd-secret-access-poc.md`
- classify / evaluate / record scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/secret/`
- policy input + Rego evaluation helpers:
  - `crates/agenta-policy/src/lib.rs`
- example secret policy:
  - `examples/policies/secret_access.rego`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated secret smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-secret-smoke-fixtures.json`
- dedicated secret smoke test:
  - `cmd/agent-auditor-hostd/tests/secret_poc_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes secret PoC records under:

```text
target/agent-auditor-hostd-secret-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the secret PoC store is bootstrapped.

## Known constraints

See [`../architecture/hostd-secret-access-known-constraints.md`](../architecture/hostd-secret-access-known-constraints.md) for the explicit limitations that still apply to this path.

## When this runbook should change

Update this document when any of the following happens:

- hostd starts consuming live fanotify secret-path events instead of deterministic preview records
- brokered secret requests come from a real adapter integration instead of the current preview input
- secret taxonomy expands beyond the current `.ssh` / `.env` / mounted-secret / brokered-request heuristics
- the checked-in Rego example stops being the default preview policy path
- persisted secret approval / audit records move away from the current bootstrap JSONL store
- local execution begins requiring elevated privileges or extra host or broker setup
