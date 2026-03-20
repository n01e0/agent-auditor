# hostd API / network GWS PoC: local runbook

This runbook covers the current `agent-auditor-hostd` API / network Google Workspace semantic-action PoC after the first GWS slice.

## What this PoC currently proves

The current GWS path is intentionally narrow:

- `agent-auditor-hostd` can assemble a session_linkage / classify / evaluate / record pipeline for API- and network-shaped Google Workspace activity without attaching live browser or proxy instrumentation yet
- session linkage can bind API and network observations to the same `session_id` model used by the rest of the hostd preview path
- the classifier can recognize these semantic actions from redaction-safe request hints:
  - `drive.permissions.update`
  - `drive.files.get_media`
  - `gmail.users.messages.send`
  - `admin.reports.activities.list`
- classified GWS actions can be normalized into `agenta-core::EventEnvelope` values with `event_type=gws_action`
- `agenta-policy` can evaluate normalized GWS events against the checked-in preview policy and return `allow` / `require_approval`
- `require_approval` can derive a pending `ApprovalRequest`
- reflected GWS hold and deny outcomes can be attached to `agenta-core` event metadata plus local approval / audit records
- reflected GWS audit records and approval requests can be written to local JSONL files for inspection
- the preview path is covered by focused unit tests, policy tests, the broad hostd smoke test, a dedicated GWS fixture smoke test, and a dedicated GWS enforcement-consistency smoke test

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today because the PoC still uses deterministic preview observations instead of live API interception, browser instrumentation, or egress capture.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these GWS-oriented categories of lines:

- `gws_session_linkage=...`
- `gws_session_linked_api=...`
- `gws_session_linked_network=...`
- `gws_classify=...`
- `gws_classified_api=...`
- `gws_classified_network=...`
- `gws_evaluate=...`
- `gws_normalized_api=...`
- `gws_normalized_network=...`
- `gws_enriched_api=...`
- `gws_policy_decision_api=...`
- `gws_approval_request_api=...`
- `gws_enforcement_api=...`
- `gws_normalized_admin=...`
- `gws_enriched_admin=...`
- `gws_policy_decision_admin=...`
- `gws_approval_request_admin=...`
- `gws_normalized_deny=...`
- `gws_enriched_deny=...`
- `gws_policy_decision_deny=...`
- `gws_approval_request_deny=...`
- `gws_enforcement_deny=...`
- `persisted_gws_audit_record_require_approval=...`
- `persisted_gws_approval_request=...`
- `persisted_gws_audit_record_allow=...`
- `persisted_gws_audit_record_deny=...`
- `gws_record=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
gws_session_linkage=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin linkage_fields=source_kind,request_id,transport,authority_hint,method_hint,path_hint,destination_ip,destination_port,semantic_surface_hint,session_id,agent_id,workspace_id,linkage_reason stages=ingest->session_correlate->surface_hint->handoff
gws_classify=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin linkage_fields=source_kind,request_id,transport,authority_hint,method_hint,path_hint,destination_ip,destination_port,semantic_surface_hint,session_id,agent_id,workspace_id,linkage_reason classification_fields=semantic_surface,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained actions=drive.permissions.update,drive.files.get_media,gmail.users.messages.send,admin.reports.activities.list stages=service_map->taxonomy->label->handoff
gws_evaluate=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin linkage_fields=source_kind,request_id,transport,authority_hint,method_hint,path_hint,destination_ip,destination_port,semantic_surface_hint,session_id,agent_id,workspace_id,linkage_reason classification_fields=semantic_surface,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained stages=normalize->policy->approval_projection
gws_normalized_api={...}
gws_policy_decision_api={...}
gws_approval_request_api={...}
gws_enforcement_api={...}
gws_normalized_admin={...}
gws_policy_decision_admin={...}
gws_normalized_deny={...}
gws_policy_decision_deny={...}
gws_enforcement_deny={...}
persisted_gws_audit_record_require_approval={...}
persisted_gws_approval_request={...}
persisted_gws_audit_record_allow={...}
persisted_gws_audit_record_deny={...}
gws_record=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin record_fields=normalized_event,policy_decision,approval_request,redaction_status stages=persist->publish sinks=structured_log,audit_store,approval_store
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated GWS fixture smoke test

```bash
cargo test -p agent-auditor-hostd --test gws_poc_smoke
```

### Run the dedicated GWS enforcement smoke test

```bash
cargo test -p agent-auditor-hostd --test gws_enforcement_smoke
```

### Run the broader hostd smoke test

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
```

### Run only hostd GWS unit tests

```bash
cargo test -p agent-auditor-hostd poc::gws:: --lib
```

### Run only the approval-path unit tests

```bash
cargo test -p agent-auditor-hostd poc::gws::approval:: --lib
```

### Run only the policy crate tests

```bash
cargo test -p agenta-policy
```

## Where the current behavior lives

- GWS module boundary:
  - `docs/architecture/hostd-api-network-gws-poc.md`
- official method/resource/scope catalog:
  - `docs/architecture/hostd-api-network-gws-action-catalog.md`
- classify / evaluate / record scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/gws/`
- preview GWS policy:
  - `examples/policies/gws_action.rego`
- policy input and decision reflection helpers:
  - `crates/agenta-policy/src/lib.rs`
- normalized event and approval record types:
  - `crates/agenta-core/src/lib.rs`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated GWS smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-gws-smoke-fixtures.json`
- dedicated GWS fixture smoke test:
  - `cmd/agent-auditor-hostd/tests/gws_poc_smoke.rs`
- dedicated GWS enforcement smoke test:
  - `cmd/agent-auditor-hostd/tests/gws_enforcement_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes GWS PoC records under:

```text
target/agent-auditor-hostd-gws-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the GWS PoC store is bootstrapped.

## How to interpret the preview policy

The checked-in preview policy is intentionally narrow:

- `drive.permissions.update` -> `require_approval`
- `drive.files.get_media` -> `require_approval`
- `gmail.users.messages.send` -> `require_approval`
- `admin.reports.activities.list` -> `allow`

This is enough to prove the end-to-end event / policy / approval / audit path. It is **not** a complete Google Workspace governance policy.

## How to interpret fail-open / fail-closed today

Use this rule when reading the current bootstrap output:

- if you see `gws_enforcement_api={... directive:"hold" ...}` for `drive.permissions.update`, `drive.files.get_media`, or `gmail.users.messages.send`, read it as **"the preview path would like to hold this"**, not **"the live request was actually paused"**
- if you see `gws_enforcement_deny={... directive:"deny" ...}` for the synthetic Gmail-send example, read it as **reflected intended deny metadata**, not evidence that Gmail delivery was actually blocked
- `admin.reports.activities.list` stays observe-only in the checked-in posture, so there is currently no deny/hold claim to make for that action

In other words: the current GWS PoC can now reflect intended hold/deny outcomes into `agenta-core` events and local approval/audit records, but the live Google Workspace request path is still documented as fail-open until a validated intercept seam exists.

For the per-action matrix, see [`../architecture/hostd-api-network-gws-action-catalog.md`](../architecture/hostd-api-network-gws-action-catalog.md).

## What to validate before trusting the preview outputs

If you are changing this path locally, the quickest honest confidence check is:

1. run `cargo test -p agent-auditor-hostd poc::gws::approval:: --lib` to verify approval-path guards and posture gating
2. run `cargo test -p agent-auditor-hostd --test gws_enforcement_smoke` to verify hold / deny / observe-only outputs still agree across event, approval, enforcement, and persisted-record views
3. run `cargo test -p agent-auditor-hostd --test gws_poc_smoke` to verify the bootstrap preview output still matches the checked-in GWS fixture set

Passing these tests means the preview contract is internally consistent. It still does **not** prove inline interception on live Google Workspace traffic.

## Known constraints

See [`../architecture/hostd-api-network-gws-known-constraints.md`](../architecture/hostd-api-network-gws-known-constraints.md) for the explicit limitations that still apply to this path.

## When this runbook should change

Update this document when any of the following happens:

- session linkage starts consuming live API adapters, proxy traces, or real egress metadata instead of deterministic preview observations
- the semantic taxonomy expands beyond the current four checked-in GWS actions
- normalized `gws_action` events change shape in `agenta-core`
- the checked-in Rego example stops being the default preview policy path
- GWS audit or approval persistence moves away from the current bootstrap JSONL store
- local execution begins requiring elevated privileges or extra Google Workspace test setup
