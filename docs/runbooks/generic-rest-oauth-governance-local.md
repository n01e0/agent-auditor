# generic REST / OAuth governance: local runbook

This runbook covers the current local workflow for the generic REST / OAuth governance slice after the contract, policy, record reflection, and smoke coverage landed.

## What this slice currently proves

The current generic REST path is intentionally narrow but concrete:

- `agenta-core` exposes a checked-in generic REST contract in `crates/agenta-core/src/rest.rs`
- the contract can represent `method`, `host`, `path_template`, `query_class`, `oauth_scope_labels`, `side_effect`, and `privilege_class` while preserving the shared `provider_id + action_key + target_hint` lineage
- `agenta-policy` can derive `input.generic_rest_action` from normalized event attributes and evaluate provider-neutral REST / OAuth policy rules
- `agent-auditor-hostd` can assemble a generic REST normalize / policy / record pipeline from deterministic preview events without re-running provider-specific taxonomy inside the generic layer
- `require_approval` generic REST decisions can derive a pending `ApprovalRequest`
- reflected generic REST `allow` / `hold` / `deny` outcomes can be attached to `agenta-core` events plus local audit / approval records
- reflected generic REST audit records and approval requests can be written to local JSONL files for inspection
- the slice is covered by focused unit tests plus a dedicated hostd smoke test for the generic REST bootstrap preview lines

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

This workflow does **not** require root today. The checked-in generic REST path still runs from deterministic preview events and docs-backed labels instead of live proxy mediation, browser relay capture, or runtime token verification.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these generic-REST-oriented categories of lines:

- `generic_rest_normalize=...`
- `generic_rest_policy=...`
- `generic_rest_record=...`
- `generic_rest_normalized_require_approval=...`
- `generic_rest_policy_decision_require_approval=...`
- `generic_rest_approval_request_require_approval=...`
- `generic_rest_enriched_require_approval=...`
- `generic_rest_normalized_allow=...`
- `generic_rest_policy_decision_allow=...`
- `generic_rest_enriched_allow=...`
- `generic_rest_normalized_deny=...`
- `generic_rest_policy_decision_deny=...`
- `generic_rest_enriched_deny=...`
- `persisted_generic_rest_audit_record_require_approval=...`
- `persisted_generic_rest_approval_request=...`
- `persisted_generic_rest_audit_record_allow=...`
- `persisted_generic_rest_audit_record_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
generic_rest_normalize=providers=gws,github upstream_contract=provider_id,action_key,target_hint upstream_metadata=method,canonical_resource,side_effect,oauth_scopes,privilege_class generic_fields=provider_id,action_key,target_hint,method,host,path_template,query_class,oauth_scope_labels,side_effect,privilege_class stages=provider_contract_join->rest_normalize->oauth_label->handoff
generic_rest_policy=providers=gws,github input_fields=provider_id,action_key,target_hint,method,host,path_template,query_class,oauth_scope_labels,side_effect,privilege_class decision_fields=normalized_event,policy_decision,approval_request,redaction_status stages=normalize->policy->approval_projection
generic_rest_record=providers=gws,github input_fields=normalized_event,policy_decision,approval_request,redaction_status record_fields=normalized_event,policy_decision,approval_request,redaction_status stages=persist->publish sinks=structured_log,audit_store,approval_store
generic_rest_normalized_require_approval={...}
generic_rest_policy_decision_require_approval={...}
generic_rest_approval_request_require_approval={...}
generic_rest_enriched_require_approval={...}
persisted_generic_rest_audit_record_require_approval={...}
persisted_generic_rest_approval_request={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated generic REST smoke test

```bash
cargo test -p agent-auditor-hostd --test generic_rest_governance_smoke
```

### Run only hostd generic REST unit tests

```bash
cargo test -p agent-auditor-hostd poc::rest:: --lib
```

### Run only the generic REST contract tests

```bash
cargo test -p agenta-core rest:: --lib
```

### Run only the generic REST policy tests

```bash
cargo test -p agenta-policy generic_rest --lib
```

### Run the broader upstream smoke tests that feed this slice

```bash
cargo test -p agent-auditor-hostd --test provider_abstraction_smoke
cargo test -p agent-auditor-hostd --test gws_poc_smoke
cargo test -p agent-auditor-hostd --test github_semantic_governance_smoke
```

## Where the current behavior lives

- generic REST phase boundary:
  - `docs/architecture/generic-rest-oauth-governance-foundation.md`
- generic REST contract types:
  - `crates/agenta-core/src/rest.rs`
- policy input derivation and generic REST Rego evaluation helpers:
  - `crates/agenta-policy/src/lib.rs`
- generic REST preview policy:
  - `examples/policies/generic_rest_action.rego`
- generic REST normalize / policy / record scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/rest/`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated generic REST smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-generic-rest-governance-smoke-fixtures.json`
- dedicated generic REST smoke test:
  - `cmd/agent-auditor-hostd/tests/generic_rest_governance_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes generic REST PoC records under:

```text
target/agent-auditor-hostd-generic-rest-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the generic REST PoC store is bootstrapped.

## How to interpret the preview policy

The checked-in preview policy is intentionally narrow:

- `GET` + `query_class=filter` + `privilege_class=admin_read` + Google audit-listing side effect -> `allow`
- `POST` + `query_class=action_arguments` + `privilege_class=outbound_send` + send-like side effect -> `require_approval`
- `PUT` + GitHub secret-write path + `privilege_class=admin_write` + `github.permission:secrets:write` -> `deny`

This is enough to prove the end-to-end generic REST event / policy / approval / audit path. It is **not** a complete cross-provider REST / OAuth governance policy.

## How to interpret fail-open / fail-closed today

Use this rule when reading the current bootstrap output:

- if you see `generic_rest_enriched_require_approval={... enforcement:{directive:"hold" ...}}`, read it as **"the preview path would like to hold this REST action"**, not **"a live provider request was actually paused"**
- if you see `generic_rest_enriched_deny={... enforcement:{directive:"deny" ...}}`, read it as reflected intended deny metadata, not evidence that a live provider request was actually blocked inline
- if you see `generic_rest_enriched_allow={...}`, read it as reflected allow metadata for the checked-in preview posture, not proof of a product-grade provider mediation path

In other words: the current generic REST slice can reflect intended allow / hold / deny outcomes into `agenta-core` events and local approval / audit records, but it does **not** yet prove inline interception of live REST traffic.

## What to validate before trusting the preview outputs

If you are changing this path locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-core rest:: --lib` to verify the generic REST contract types still parse and round-trip cleanly
2. run `cargo test -p agenta-policy generic_rest --lib` to verify `input.generic_rest_action` derivation and the checked-in preview Rego policy still agree on the preview actions
3. run `cargo test -p agent-auditor-hostd poc::rest:: --lib` to verify the generic REST normalize / record / persistence unit tests still agree on the preview contract
4. run `cargo test -p agent-auditor-hostd --test generic_rest_governance_smoke` to verify the bootstrap generic REST preview output still matches the checked-in fixture set

Passing these tests means the repository still agrees on the generic REST contract, policy input, record reflection, and bootstrap preview. It still does **not** prove live provider mediation.

## Known constraints

See [`../architecture/generic-rest-oauth-governance-known-constraints.md`](../architecture/generic-rest-oauth-governance-known-constraints.md) for the explicit limitations that still apply to this slice.

## When this runbook should change

Update this document when any of the following happens:

- live REST interception, proxy mediation, or browser-relay-backed generic REST inputs replace deterministic preview events
- the generic REST contract fields change in `agenta-core`
- the checked-in preview policy expands beyond the current allow / hold / deny example slice
- generic REST audit or approval persistence moves away from the current bootstrap JSONL store
- the smoke fixtures stop being the canonical bootstrap preview contract
- messaging / collaboration governance starts layering additional action families above the generic REST seam
