# messaging / collaboration governance: local runbook

This runbook covers the current local workflow for the messaging / collaboration governance slice after the first Slack / Discord taxonomy, `agenta-core` contract, policy path, record reflection, and smoke coverage landed.

## What this slice currently proves

The current messaging path is intentionally narrow but concrete:

- `agenta-core` exposes a checked-in provider-neutral messaging contract in `crates/agenta-core/src/messaging.rs`
- the contract can represent `action_family`, `channel_hint`, `conversation_hint`, `delivery_scope`, `membership_target_kind`, `permission_target_kind`, `file_target_kind`, and `attachment_count_hint` while preserving upstream provider and generic REST lineage
- `agent-auditor-hostd` can assemble a messaging taxonomy / policy / record pipeline from deterministic preview events without re-running provider-specific taxonomy inside the messaging layer
- the checked-in taxonomy can classify a minimal Slack / Discord sample into the shared collaboration families `message.send`, `channel.invite`, `permission.update`, and `file.upload`
- `agenta-policy` can derive `input.messaging_action` from normalized event attributes and evaluate the checked-in preview messaging policy
- `require_approval` messaging decisions can derive pending `ApprovalRequest` records
- reflected messaging `allow` / `hold` / `deny` outcomes can be attached to `agenta-core` events plus local audit / approval records
- reflected messaging audit records and approval requests can be written to local JSONL files for inspection
- the slice is covered by focused unit tests plus a dedicated hostd smoke test for the messaging bootstrap preview lines

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

This workflow does **not** require root today. The checked-in messaging path still runs from deterministic preview events and docs-backed permission labels instead of live Slack / Discord mediation, browser relay capture, webhook gateways, or runtime token verification.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these messaging-oriented categories of lines:

- `messaging_taxonomy=...`
- `messaging_policy=...`
- `messaging_record=...`
- `messaging_normalized_allow=...`
- `messaging_policy_decision_allow=...`
- `messaging_enriched_allow=...`
- `messaging_normalized_require_approval=...`
- `messaging_policy_decision_require_approval=...`
- `messaging_approval_request_require_approval=...`
- `messaging_enriched_require_approval=...`
- `messaging_normalized_deny=...`
- `messaging_policy_decision_deny=...`
- `messaging_enriched_deny=...`
- `messaging_normalized_file_upload=...`
- `messaging_policy_decision_file_upload=...`
- `messaging_approval_request_file_upload=...`
- `messaging_enriched_file_upload=...`
- `persisted_messaging_audit_record_allow=...`
- `persisted_messaging_audit_record_require_approval=...`
- `persisted_messaging_approval_request_require_approval=...`
- `persisted_messaging_audit_record_deny=...`
- `persisted_messaging_audit_record_file_upload=...`
- `persisted_messaging_approval_request_file_upload=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
messaging_taxonomy=providers=slack,discord surfaces=slack.chat,slack.conversations,slack.files,discord.channels,discord.threads,discord.permissions action_families=message.send,channel.invite,permission.update,file.upload ... stages=provider_join->family_inference->label->handoff
messaging_policy=providers=slack,discord action_families=message.send,channel.invite,permission.update,file.upload ... stages=normalize->policy->approval_projection
messaging_record=providers=slack,discord action_families=message.send,channel.invite,permission.update,file.upload ... stages=persist->publish sinks=structured_log,audit_store,approval_store
messaging_normalized_require_approval={...}
messaging_policy_decision_require_approval={...}
messaging_approval_request_require_approval={...}
messaging_enriched_require_approval={...}
persisted_messaging_audit_record_require_approval={...}
persisted_messaging_approval_request_require_approval={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated messaging smoke test

```bash
cargo test -p agent-auditor-hostd --test messaging_governance_smoke
```

### Run only hostd messaging unit tests

```bash
cargo test -p agent-auditor-hostd poc::messaging:: --lib
```

### Run only the messaging contract tests

```bash
cargo test -p agenta-core messaging:: --lib
```

### Run only the messaging policy tests

```bash
cargo test -p agenta-policy messaging_action --lib
```

### Run the broader upstream smoke tests that feed this slice

```bash
cargo test -p agent-auditor-hostd --test generic_rest_governance_smoke
cargo test -p agent-auditor-hostd --test provider_abstraction_smoke
```

## Where the current behavior lives

- messaging phase boundary:
  - `docs/architecture/messaging-collaboration-governance-foundation.md`
- messaging taxonomy catalog:
  - `docs/architecture/messaging-collaboration-action-catalog.md`
- messaging contract types:
  - `crates/agenta-core/src/messaging.rs`
- policy input derivation and messaging Rego evaluation helpers:
  - `crates/agenta-policy/src/lib.rs`
- messaging preview policy:
  - `examples/policies/messaging_action.rego`
- messaging taxonomy / policy / record scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/messaging/`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated messaging smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-messaging-governance-smoke-fixtures.json`
- dedicated messaging smoke test:
  - `cmd/agent-auditor-hostd/tests/messaging_governance_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes messaging PoC records under:

```text
target/agent-auditor-hostd-messaging-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the messaging PoC store is bootstrapped.

## How to interpret the preview policy

The checked-in preview policy is intentionally narrow:

- Slack `chat.post_message` into a public channel -> `allow`
- Discord thread member add -> `require_approval`
- Discord permission overwrite update -> `deny`
- Slack file upload -> `require_approval`

This is enough to prove the end-to-end messaging event / policy / approval / audit path. It is **not** a complete Slack / Discord governance model.

## How to interpret fail-open / fail-closed today

Use this rule when reading the current bootstrap output:

- if you see `messaging_enriched_require_approval={... enforcement:{directive:"hold" ...}}`, read it as **"the preview path would like to hold this messaging action"**, not **"a live Slack or Discord action was actually paused"**
- if you see `messaging_enriched_deny={... enforcement:{directive:"deny" ...}}`, read it as reflected intended deny metadata, not evidence that a live provider request was actually blocked inline
- if you see `messaging_enriched_allow={...}`, read it as reflected allow metadata for the checked-in preview posture, not proof of a product-grade messaging mediation path

In other words: the current messaging slice can reflect intended allow / hold / deny outcomes into `agenta-core` events and local approval / audit records, but it does **not** yet prove inline interception of live Slack or Discord traffic.

## What to validate before trusting the preview outputs

If you are changing this path locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-core messaging:: --lib` to verify the messaging contract types still parse and round-trip cleanly
2. run `cargo test -p agenta-policy messaging_action --lib` to verify `input.messaging_action` derivation and the checked-in preview Rego policy still agree on the preview actions
3. run `cargo test -p agent-auditor-hostd poc::messaging:: --lib` to verify the messaging taxonomy / record / persistence unit tests still agree on the preview contract
4. run `cargo test -p agent-auditor-hostd --test messaging_governance_smoke` to verify the bootstrap messaging preview output still matches the checked-in fixture set

Passing these tests means the repository still agrees on the messaging contract, policy input, record reflection, and bootstrap preview. It still does **not** prove live provider mediation.

## Known constraints

See [`../architecture/messaging-collaboration-governance-known-constraints.md`](../architecture/messaging-collaboration-governance-known-constraints.md) for the explicit limitations that still apply to this slice.

## When this runbook should change

Update this document when any of the following happens:

- live Slack / Discord interception, mediation, or webhook-gateway-backed messaging inputs replace deterministic preview events
- the messaging contract fields change in `agenta-core`
- the shared messaging taxonomy expands beyond the current six checked-in provider actions
- the checked-in preview policy expands beyond the current allow / hold / deny example slice
- messaging audit or approval persistence moves away from the current bootstrap JSONL store
- the smoke fixtures stop being the canonical bootstrap preview contract
- approval / control-plane UX stops being a future phase and starts consuming the messaging records directly
