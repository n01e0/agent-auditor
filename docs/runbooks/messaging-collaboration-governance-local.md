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
- one Hermes/Discord observed-runtime path now completes `capture -> correlate -> classify -> policy -> audit` with durable `validated_observation` inspection output for `channels.messages.create`
- the slice is covered by focused unit tests plus a dedicated hostd smoke test for the messaging bootstrap preview lines

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

This workflow does **not** require root today. Most of the messaging slice still runs from deterministic preview events and docs-backed permission labels rather than broad live Slack / Discord mediation, browser relay capture, webhook gateways, or runtime token verification. The current exception is one checked-in Hermes/Discord observed-runtime path for Discord channel message send, which now reaches durable `validated_observation` metadata through the existing live-proxy/session-correlation seam.

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
- `messaging_observed_runtime_source=...`
- `messaging_observed_capture_summary=...`
- `messaging_observed_normalized_event=...`
- `persisted_messaging_observed_audit_record=...`
- `persisted_messaging_observed_audit_observation_local_jsonl_inspection=...`

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

### Run the Hermes/Discord observed-runtime validated-observation smoke test

```bash
cargo test -p agent-auditor-hostd --test messaging_observed_smoke
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
- observed-runtime Hermes/Discord wrapper:
  - `cmd/agent-auditor-hostd/src/poc/live_proxy/messaging_observed.rs`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated messaging smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-messaging-governance-smoke-fixtures.json`
- dedicated messaging smoke test:
  - `cmd/agent-auditor-hostd/tests/messaging_governance_smoke.rs`
- observed-runtime Hermes/Discord smoke test:
  - `cmd/agent-auditor-hostd/tests/messaging_observed_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes messaging PoC records under:

```text
target/agent-auditor-hostd-messaging-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `audit-records.integrity.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the messaging PoC store is bootstrapped.

## Checked-in Hermes/Discord validated-observation path

The first checked-in live messaging path is intentionally narrow:

- Hermes runtime -> forward proxy observed-runtime seam
- Discord `POST /api/v10/channels/{channel_id}/messages`
- semantic action: `channels.messages.create`
- messaging family: `message.send`

The strongest expected reviewer-facing evidence is inside `persisted_messaging_observed_audit_observation_local_jsonl_inspection` or `agent-auditor-cli audit show`:

- `observation_provenance="observed_request"`
- `validation_status="validated_observation"`
- `evidence_tier="validated_observation"`
- `capture_source="forward_proxy_observed_runtime_path"`
- `session_correlation_status="runtime_path_confirmed"`
- `durable_integrity.signature_status="unsigned_baseline"`
- `durable_storage_lineage.store="agent-auditor-hostd-messaging-poc-store"`
- `durable_storage_lineage.stream="audit-records"`

That is the current minimum honest claim for the Hermes/Discord path: one real observed-runtime Discord request completed the checked-in auditable path and can be verified from durable inspection output.

## Minimum final evidence bundle to save

For the checked-in Hermes/Discord validated path, save at least:

1. the rendered compose config command you actually used
2. one observed-runtime `requests.jsonl` line showing the Discord request envelope
3. one messaging `audit-records.jsonl` line showing `channels.messages.create`
4. one messaging `audit-records.integrity.jsonl` checkpoint line
5. one `agent-auditor-cli audit show --state-dir /state ...` output showing `observation_local_inspection`, `durable_integrity`, and `durable_storage_lineage`
6. the exact Hermes image tag, topology, and Discord guild/channel target you used

That final evidence bundle is enough for another reviewer to confirm that the result crossed the observed-runtime seam, kept durable integrity/storage lineage, and honestly reached `validated_observation` for this one Discord route.

## How to interpret the preview policy

The checked-in preview policy is intentionally narrow:

- Slack `chat.post_message` into a public channel -> `allow`
- Discord `channels.messages.create` through the observed-runtime path -> `allow`, with durable `validated_observation` metadata
- Discord thread member add -> `require_approval`
- Discord permission overwrite update -> `deny`
- Slack file upload -> `require_approval`

This is enough to prove the end-to-end messaging event / policy / approval / audit path for the checked-in preview samples plus one Hermes/Discord observed-runtime route. It is **not** a complete Slack / Discord governance model.

## How to interpret fail-open / fail-closed today

Use this rule when reading the current bootstrap output:

- if you see `messaging_enriched_require_approval={... enforcement:{directive:"hold" ...}}`, read it as **"the preview path would like to hold this messaging action"**, not **"a live Slack or Discord action was actually paused"**
- if you see `messaging_enriched_deny={... enforcement:{directive:"deny" ...}}`, read it as reflected intended deny metadata, not evidence that a live provider request was actually blocked inline
- if you see `messaging_enriched_allow={...}`, read it as reflected allow metadata for the checked-in preview posture, not proof of a product-grade messaging mediation path
- if you see `messaging_observed_*` lines with `validation_status=validated_observation`, read that as **"this Discord request completed the minimum auditable observed-runtime path"**, not **"Slack/Discord now has broad live inline enforcement"**

In other words: the current messaging slice can reflect intended allow / hold / deny outcomes into `agenta-core` events and local approval / audit records, and it now proves one Hermes/Discord observed-runtime route to durable `validated_observation`. It still does **not** prove broad inline interception, pause/resume, or fail-closed live Slack/Discord enforcement.

## What to validate before trusting the preview outputs

If you are changing this path locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-core messaging:: --lib` to verify the messaging contract types still parse and round-trip cleanly
2. run `cargo test -p agenta-policy messaging_action --lib` to verify `input.messaging_action` derivation and the checked-in preview Rego policy still agree on the preview actions
3. run `cargo test -p agent-auditor-hostd poc::messaging:: --lib` to verify the messaging taxonomy / record / persistence unit tests still agree on the preview contract
4. run `cargo test -p agent-auditor-hostd --test messaging_governance_smoke` to verify the bootstrap messaging preview output still matches the checked-in fixture set
5. run `cargo test -p agent-auditor-hostd --test messaging_observed_smoke` to verify the checked-in Hermes/Discord observed-runtime route still preserves `observed_request` provenance plus durable `validated_observation` inspection fields

Passing these tests means the repository still agrees on the messaging contract, policy input, record reflection, bootstrap preview, and the one checked-in Hermes/Discord validated-observation route. It still does **not** prove broad live provider mediation.

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
