# policy authoring / explainability local runbook

This runbook is the local development guide for the policy authoring / explainability phase.

It is intentionally scoped to the current P14 slice:

- authoring model in `crates/agenta-policy`
- explanation schema in `crates/agenta-core`
- approval-record presentation / rationale projection in `agenta-core` + `agenta-policy`
- smoke validation in `cmd/agent-auditor-controld`

## Primary files

### Authoring model

- `crates/agenta-policy/src/lib.rs`
- `docs/architecture/policy-authoring-model-v1.md`

### Explanation schema

- `crates/agenta-core/src/lib.rs`
- `docs/architecture/policy-explanation-schema-v1.md`

### Reviewer-facing projection / approval record

- `crates/agenta-core/src/controlplane.rs`
- `crates/agenta-policy/src/lib.rs`

### Smoke path

- `cmd/agent-auditor-controld/src/main.rs`
- `cmd/agent-auditor-controld/tests/control_plane_smoke.rs`

## What to run locally

### Baseline validation

Run this before opening or updating a PR:

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy -- -D warnings
```

### Focused tests for this phase

#### Authoring model tests

```bash
cargo test -p agenta-policy policy_authoring_rule_accepts_singular_provider_action_fields
cargo test -p agenta-policy policy_authoring_rule_normalizes_plural_provider_action_lists
cargo test -p agenta-policy policy_authoring_posture_preserves_hold_without_policy_decision_mapping
```

#### Explanation / rationale unit tests

```bash
cargo test -p agenta-policy policy_decision_deserializes_explanation_rationale_and_reviewer_hint
cargo test -p agenta-policy apply_decision_to_event_uses_structured_explanation_summary_when_present
cargo test -p agenta-policy approval_request_from_decision_projects_reason_and_hint
cargo test -p agenta-policy approval_request_from_decision_uses_explanation_summary_when_rationale_is_missing
```

#### Core control-plane projection tests

```bash
cargo test -p agenta-core decision_summary_prefers_reviewer_facing_summary
cargo test -p agenta-core requester_rationale_summary_prefers_persisted_rationale
```

#### Local smoke for reviewer-facing projection

```bash
cargo test -p agent-auditor-controld --test control_plane_smoke -- --nocapture
```

The smoke test should continue to prove that:

- the approval queue item surfaces the reviewer-facing summary
- the rationale capture view surfaces the persisted rationale
- the bootstrap control-plane examples still deserialize cleanly

## Change guide by concern

### If you change provider / action / posture authoring

Touch:

- `crates/agenta-policy/src/lib.rs`
- `docs/architecture/policy-authoring-model-v1.md`

Re-run at least:

```bash
cargo test -p agenta-policy policy_authoring_
```

### If you change explanation schema fields

Touch:

- `crates/agenta-core/src/lib.rs`
- `docs/architecture/policy-explanation-schema-v1.md`

Re-run at least:

```bash
cargo test -p agenta-core
cargo test -p agenta-policy policy_decision_deserializes_explanation_rationale_and_reviewer_hint
```

### If you change reviewer-facing summary / rationale projection

Touch:

- `crates/agenta-core/src/controlplane.rs`
- `crates/agenta-policy/src/lib.rs`
- `cmd/agent-auditor-controld/tests/control_plane_smoke.rs`

Re-run at least:

```bash
cargo test -p agenta-core
cargo test -p agenta-policy approval_request_from_decision_
cargo test -p agent-auditor-controld --test control_plane_smoke -- --nocapture
```

## Review checklist

Before shipping a PR in this phase, confirm all of the following:

- authoring-time fields are not overloaded with reviewer-facing wording
- explanation remains redaction-safe and machine-readable
- `hold` remains representable in explanation even if evaluator decision enums are narrower
- reviewer-facing summary and rationale are derived projections, not the authoring contract itself
- docs stay aligned across:
  - foundation boundary
  - authoring model v1
  - explanation schema v1
  - known constraints

## Related docs

- `docs/architecture/policy-authoring-explainability-foundation.md`
- `docs/architecture/policy-authoring-model-v1.md`
- `docs/architecture/policy-explanation-schema-v1.md`
- `docs/architecture/policy-authoring-explainability-known-constraints.md`
