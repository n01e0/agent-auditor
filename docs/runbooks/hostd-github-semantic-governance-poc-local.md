# hostd GitHub semantic governance PoC: local runbook

This runbook covers the current `agent-auditor-hostd` GitHub semantic-governance PoC after the first GitHub slice.

Use the real-traffic evidence labels in [`../architecture/real-traffic-observation-boundary.md`](../architecture/real-traffic-observation-boundary.md) literally when reading this document. The current GitHub story is split: the six-action GitHub governance slice is still mostly fixture preview, while one `repos.update_visibility` path is now exposed as a validated observation through the forward-proxy observed-runtime seam.

## What this PoC currently proves

The current GitHub path is intentionally narrow:

- `agent-auditor-hostd` can assemble a GitHub taxonomy / metadata / policy / record pipeline from deterministic preview observations for the checked-in six-action governance slice
- the classifier can recognize these high-risk GitHub governance actions from redaction-safe request hints:
  - `repos.update_visibility`
  - `branches.update_protection`
  - `actions.workflow_dispatch`
  - `actions.runs.rerun`
  - `pulls.merge`
  - `actions.secrets.create_or_update`
- the docs-backed GitHub metadata catalog fixes method / canonical resource / required permission / side effect for those six actions
- classified GitHub actions can be normalized into `agenta-core::EventEnvelope` values with `event_type=github_action`
- `agenta-policy` can evaluate normalized GitHub events against the checked-in preview policy and return `allow` / `require_approval` / `deny`
- `require_approval` can derive a pending `ApprovalRequest`
- reflected GitHub `hold` and `deny` outcomes can be attached to `agenta-core` event metadata plus local approval / audit records
- reflected GitHub audit records and approval requests can be written to local JSONL files for inspection
- the fixture-preview path is covered by focused unit tests, the broader provider-abstraction smoke test, and a dedicated GitHub fixture smoke test
- the repository also exposes one forward-proxy observed-runtime GitHub path where `repos.update_visibility` completes `capture -> correlate -> classify -> policy -> audit` with `observation_provenance=observed_request` and `validation_status=validated_observation`
- even that validated observation is still a fail-open audit/approval proof, not an inline GitHub block/hold proof

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today. The checked-in validated-observation path is still repo-local and uses the hostd-owned forward-proxy observed-runtime seam rather than a production GitHub API proxy deployment, browser extension, or inline network block path.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these GitHub-oriented categories of lines:

- `github_taxonomy=...`
- `github_metadata=...`
- `github_policy=...`
- `github_classified_require_approval=...`
- `github_normalized_require_approval=...`
- `github_policy_decision_require_approval=...`
- `github_approval_request_require_approval=...`
- `github_enriched_require_approval=...`
- `github_normalized_allow=...`
- `github_policy_decision_allow=...`
- `github_enriched_allow=...`
- `github_normalized_deny=...`
- `github_policy_decision_deny=...`
- `github_enriched_deny=...`
- `persisted_github_audit_record_require_approval=...`
- `persisted_github_approval_request=...`
- `persisted_github_audit_record_allow=...`
- `persisted_github_audit_record_deny=...`
- `github_record=...`
- `github_validated_runtime_source=...`
- `github_validated_source_kind=...`
- `github_validated_session_correlation_status=...`
- `github_validated_capture_summary=...`
- `github_validated_normalized_event=...`
- `github_validated_policy_decision=...`
- `github_validated_approval_request=...`
- `persisted_github_validated_audit_record=...`
- `persisted_github_validated_approval_request=...`
- `persisted_github_validated_audit_observation_local_jsonl_inspection=...`
- `persisted_github_validated_approval_observation_local_jsonl_inspection=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
github_taxonomy=sources=api_observation,browser_observation surfaces=github,github.repos,github.branches,github.actions,github.pulls ... actions=repos.update_visibility,branches.update_protection,actions.workflow_dispatch,actions.runs.rerun,pulls.merge,actions.secrets.create_or_update stages=service_map->taxonomy->label->handoff
github_metadata=contract_fields=provider_id,action_key metadata_fields=method,canonical_resource,side_effect,oauth_scopes,privilege_class ...
github_policy=sources=api_observation,browser_observation surfaces=github,github.repos,github.branches,github.actions,github.pulls ... stages=normalize->annotate->evaluate->project
github_normalized_require_approval={...}
github_policy_decision_require_approval={...}
github_approval_request_require_approval={...}
github_enriched_require_approval={...}
github_normalized_allow={...}
github_policy_decision_allow={...}
github_enriched_allow={...}
github_normalized_deny={...}
github_policy_decision_deny={...}
github_enriched_deny={...}
persisted_github_audit_record_require_approval={...}
persisted_github_approval_request={...}
persisted_github_audit_record_allow={...}
persisted_github_audit_record_deny={...}
github_record=sources=api_observation,browser_observation surfaces=github,github.repos,github.branches,github.actions,github.pulls record_fields=normalized_event,policy_decision,approval_request,redaction_status stages=persist->publish sinks=structured_log,audit_store,approval_store
github_validated_runtime_source=forward_proxy_observed_runtime_path
github_validated_source_kind=live_proxy_observed
github_validated_session_correlation_status=runtime_path_confirmed
github_validated_capture_summary=request_id=req_live_proxy_github_validated_repos_update_visibility source_kind=live_proxy_observed semantic_action=repos.update_visibility ...
github_validated_normalized_event={..."action":{"attributes":{"observation_provenance":"observed_request","validation_status":"validated_observation","validation_capture_source":"forward_proxy_observed_runtime_path"}}}
github_validated_policy_decision={...}
github_validated_approval_request={...}
persisted_github_validated_audit_observation_local_jsonl_inspection={..."observation_provenance":"observed_request","validation_status":"validated_observation","evidence_tier":"validated_observation"}
```

## Current real-traffic evidence boundary for this slice

Read the current GitHub outputs as three separate tiers:

- `github_*` preview bootstrap lines and `github_semantic_governance_smoke` still prove the six-action **fixture-preview** contract.
- `github_validated_*` bootstrap lines and `github_validated_observation_smoke` prove one **validated observation** for `repos.update_visibility` through `forward_proxy_observed_runtime_path`.
- the other checked-in GitHub actions (`branches.update_protection`, `actions.workflow_dispatch`, `actions.runs.rerun`, `pulls.merge`, `actions.secrets.create_or_update`) do **not** become validated observations just because the slice now has one validated path.

That distinction matters: the repository can now prove one real observed-and-validated GitHub path, but it still does not claim broad live GitHub interception coverage.

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated GitHub fixture smoke test

```bash
cargo test -p agent-auditor-hostd --test github_semantic_governance_smoke
```

### Run the validated-observation GitHub smoke test

```bash
cargo test -p agent-auditor-hostd --test github_validated_observation_smoke
```

### Run the broader provider-abstraction smoke test

```bash
cargo test -p agent-auditor-hostd --test provider_abstraction_smoke
```

### Run only hostd GitHub unit tests

```bash
cargo test -p agent-auditor-hostd poc::github:: --lib
```

### Run only the policy crate GitHub preview tests

```bash
cargo test -p agenta-policy github_action --lib
```

## Where the current behavior lives

- GitHub module boundary:
  - `docs/architecture/hostd-github-semantic-governance-poc.md`
- GitHub docs-backed metadata catalog:
  - `docs/architecture/provider-abstraction-github-candidate-catalog.md`
- GitHub known constraints:
  - `docs/architecture/hostd-github-semantic-governance-known-constraints.md`
- classify / normalize / record scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/github/`
- preview GitHub policy:
  - `examples/policies/github_action.rego`
- policy input and decision reflection helpers:
  - `crates/agenta-policy/src/lib.rs`
- normalized event and approval record types:
  - `crates/agenta-core/src/lib.rs`
- bootstrap preview output and local persistence preview:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated GitHub smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-github-semantic-governance-smoke-fixtures.json`
- dedicated GitHub fixture smoke test:
  - `cmd/agent-auditor-hostd/tests/github_semantic_governance_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes GitHub PoC records under:

```text
target/agent-auditor-hostd-github-poc-store/
```

Expected files:

- `audit-records.jsonl`
- `approval-requests.jsonl`

These files are bootstrap artifacts for local inspection only. They are intentionally reset when the GitHub PoC store is bootstrapped.

## How to interpret the preview policy

The checked-in preview policy is intentionally narrow:

- `repos.update_visibility` -> `require_approval`
- `branches.update_protection` -> `require_approval`
- `actions.workflow_dispatch` -> `require_approval`
- `actions.runs.rerun` -> `allow`
- `pulls.merge` -> `require_approval`
- `actions.secrets.create_or_update` -> `deny`

This is enough to prove the end-to-end event / policy / approval / audit path. It is **not** a complete GitHub governance policy.

## How to interpret fail-open / fail-closed today

Use this rule when reading the current bootstrap output:

- if you see `github_enriched_require_approval={... enforcement:{directive:"hold" ...}}` for repository visibility changes, branch protection updates, workflow dispatch, or pull-request merge, read it as **"the preview path would like to hold this"**, not **"the live GitHub action was actually paused"**
- if you see `github_enriched_deny={... enforcement:{directive:"deny" ...}}` for repository Actions secret writes, read it as reflected intended deny metadata, not evidence that a live GitHub request was actually blocked
- `actions.runs.rerun` stays observe-only/allow in the checked-in posture, so there is currently no hold or deny claim to make for that action
- if you see `github_validated_*` lines with `validation_status=validated_observation`, read that as **"this request completed the minimum auditable observed-runtime path"**, not **"GitHub now has a validated fail-closed enforcement path"**

In other words: the current GitHub PoC can now reflect intended allow / hold / deny outcomes into `agenta-core` events and local approval / audit records, and it can prove one validated observation through the observed-runtime seam, but the live GitHub request path is still documented as fail-open because there is no validated inline intercept / pause / resume path.

## What to validate before trusting the preview outputs

If you are changing this path locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-policy github_action --lib` to verify the checked-in GitHub preview policy still evaluates the normalized GitHub governance actions
2. run `cargo test -p agent-auditor-hostd poc::github:: --lib` to verify the GitHub taxonomy / normalization / policy / record unit tests still agree on the six-action slice
3. run `cargo test -p agent-auditor-hostd --test github_semantic_governance_smoke` to verify the bootstrap preview output still matches the checked-in GitHub fixture set
4. run `cargo test -p agent-auditor-hostd --test github_validated_observation_smoke` to verify the observed-runtime GitHub path still preserves `observed_request` provenance plus `validated_observation` status end to end
5. run `cargo test -p agent-auditor-hostd --test provider_abstraction_smoke` to verify the broader provider-abstraction bootstrap contract still agrees with the GitHub slice

Passing these tests means the fixture-preview contract and the single validated-observation GitHub path are internally consistent. It still does **not** prove broad inline interception on live GitHub traffic.

## Known constraints

See [`../architecture/hostd-github-semantic-governance-known-constraints.md`](../architecture/hostd-github-semantic-governance-known-constraints.md) for the explicit limitations that still apply to this path.

## When this runbook should change

Update this document when any of the following happens:

- GitHub observation inputs start consuming live API adapters, browser relays, or proxy traces instead of deterministic preview observations
- more GitHub actions gain their own observed-request or validated-observation paths beyond `repos.update_visibility`
- the semantic taxonomy expands beyond the current six checked-in GitHub governance actions
- normalized `github_action` events change shape in `agenta-core`
- the checked-in Rego example stops being the default preview policy path
- GitHub audit or approval persistence moves away from the current bootstrap JSONL store
- local execution begins requiring elevated privileges or extra GitHub test setup
