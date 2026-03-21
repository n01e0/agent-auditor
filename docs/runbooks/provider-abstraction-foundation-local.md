# provider abstraction foundation: local runbook

This runbook covers the current local workflow for the provider-abstraction foundation slice after Google Workspace moved onto the shared provider contract.

## What this slice currently proves

The current provider-abstraction path is intentionally narrow but concrete:

- `agenta-core` exposes a shared provider action contract keyed by `provider_id + action_key + target_hint`
- `agenta-core` exposes shared provider metadata types for `method`, `canonical_resource`, `side_effect`, `oauth_scopes`, and `privilege_class`
- the checked-in Google Workspace PoC now emits normalized events that carry shared provider contract fields instead of relying only on a GWS-only semantic label
- `agenta-policy` can derive `input.provider_action` from those shared contract fields and evaluate policy on provider + action identity
- `agent-auditor-hostd` can preview a provider-abstraction catalog join from a normalized GWS event into docs-backed shared metadata
- the repository fixes the next provider candidate as GitHub at the docs / schema / test layer without claiming that a live GitHub runtime exists yet
- the slice is covered by focused unit tests plus a dedicated hostd smoke test for the shared provider contract and metadata preview lines

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

This workflow does **not** require root today. The checked-in provider-abstraction preview still runs from deterministic bootstrap data and the current live runtime-facing path is limited to the existing GWS PoC.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected provider-abstraction-oriented output includes these lines:

- `provider_abstraction_plan=...`
- `provider_abstraction_catalog=...`
- `provider_abstraction_policy_input=...`
- `provider_abstraction_metadata_entry=...`

You should also still see the GWS pipeline lines that prove where those shared fields came from, especially:

- `gws_classify=...`
- `gws_evaluate=...`
- `gws_normalized_api=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
provider_abstraction_plan=providers=gws,github taxonomy_output=provider_id,provider_action_label,target_hint,taxonomy_reason contract_fields=provider_id,action_key,target_hint metadata_fields=method,canonical_resource,side_effect,oauth_scopes,privilege_class
provider_abstraction_catalog=entries=4 actions=gws:drive.permissions.update,gws:drive.files.get_media,gws:gmail.users.messages.send,gws:admin.reports.activities.list
gws_classify=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin linkage_fields=source_kind,request_id,transport,authority_hint,method_hint,path_hint,destination_ip,destination_port,semantic_surface_hint,session_id,agent_id,workspace_id,linkage_reason classification_fields=semantic_surface,provider_id,action_key,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained actions=drive.permissions.update,drive.files.get_media,gmail.users.messages.send,admin.reports.activities.list stages=service_map->taxonomy->label->handoff
gws_evaluate=sources=api_observation,network_observation surfaces=gws,gws.drive,gws.gmail,gws.admin linkage_fields=source_kind,request_id,transport,authority_hint,method_hint,path_hint,destination_ip,destination_port,semantic_surface_hint,session_id,agent_id,workspace_id,linkage_reason classification_fields=semantic_surface,provider_id,action_key,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained stages=normalize->policy->approval_projection
provider_abstraction_policy_input={...}
provider_abstraction_metadata_entry={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated provider-abstraction smoke test

```bash
cargo test -p agent-auditor-hostd --test provider_abstraction_smoke
```

### Run only the shared provider type tests

```bash
cargo test -p agenta-core provider:: --lib
```

### Run only the provider-action policy-input tests

```bash
cargo test -p agenta-policy provider_action --lib
```

### Run only the hostd provider-abstraction round-trip unit test

```bash
cargo test -p agent-auditor-hostd gws_provider_metadata_catalog_covers_all_preview_actions_for_policy_input --lib
```

### Run the broader GWS smoke coverage that feeds the shared provider path

```bash
cargo test -p agent-auditor-hostd --test gws_poc_smoke
cargo test -p agent-auditor-hostd --test gws_enforcement_smoke
```

## Where the current behavior lives

- shared provider contract and metadata types:
  - `crates/agenta-core/src/provider.rs`
- provider-aware policy input derivation and Rego evaluation helpers:
  - `crates/agenta-policy/src/lib.rs`
- current provider-specific taxonomy and normalization path:
  - `cmd/agent-auditor-hostd/src/poc/gws/`
- preview bootstrap output that surfaces the provider-abstraction summary and metadata join:
  - `cmd/agent-auditor-hostd/src/main.rs`
- hostd provider-abstraction smoke fixtures:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-provider-abstraction-smoke-fixtures.json`
- dedicated provider-abstraction smoke test:
  - `cmd/agent-auditor-hostd/tests/provider_abstraction_smoke.rs`
- next-provider docs catalog fixed for the shared metadata shape:
  - `docs/architecture/provider-abstraction-github-candidate-catalog.md`
- GitHub-specific local workflow and limitations for that next-provider slice:
  - `docs/runbooks/hostd-github-semantic-governance-poc-local.md`
  - `docs/architecture/hostd-github-semantic-governance-known-constraints.md`

## How to interpret the current preview

Use these rules when reading the current output:

- `provider_abstraction_plan` proves the ownership split only: taxonomy -> contract -> metadata
- `provider_abstraction_catalog` is a checked-in preview catalog for the currently wired GWS actions, not a generic live provider registry
- `provider_abstraction_policy_input` proves that the shared provider contract can be derived from a normalized event and exposed to policy without depending on the legacy GWS-only label
- `provider_abstraction_metadata_entry` proves that the shared action identity can join against docs-backed metadata without re-running provider-specific classification
- the GitHub catalog now fixes docs-backed method / resource / required permission / side effect metadata for six high-risk GitHub governance actions, and the repository has checked-in PoC taxonomy plus `agenta-core` normalization, a GitHub preview policy example, and append-only audit / approval record reflection for those actions, but there is still **no** live GitHub runtime adapter or interception path yet
- the `oauth_scopes` field is the current stable metadata field name across providers; for GitHub it currently carries docs-backed auth labels rather than runtime-verified grants

## What to validate before trusting the preview outputs

If you change this slice locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-core provider:: --lib` to verify the shared provider contract and metadata types still round-trip cleanly
2. run `cargo test -p agenta-policy provider_action --lib` to verify provider-action derivation and provider-based policy input still hold
3. run `cargo test -p agenta-policy github_action --lib` to verify the checked-in GitHub preview policy still evaluates the normalized GitHub governance actions
4. run `cargo test -p agent-auditor-hostd gws_provider_metadata_catalog_covers_all_preview_actions_for_policy_input --lib` to verify the current GWS-backed preview actions still join against the shared metadata catalog
5. run `cargo test -p agent-auditor-hostd github_pipeline_can_require_approval_for_visibility_dispatch_and_merge --lib` to verify the GitHub PoC still bridges normalized actions into `agenta-policy`
6. run `cargo test -p agent-auditor-hostd github_hold_reflects_into_event_approval_and_audit_records --lib` to verify GitHub hold outcomes still project into append-only audit / approval records
7. run `cargo test -p agent-auditor-hostd --test provider_abstraction_smoke` to verify the bootstrap provider-abstraction output still matches the checked-in fixture contract

Passing these tests means the repository still agrees on the shared provider contract, metadata shape, and bootstrap preview. It does **not** prove a production-ready multi-provider runtime.

## Known constraints

See [`../architecture/provider-abstraction-known-constraints.md`](../architecture/provider-abstraction-known-constraints.md) for the explicit limitations that still apply to this slice.

## When this runbook should change

Update this document when any of the following happens:

- a non-GWS provider gains a real checked-in classifier, adapter, or normalized runtime path
- the shared provider contract fields change in `agenta-core`
- the shared metadata schema adds or splits fields beyond the current `oauth_scopes` / privilege model
- hostd bootstrap output stops exposing the provider-abstraction summary or metadata join preview lines
- GitHub moves from a docs-backed governance metadata catalog into a real runtime-backed provider implementation
- provider metadata stops being maintained as a checked-in code/docs catalog and becomes a generated or remote-backed registry
