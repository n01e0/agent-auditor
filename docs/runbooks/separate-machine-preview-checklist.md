# separate-machine preview checklist

This note connects the **focused smoke tests** to the **runbooks** they validate for the current separate-machine audit preview target.

Use it after [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md) when you want a compact answer to:

- which focused smoke test should I run?
- which runbook does that smoke test back?
- what should I inspect if that smoke test passes?
- what is the minimum checklist before I say the separate-machine preview is ready to evaluate?

## focused smoke test → runbook map

| focused smoke test | primary preview slice | runbooks it backs | what to inspect after it passes |
| --- | --- | --- | --- |
| `cargo test -p agent-auditor-hostd --test poc_smoke` | hostd bootstrap, persisted JSONL artifacts, baseline PoC slices | [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md), [`hostd-filesystem-poc-local.md`](hostd-filesystem-poc-local.md), [`hostd-network-poc-local.md`](hostd-network-poc-local.md), [`hostd-secret-access-poc-local.md`](hostd-secret-access-poc-local.md), [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md) | `target/agent-auditor-hostd*-store/`, `approval-requests.jsonl`, `audit-records.jsonl`, hostd bootstrap stdout |
| `cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke` | live preview seam honesty, coverage / preview / unsupported / fail-open display rules | [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md), [`hostd-enforcement-foundation-local.md`](hostd-enforcement-foundation-local.md), [`hostd-api-network-gws-poc-local.md`](hostd-api-network-gws-poc-local.md), [`hostd-github-semantic-governance-poc-local.md`](hostd-github-semantic-governance-poc-local.md), [`generic-rest-oauth-governance-local.md`](generic-rest-oauth-governance-local.md), [`messaging-collaboration-governance-local.md`](messaging-collaboration-governance-local.md) | live preview reflected records, `coverage_support`, `coverage_display_rule`, `coverage_summary`, approval-materialization behavior |
| `cargo test -p agent-auditor-controld --test control_plane_smoke` | control-plane status / explanation / notification / reconciliation / export consistency | [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md), [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md), [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md), [`policy-authoring-explainability-local.md`](policy-authoring-explainability-local.md) | controld bootstrap stdout, `approval_ops_hardening_pattern_matrix`, `approval_audit_export_*`, local-vs-export consistency fields |

## how to read failures

If a focused smoke test fails, use the matching runbook family first instead of widening the investigation immediately.

### `poc_smoke` fails

Start with:

- `separate-machine-audit-preview-local.md`
- the relevant hostd PoC runbook for the failing slice
- `approval-jsonl-inspection-local.md` if the failure involves approval JSONL output

Typical symptom groups:

- bootstrap stdout drift
- missing or malformed local JSONL artifacts
- persisted approval/audit records no longer matching the checked-in fixture contract

### `live_proxy_seam_smoke` fails

Start with:

- `hostd-enforcement-foundation-local.md`
- the provider-specific live preview runbook for the failing seam
- the live preview architecture notes linked from those runbooks

Typical symptom groups:

- `coverage_support` / `coverage_display_rule` drift
- fail-open wording drift
- approval materialization mismatch for `shadow` / `enforce_preview` / `unsupported`

### `control_plane_smoke` fails

Start with:

- `approval-control-plane-ux-local.md`
- `approval-jsonl-inspection-local.md`
- `policy-authoring-explainability-local.md`

Typical symptom groups:

- stale run / waiting_merge / recovery / status drift projection mismatch
- audit/export field drift
- reviewer-facing summary / rationale / explanation consistency drift

## separate-machine preview checklist

Mark the preview as ready to evaluate on another Linux machine only if all of these are true.

### setup

- [ ] checked out an exact revision and kept docs + binaries on the same revision
- [ ] built `agent-auditor-hostd`, `agent-auditor-controld`, and `agent-auditor-cli`
- [ ] started from a clean preview-local `target/agent-auditor-hostd*-store/` state

### runtime execution

- [ ] `./target/release/agent-auditor-hostd` ran successfully
- [ ] `./target/release/agent-auditor-controld` ran successfully
- [ ] hostd created the expected preview-local JSONL artifacts under `target/agent-auditor-hostd*-store/`

### focused validation

- [ ] `cargo test -p agent-auditor-hostd --test poc_smoke`
- [ ] `cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke`
- [ ] `cargo test -p agent-auditor-controld --test control_plane_smoke`

### artifact inspection

- [ ] local `approval-requests.jsonl` / `audit-records.jsonl` are readable on the separate machine
- [ ] local JSONL inspection still shows reviewer-facing summary / persisted rationale / requester context in the expected places
- [ ] control-plane export output still lines up with the local JSONL inspection fields that are meant to match
- [ ] live preview records still distinguish `preview_supported` vs `unsupported` and keep the current fail-open display rule explicit

### cleanup / retry

- [ ] preview-local store directories can be removed cleanly before rerunning the same revision
- [ ] if output drifts, the operator can retry from a clean local state or roll back to the previous known-good revision without guesswork

## shortest operator order

If you only want the compact separate-machine preview flow, use this exact order:

1. follow [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md) through build + run
2. run `poc_smoke`
3. inspect the local JSONL artifacts
4. run `live_proxy_seam_smoke`
5. inspect live preview coverage / fail-open fields
6. run `control_plane_smoke`
7. compare control-plane export output to local inspection output
8. mark the checklist above complete before calling the preview reproducible

## related docs

- [`separate-machine-audit-preview-local.md`](separate-machine-audit-preview-local.md)
- [`approval-jsonl-inspection-local.md`](approval-jsonl-inspection-local.md)
- [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md)
- [`hostd-enforcement-foundation-local.md`](hostd-enforcement-foundation-local.md)
