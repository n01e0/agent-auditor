# live preview record reflection

This note fixes the first checked-in policy / approval / audit reflection path for live proxy previews.

## Goal of P13-7

Connect the shared live preview path to the repository’s existing policy evaluators and append-only stores without pretending that inline enforcement already exists.

That means the repository now proves three things at once:

1. live preview inputs can reach the existing policy surfaces
2. `require_approval` outcomes can create pending approval records
3. audit records can reflect the real runtime posture as **observe-only fallback**, not fake fail-closed enforcement

## Checked-in Rust pieces

The new checked-in logic lives mainly in:

- `cmd/agent-auditor-hostd/src/poc/live_proxy/mode.rs`
- `cmd/agent-auditor-hostd/src/poc/live_proxy/policy.rs`
- `cmd/agent-auditor-hostd/src/poc/live_proxy/approval.rs`
- `cmd/agent-auditor-hostd/src/poc/live_proxy/audit.rs`

and is supported by a new normalization helper in:

- `cmd/agent-auditor-hostd/src/poc/messaging/policy.rs`

## Policy bridge

`live_proxy/policy.rs` now does more than describe a boundary.

It can:

- annotate normalized events as live-preview inputs
- evaluate those events against the existing policy evaluators for:
  - generic REST
  - GWS
  - GitHub
  - messaging
- project explicit preview metadata alongside the decision:
  - `coverage_posture`
  - `mode_behavior`
  - `mode_status`
  - `record_status`
  - `approval_eligibility`

The important detail is that the policy bridge keeps the repository honest about the current live posture. A `deny` or `require_approval` decision is treated as **policy intent**, not proof of real inline interception.

## Approval projection

`live_proxy/approval.rs` now projects preview approval state from a live policy evaluation.

For `require_approval` decisions it now depends on the mode projection:

- `shadow`
  - keeps the result advisory-only
  - does **not** create an `ApprovalRequest`
  - marks the wait state as `shadow_observe_only`
- `enforce_preview`
  - creates a pending `ApprovalRequest`
  - attaches enforcement metadata showing `directive=hold`, `status=observe_only_fallback`, and `enforced=false`
  - marks the live wait state as `pending_approval_record_only`
- `unsupported`
  - records the signal as unsupported
  - does **not** create an `ApprovalRequest`
  - marks the wait state as `unsupported_mode_no_approval_path`

That is the key distinction for this phase: the repository can now distinguish advisory-only shadow behavior, preview-record-only enforce-preview behavior, and unsupported-mode diagnostic behavior without pretending any of them are true inline pause/resume.

## Audit reflection

`live_proxy/audit.rs` now reflects live preview decisions into append-only audit records.

Every reflected live preview record now carries:

- the policy decision
- the realized enforcement directive (`allow`, `hold`, or `deny`)
- `status=observe_only_fallback`
- `enforced=false`
- `mode_behavior`
- `mode_status`
- `record_status`
- a mode-specific `coverage_gap`
- `redaction_status=redaction_safe_preview_only`
- the redaction-safe live request summary

That means the audit log now answers the operator question correctly:

- what the policy *wanted* to do
- whether the mode was shadow, enforce-preview, or unsupported
- what the runtime *actually* did
- why the result was preview-only instead of real inline enforcement

## Persistence

`live_proxy/audit.rs` also introduces a small store bridge so the same live preview reflection can persist through the existing append-only PoC stores for:

- generic REST
- GWS
- GitHub
- messaging

In other words, P13-7 does not invent a new storage shape. It reuses the repository’s existing per-slice stores and writes the live preview reflection into them.

## Messaging-specific addition

The messaging governance slice did not previously expose a public event normalizer for classified messaging actions.

P13-7 adds one in `messaging/policy.rs` so the live preview path can:

- take a classified Slack/Discord collaboration action
- normalize it into the flat event shape expected by `agenta-policy`
- carry enough generic REST lineage (including docs-backed scope labels) for policy evaluation and record reflection

## What the new tests prove

The new tests prove that the live preview path can now:

- keep shadow `require_approval` results advisory-only with no approval request
- create preview-only approval state for enforce-preview `require_approval` results
- reflect unsupported-mode deny results with an explicit unsupported coverage gap
- reflect a GWS allow preview into an audit record with `observe_only_fallback`
- persist those records through the existing append-only PoC stores

## What this still does not claim

P13-8 still does **not** claim:

- inline fail-closed deny enforcement
- inline hold / resume support
- approval queue reconciliation
- provider retry coordination
- final mode semantics for `shadow`, `enforce_preview`, and `unsupported`

Those remain P13-8 work.

## Related docs

- live proxy phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- shared live envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- generic REST live preview adapter: [`generic-rest-live-preview-path.md`](generic-rest-live-preview-path.md)
- provider live preview adapters: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
- live preview mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- live coverage posture: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
