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
  - `coverage_posture=preview_record_only`
  - `mode_status`
  - `approval_eligibility`

The important detail is that the policy bridge keeps the repository honest about the current live posture. A `deny` or `require_approval` decision is treated as **policy intent**, not proof of real inline interception.

## Approval projection

`live_proxy/approval.rs` now projects preview approval state from a live policy evaluation.

For `require_approval` decisions it will:

- create a pending `ApprovalRequest`
- attach enforcement metadata showing:
  - `directive=hold`
  - `status=observe_only_fallback`
  - `enforced=false`
- mark the live wait state as `pending_approval_record_only`
- make it explicit that no real pause/resume token exists yet

That is the key distinction for this phase: the repository can now **record approval intent** on the live preview path, but it still cannot pause the in-flight provider request.

## Audit reflection

`live_proxy/audit.rs` now reflects live preview decisions into append-only audit records.

Every reflected live preview record carries:

- the policy decision
- the realized enforcement directive (`allow`, `hold`, or `deny`)
- `status=observe_only_fallback`
- `enforced=false`
- `coverage_gap=live_preview_path_has_no_inline_hold_deny_or_resume`
- `redaction_status=redaction_safe_preview_only`
- the redaction-safe live request summary

That means the audit log now answers the operator question correctly:

- what the policy *wanted* to do
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

- evaluate a generic REST live preview and create a preview-only approval record
- reflect a GWS allow preview into an audit record with `observe_only_fallback`
- reflect a GitHub deny preview into an audit record with `observe_only_fallback`
- reflect a messaging approval-gated preview into both an approval record and an audit record
- persist those records through the existing append-only PoC stores

## What this still does not claim

P13-7 still does **not** claim:

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
- live coverage posture: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
