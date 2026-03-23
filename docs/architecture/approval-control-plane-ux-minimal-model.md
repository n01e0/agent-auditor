# approval / control-plane UX minimal model

This note fixes the first checked-in minimal model for the operator-facing approval / control-plane UX slice.

It sits directly on top of the boundary in [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md).

## Goal of P12-2

Define the smallest repository-owned model that lets the control plane talk about:

- **what is in the approval queue**
- **what a reviewer needs to decide**
- **what rationale the system should preserve**

without redefining upstream policy, provider taxonomy, or append-only audit records.

The immediate rule is:

- upstream layers still own `ApprovalRequest`, `PolicyDecision`, `ApprovalDecisionRecord`, and `EventEnvelope`
- the control-plane UX layer owns a derived queue item plus two reviewer-facing summaries:
  - `ApprovalQueueItem`
  - `ApprovalDecisionSummary`
  - `ApprovalRationaleCapture`
- the minimal control-plane model must stay redaction-safe and derivable from already-recorded approval state

## Checked-in model surface

The checked-in Rust types live in:

- `crates/agenta-core/src/controlplane.rs`

The initial surface is intentionally small.

### `ApprovalQueueItem`

Owns the reviewable queue entry:

- queue identity:
  - `approval_id`
  - `session_id`
  - `event_id`
- lifecycle timestamps:
  - `requested_at`
  - `resolved_at`
  - `expires_at`
- current queue status:
  - `status`
- review/filter fields:
  - `action_class`
  - `action_verb`
  - `target`
  - redaction-safe `attributes`
- reviewer-facing projections:
  - `decision_summary`
  - `rationale_capture`

This is the smallest self-contained queue object that can be rendered or filtered by a future control-plane service without re-running provider taxonomy or policy evaluation.

### `ApprovalDecisionSummary`

Owns the operator-facing “what am I deciding?” card.

Fields:

- `action_summary`
- `rule_id`
- `target_hint`
- `severity`
- `policy_reason`
- `scope`
- `ttl_seconds`
- `reviewer_hint`

This summary is intentionally descriptive, not authoritative. It explains the request in reviewer-friendly terms, but it does not become a second policy source of truth.

`rule_id` is carried so later status/explanation views can anchor the queue item back to the matched policy contract without reopening policy evaluation.

### `ApprovalRationaleCapture`

Owns the “why did this request exist, and what rationale was captured?” view.

Fields:

- `policy_reason`
- `agent_reason`
- `human_request`
- `reviewer_id`
- `reviewer_note`
- `outcome`

This keeps policy rationale, requester intent, and reviewer rationale adjacent without mutating the original policy output or inventing a second approval record format.

## Derivation rules

The minimal model is derived from already-existing approval artifacts, not invented independently.

### Source of truth remains upstream

The control-plane model is derived from:

- `ApprovalRequest`
- `ApprovalRequestAction`
- `ApprovalPolicy`
- optional `RequesterContext`
- optional `ApprovalDecisionRecord`

That means:

- the control plane does **not** re-evaluate policy to produce `ApprovalDecisionSummary`
- it does **not** re-run provider taxonomy to produce queue labels
- it does **not** recover raw payloads that were already excluded by redaction

### Action summary fallback

The checked-in model uses a small fallback rule for `action_summary`:

1. prefer `ApprovalRequest.request.summary`
2. otherwise fall back to `"<action_verb> <target>"` when a target exists
3. otherwise fall back to `action_verb`

This keeps the minimal model renderable even when upstream producers only supply verb + target.

## Why this model is small on purpose

This phase is not the place to solve every operator concern.

The minimal model is enough to unlock later work on:

- queue shaping and de-duplication
- decision cards / reviewer prompts
- rationale capture UX
- notification summaries
- stale / waiting / reconciliation semantics

But it intentionally avoids prematurely baking in:

- stale / drift / waiting-state enums
- reconciliation status machines
- notification delivery state
- provider-specific resume / cancel semantics
- product-specific inbox grouping or pagination contracts

Those stay for later P12 tasks.

## Redaction rule

The control-plane minimal model may carry:

- approval ids, event ids, session ids
- action class / verb / target hints
- redaction-safe attributes from upstream approval requests
- policy reason, severity, scope, TTL, and reviewer hint
- requester context and reviewer rationale

It must **not** carry:

- raw message bodies
- uploaded bytes or file contents
- token values or auth headers
- full request or response payloads
- invite links, participant rosters, or secret contents
- provider-specific opaque blobs that upstream layers intentionally excluded

## Bootstrap preview

`cmd/agent-auditor-controld/src/main.rs` now emits deterministic preview lines for:

- `approval_queue_model=...`
- `approval_queue_item=...`
- `approval_decision_summary=...`
- `approval_rationale_capture=...`

Those bootstrap lines are only a local preview of the checked-in model shape. They are not yet a full approval inbox or reviewer workflow.

## Explicitly out of scope for P12-2

- stale / drift / `waiting_merge` semantics
- reconciliation algorithms
- notification routing or fanout
- UI layout or paging rules
- live provider resume / cancel after approval
- production persistence or multi-process queue coordination
- authorization rules for who may review what

## Related docs

- phase boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- known constraints: [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md)
- ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- status / notification / reconciliation: [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)
- status explanation: [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md)
- audit export: [`approval-control-plane-audit-export.md`](approval-control-plane-audit-export.md)
- architecture overview: [`overview.md`](overview.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- hostd enforcement known constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- messaging boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- generic REST boundary: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- Rust implementation notes: [`rust-implementation.md`](rust-implementation.md)
