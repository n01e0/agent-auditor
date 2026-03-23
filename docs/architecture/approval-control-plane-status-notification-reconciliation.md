# approval / control-plane status, notification, and reconciliation

This note fixes the checked-in improvement set for control-plane status surfaces, notification summaries, and reconciliation summaries.

It sits on top of:

- [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)

## Goal of P12-4

Make the control-plane slice usable for operator-facing status and notification work without pretending that a full reviewer inbox or production reconciliation worker already exists.

The immediate improvement points are:

1. **status surfaces should be reviewer-readable**
   - queue + ops-hardening facts should condense into a stable status headline, detail line, and actionable bit
2. **notifications should be delivery-ready**
   - the control plane should be able to derive a small notification summary without re-reading raw upstream records
3. **reconciliation should be summarized separately from UI status**
   - operators need a concise “what does the control plane think should happen next?” summary that is distinct from end-user messaging
4. **tests should exercise the control-plane view directly**
   - not just upstream governance layers or individual unit helpers

## Checked-in model surface

The repository now adds these control-plane-facing types in `crates/agenta-core/src/controlplane.rs`:

- `ApprovalStatusKind`
- `ApprovalStatusSummary`
- `ApprovalNotificationClass`
- `ApprovalNotificationAudience`
- `ApprovalNotificationSummary`
- `ApprovalReconciliationState`
- `ApprovalReconciliationSummary`

The follow-on ownership / next-step explanation layer is documented separately in [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md).

These are derived from:

- `ApprovalQueueItem`
- `ApprovalOpsHardeningStatus`

That keeps the ownership split honest:

- queue derivation still comes from the minimal model
- stale / drift / recovery / waiting semantics still come from the ops-hardening layer
- status / notification / reconciliation summaries sit on top as operator-facing projections

## Status improvements fixed here

`ApprovalStatusSummary` is the first stable operator-facing status card.

It currently owns:

- `kind`
- `headline`
- `detail`
- `actionable`

The checked-in `ApprovalStatusKind` values are:

- `pending_review`
- `stale_queue`
- `stale_follow_up`
- `drifted`
- `waiting_downstream`
- `waiting_merge`
- `resolved`

This keeps four important distinctions visible:

- an item can be **pending review** and actionable
- an item can be **stale** or **drifted**, which should block casual reviewer action even when the queue entry still exists
- an item can be **approved and waiting** on downstream completion or merge-like follow-up
- an item can be **approved but stale in follow-up**, which should route back to ops recheck rather than passive requester waiting

## Notification improvements fixed here

`ApprovalNotificationSummary` is the first delivery-ready control-plane summary.

It currently owns:

- `class`
- `audience`
- `headline`
- `status_line`

The checked-in `ApprovalNotificationClass` values are:

- `review_required`
- `stale_queue_alert`
- `stale_follow_up_alert`
- `drift_alert`
- `waiting_downstream_reminder`
- `waiting_merge_reminder`
- `resolution_update`

The checked-in `ApprovalNotificationAudience` values are:

- `reviewer`
- `ops`
- `requester`

This is intentionally small, but it already fixes a useful rule:

- **review prompts**, **ops alerts**, and **requester updates** are different control-plane outputs and should not be conflated into one generic “notification” blob

## Reconciliation improvements fixed here

`ApprovalReconciliationSummary` is the first control-plane-facing summary for “what needs to happen next to make the current view consistent?”

It currently owns:

- `state`
- `note`

The checked-in `ApprovalReconciliationState` values are:

- `in_sync`
- `needs_queue_refresh`
- `needs_audit_replay`
- `needs_downstream_refresh`
- `awaiting_completion`

This is deliberately smaller than a future reconciler state machine, but it fixes a clear separation:

- **status summary** answers “what should the operator see right now?”
- **notification summary** answers “what message should be delivered, and to whom?”
- **reconciliation summary** answers “what consistency action or follow-up is implied by the current control-plane state?”

## Derivation priorities

The checked-in derivation logic uses these priorities:

1. **drift dominates status**
   - if durable audit or decision evidence is missing, the item becomes `drifted`
2. **stale queue state is visible even without durable drift**
   - stale queue projections become `stale_queue`
3. **waiting states remain explicit after approval**
   - `waiting_merge` stays separate from generic downstream completion
4. **notifications follow the derived status**
   - drift -> ops alert
   - stale queue -> stale queue alert
   - stale follow-up -> ops alert
   - pending review -> reviewer prompt
   - waiting downstream -> requester reminder
   - waiting merge -> requester reminder
   - resolved -> requester resolution update
5. **reconciliation follows recovery semantics**
   - replay from audit -> `needs_audit_replay`
   - refresh queue projection -> `needs_queue_refresh`
   - recheck downstream state -> `needs_downstream_refresh`
   - await downstream completion -> `awaiting_completion`
   - none needed -> `in_sync`

## Bootstrap preview

`cmd/agent-auditor-controld/src/main.rs` now emits deterministic preview lines for:

- `approval_control_plane_surface_model=...`
- `approval_status_summary_stale=...`
- `approval_notification_summary_stale=...`
- `approval_reconciliation_summary_stale=...`
- `approval_status_summary_waiting_merge=...`
- `approval_notification_summary_waiting_merge=...`
- `approval_reconciliation_summary_waiting_merge=...`
- `approval_status_summary_stale_waiting_merge=...`
- `approval_notification_summary_stale_waiting_merge=...`
- `approval_reconciliation_summary_stale_waiting_merge=...`

These previews prove that the repository has a stable control-plane vocabulary for status, notification, and reconciliation summaries.

They do **not** yet prove:

- a production reviewer inbox
- notification delivery transports
- background reconciliation workers
- provider resume / cancel integration

## Control-plane tests added here

P12-4 adds two layers of control-plane tests:

1. **`agenta-core` unit tests**
   - verify status derivation for pending, drifted, stale, stale-follow-up, and waiting-merge cases
   - verify notification audience/class routing
   - verify reconciliation summaries track recovery semantics

2. **`agent-auditor-controld` smoke test**
   - runs the control-plane bootstrap binary
   - verifies the deterministic preview lines for queue, ops hardening, status, notification, and reconciliation outputs
   - checks that stale, `waiting_merge`, and stale-follow-up projections remain stable from the control-plane perspective

## Still out of scope

This note does **not** yet add:

- real delivery transports for notifications
- persistent materialized status views
- a full reconciliation daemon
- SLA/escalation logic for unresolved items
- reviewer UI layout or workflow design
- production authz around who receives which notifications

## Related docs

- phase boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- known constraints: [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md)
- minimal model: [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- status explanation: [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md)
- architecture overview: [`overview.md`](overview.md)
- Rust implementation notes: [`rust-implementation.md`](rust-implementation.md)
