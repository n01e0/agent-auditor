# approval / control-plane status explanation

This note fixes the next gap in the approval / control-plane UX slice: making status easier for reviewers and operators to follow without collapsing queue state, notification routing, and reconciliation guidance into one blob.

It builds on:

- [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)

## gap being closed

Before this step, the checked-in control-plane surface had:

- `ApprovalStatusSummary`
- `ApprovalNotificationSummary`
- `ApprovalReconciliationSummary`

That was enough to say **what state the queue item is in**, but still weak at showing:

- **who currently owns the next move**
- **what concrete next step a reviewer or operator should take**
- **which policy rule the current state traces back to**
- **what requester context is still worth carrying forward while staying redaction-safe**

In practice, a reviewer/operator could see `waiting_merge`, `stale_queue`, or `drifted`, but still have to mentally reconstruct why the item exists and who should touch it next.

## checked-in model

`crates/agenta-core/src/controlplane.rs` now adds:

- `ApprovalStatusOwner`
- `ApprovalStatusExplanation`

It also extends `ApprovalDecisionSummary` with:

- `rule_id`

## `ApprovalStatusOwner`

This is the smallest ownership hint needed to follow the current state:

- `reviewer`
- `ops`
- `requester`
- `none`

The goal is not to model org charts or RBAC. It is only to make the next responsible lane explicit.

## `ApprovalStatusExplanation`

`ApprovalStatusExplanation` is the checked-in explanation card for one derived control-plane state.

Fields:

- `owner`
- `summary`
- `next_step`
- `rule_id`
- `policy_reason`
- `reviewer_hint`
- `requester_context`

This is intentionally adjacent to `ApprovalStatusSummary`, not a replacement for it.

### why both exist

- **status summary** answers: “what state is this in?”
- **status explanation** answers: “who owns it, why does it exist, and what should happen next?”

Keeping them separate prevents one string field from becoming an overloaded pseudo-UI contract.

## derivation rules fixed here

The explanation is derived from already-checked-in inputs:

- `ApprovalQueueItem`
- `ApprovalDecisionSummary`
- `ApprovalRationaleCapture`
- `ApprovalOpsHardeningStatus`
- `ApprovalStatusSummary`

It does **not**:

- re-run policy
- invent a second approval record
- recover raw payloads or secret-bearing context
- claim that a live reviewer inbox or background reconciler already exists

### ownership mapping

- `pending_review` -> `reviewer`
- `stale_queue` -> `ops`
- `stale_follow_up` -> `ops`
- `drifted` -> `ops`
- `waiting_downstream` -> `requester`
- `waiting_merge` -> `requester`
- `resolved` -> `none`

### next-step mapping

The explanation keeps a checked-in next-step sentence per state family:

- reviewer-owned pending work points at reviewer action and expiry timing
- stale queue or drifted states point at ops refresh/replay work
- stale follow-up points at rechecking downstream/merge state
- waiting states point at passive follow-up with escalation only if the item later becomes stale
- resolved state makes the absence of required action explicit

## requester context rule

The explanation may carry a compact redaction-safe requester context line built from:

- `human_request`
- `agent_reason`

This preserves “why was this requested?” context without reopening raw payload access.

## bootstrap / smoke contract

`cmd/agent-auditor-controld` now emits deterministic explanation previews alongside the existing status, notification, and reconciliation previews.

Representative lines include:

- `approval_status_summary_pending_review=...`
- `approval_status_explanation_pending_review=...`
- `approval_status_explanation_stale=...`
- `approval_status_explanation_waiting_merge=...`
- `approval_status_explanation_stale_waiting_merge=...`

These lines prove the repository-owned control-plane explanation vocabulary. They do **not** prove a production inbox, reviewer assignment system, or live workflow runner.

## tests fixed here

This step adds coverage in two places:

1. **`agenta-core` unit tests**
   - verify rule id retention in `ApprovalDecisionSummary`
   - verify owner / next-step / requester-context derivation for pending review, waiting merge, and stale follow-up paths

2. **`agent-auditor-controld` smoke test**
   - verifies explanation preview lines for pending review, stale queue, waiting merge, and stale follow-up states

## explicit non-goals

Still out of scope:

- reviewer assignment or escalation policy engines
- notification delivery state machines
- durable control-plane storage
- background reconciliation workers
- live provider resume/cancel automation
- full UI layout decisions

## related docs

- phase boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- minimal model: [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- status / notification / reconciliation: [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)
- audit export: [`approval-control-plane-audit-export.md`](approval-control-plane-audit-export.md)
- local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- known constraints: [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md)
