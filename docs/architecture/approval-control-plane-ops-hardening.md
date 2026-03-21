# approval / control-plane ops hardening

This note fixes the first checked-in hardening vocabulary for stale state, drift, recovery, and `waiting_merge` handling in the operator-facing approval / control-plane slice.

It sits on top of:

- [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)

## Goal of P12-3

Make the control-plane layer explicit about four operational questions that should not stay implicit in ad hoc runners or reviewer intuition:

1. **Is this queue item fresh enough to trust?**
2. **Does queue state still agree with durable approval / audit facts?**
3. **What recovery action should the operator or control plane take next?**
4. **Is this item still waiting on reviewer input, downstream completion, or merge-like follow-up?**

The immediate rule is:

- stale-ness is a **freshness** concern
- disagreement between queue state and durable records is a **drift** concern
- the next operator/control-plane action is a **recovery** concern
- unresolved post-decision work is a **waiting-state** concern

Those concerns can be related, but they are not interchangeable.

## Checked-in model surface

The first checked-in Rust surface lives in:

- `crates/agenta-core/src/controlplane.rs`

P12-3 adds these operator-facing control-plane types:

- `ApprovalOpsSignals`
- `ApprovalQueueFreshness`
- `ApprovalQueueDrift`
- `ApprovalRecoveryAction`
- `ApprovalWaitingState`
- `ApprovalOpsHardeningStatus`

## Why signals are explicit

The checked-in model does **not** hardcode one global timeout or deployment policy for stale detection.

Instead, it accepts a small set of control-plane facts through `ApprovalOpsSignals`:

- `stale`
- `audit_record_present`
- `decision_record_present`
- `downstream_completion_recorded`
- `requires_merge_follow_up`

This keeps the ownership split honest:

- deployments can choose their own stale threshold / freshness heuristic
- append-only audit or downstream reconcilers can decide whether the durable records they expect are present
- the checked-in model stays responsible only for surfacing the resulting control-plane semantics consistently

## Hardening vocabulary

### `ApprovalQueueFreshness`

Values:

- `fresh`
- `stale`
- `expired`

Interpretation:

- `fresh` means the queue item is not currently marked stale
- `stale` means the queue projection is old enough that an operator should treat it carefully, even if the item is still pending
- `expired` means the upstream approval status already reached `expired`; this is stronger than “stale”

### `ApprovalQueueDrift`

Values:

- `in_sync`
- `missing_audit_record`
- `missing_decision_record`
- `missing_downstream_completion`

Interpretation:

- `missing_audit_record` means the queue item exists, but the corresponding durable audit evidence is missing from the control-plane view
- `missing_decision_record` means the queue item reflects a reviewer outcome, but the durable decision evidence is not present where the control plane expects it
- `missing_downstream_completion` means approval resolution exists, but the control plane still lacks the downstream completion signal it expects before considering the flow fully done

This is deliberately narrower than a full reconciliation engine. It is the first stable vocabulary, not the final state machine.

### `ApprovalRecoveryAction`

Values:

- `none_needed`
- `refresh_queue_projection`
- `replay_from_audit`
- `await_downstream_completion`

Interpretation:

- `refresh_queue_projection` is for stale queue state that should be re-materialized from known append-only inputs
- `replay_from_audit` is for drift where the queue no longer agrees with durable approval / audit facts
- `await_downstream_completion` is for cases where the decision is already made, but merge-like or delivery-like follow-up has not finished yet

The recovery action is operational guidance, not a provider-specific retry command.

### `ApprovalWaitingState`

Values:

- `reviewer_decision`
- `downstream_completion`
- `waiting_merge`
- `resolved`

Interpretation:

- `reviewer_decision` means the queue item is still pending human review
- `downstream_completion` means a decision exists, but the control plane still expects a completion / reconciliation signal
- `waiting_merge` is the explicit subset of downstream waiting where the follow-up is merge-like rather than generic runtime completion
- `resolved` means there is no remaining reviewer or downstream waiting state in the current control-plane view

## `waiting_merge` semantics

`waiting_merge` is fixed here as a **control-plane waiting state**, not a hidden property of one specific runner.

Use `waiting_merge` when:

- the approval or review decision is already recorded
- the remaining follow-up is a merge-like or externally finalized action
- the control plane should show the item as waiting on that follow-up rather than pretending it is fully complete

Do **not** use `waiting_merge` to mean:

- the item is still pending reviewer action
- the queue is stale
- policy has not run yet
- a provider-specific runtime retry is required

This keeps “approved but not yet fully landed” separate from both stale queue data and unresolved reviewer work.

## Derivation rules fixed by P12-3

The checked-in helper `ApprovalOpsHardeningStatus::derive(...)` uses the following priority rules:

1. **Freshness**
   - `expired` if the upstream approval status is already `expired`
   - otherwise `stale` if the control-plane signals say the queue item is stale
   - otherwise `fresh`

2. **Drift**
   - missing durable audit evidence wins first
   - then missing durable decision evidence when reviewer outcome is already reflected
   - then missing downstream completion for approved items
   - otherwise `in_sync`

3. **Waiting state**
   - `reviewer_decision` for pending items
   - `waiting_merge` for approved items that still require merge-like follow-up
   - `downstream_completion` for approved items that still lack generic downstream completion
   - otherwise `resolved`

4. **Recovery action**
   - replay from audit for durable drift
   - await downstream completion for merge-like or downstream waiting
   - refresh queue projection for stale pending items without durable drift
   - otherwise no action is needed

These are intentionally conservative operator semantics, not proof of a full distributed reconciliation implementation.

## Bootstrap preview

`cmd/agent-auditor-controld/src/main.rs` now emits deterministic preview lines for:

- `approval_ops_hardening_model=...`
- `approval_ops_hardening_status_stale=...`
- `approval_ops_hardening_status_waiting_merge=...`

Those lines prove the repository-owned vocabulary and example derivation paths. They do **not** yet prove a full production control-plane reconciler.

## What this fixes now

P12-3 makes these statements stable across code and docs:

- stale queue state is not the same thing as drift
- drift is not the same thing as waiting for merge-like completion
- `waiting_merge` is a first-class control-plane state, not an out-of-band runner convention
- recovery guidance should be derived from queue + durable-state signals, not from provider-specific heuristics
- merge-like follow-up and generic downstream completion are both explicit waiting states instead of hidden operator tribal knowledge

## What still remains for later P12 work

This note does **not** yet add:

- a full reconciliation worker
- notification fanout for stale / drift / waiting states
- persistent status materialization beyond the preview bootstrap
- a production operator inbox
- live provider resume / cancel integration after approval resolution
- durable SLA / escalation policy for stale items

Those stay for P12-4 and P12-5.

## Related docs

- phase boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- minimal model: [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- architecture overview: [`overview.md`](overview.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- hostd enforcement known constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- Rust implementation notes: [`rust-implementation.md`](rust-implementation.md)
