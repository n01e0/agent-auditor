# approval / control-plane UX: known constraints

This note records the current constraints of the repository-wide approval / control-plane UX slice.

## Current limitations

1. **The control plane is still a deterministic bootstrap, not a product workflow**
   - `agent-auditor-controld` currently emits deterministic preview lines to stdout
   - there is no durable queue backend, reviewer inbox service, or long-running operator control plane yet
   - the slice proves a repository-owned contract, not a full operator-facing product

2. **The control-plane slice still depends on upstream preview producers**
   - queue, status, notification, and reconciliation summaries still derive from `ApprovalRequest` and related approval/audit metadata produced upstream
   - the control-plane layer does not independently observe provider activity, classify actions, or re-run policy
   - if upstream redaction-safe approval records change, the control-plane slice must follow that contract

3. **Coverage is still driven by one checked-in sample request path**
   - the bootstrap and smoke path currently centers on a single messaging-style `channel.invite` approval example plus stale and `waiting_merge` projections
   - this is enough to stabilize the control-plane vocabulary
   - it is not enough to claim comprehensive coverage across all approval-producing domains

4. **There is no reviewer inbox or decision-taking UI yet**
   - `ApprovalQueueItem`, `ApprovalDecisionSummary`, and `ApprovalRationaleCapture` define the shape of reviewable work
   - they do not yet come with list/filter/paging UX, approval forms, defer flows, bulk actions, or reviewer routing logic

5. **Notification support stops at summary derivation**
   - `ApprovalNotificationSummary` can classify notifications as reviewer prompts, ops alerts, requester reminders, or resolution updates
   - there is no email, chat, webhook, pager, or mobile delivery implementation behind those summaries yet
   - the repository proves delivery-ready summary shape, not notification transport

6. **Reconciliation support stops at summary derivation**
   - `ApprovalReconciliationSummary` can describe states like `needs_queue_refresh`, `needs_audit_replay`, and `awaiting_completion`
   - there is no background reconciliation worker, retry scheduler, durable checkpoint store, or replay engine yet
   - the repository proves reconciliation vocabulary, not a reconciliation subsystem

7. **`waiting_merge` is explicit vocabulary, not live merge tracking**
   - `waiting_merge` is now a checked-in control-plane waiting state
   - it does not yet mean the control plane has integrated with real GitHub merge callbacks, workflow completion hooks, or downstream runtime handoff acknowledgements
   - it is still a derived state in the preview contract

8. **Freshness and drift signals are externally supplied heuristics today**
   - `ApprovalOpsSignals` carries booleans like `stale`, `audit_record_present`, and `decision_record_present`
   - the repository does not yet fix a universal stale threshold, drift detector, or deployment-wide reconciliation policy
   - deployments or future workers still need to decide how those signals are produced

9. **Reviewer identity and authorization are still shallow**
   - the current slice can carry reviewer ids and reviewer notes as strings
   - it does not yet prove reviewer authn/authz, policy-controlled reviewer assignment, escalation ownership, or tenant isolation

10. **No live provider resume / cancel / finalize path exists yet**
    - the control-plane slice can summarize pending review, stale queue state, drift, and `waiting_merge`
    - it does not yet drive live provider resume / cancel callbacks for Slack, Discord, GitHub, GWS, filesystem, process, or other surfaces
    - decisions are still represented as repository-owned records and summaries, not runtime orchestration

11. **There is no dedicated control-plane persistence store yet**
    - `agent-auditor-controld` does not currently create a queue database, notification outbox, or reconciliation ledger
    - unlike some hostd PoC slices, there is no control-plane JSONL or local store directory to inspect
    - the control-plane bootstrap is stdout-only today

12. **Smoke coverage is deterministic by design**
    - `cmd/agent-auditor-controld/tests/control_plane_smoke.rs` validates the bootstrap preview contract for queue, ops-hardening, status, notification, and reconciliation lines
    - `agenta-core` unit tests validate derivation behavior for pending, stale, drifted, and `waiting_merge` cases
    - none of this is evidence of a deployed reviewer workflow, notification service, or reconciliation daemon operating against live approval traffic

13. **The slice is still intentionally single-node and single-process in spirit**
    - the current checked-in path does not address distributed locking, concurrent reviewers, optimistic concurrency, replication, or HA control-plane coordination
    - those concerns are intentionally postponed rather than implied by the existence of the summary models

## Practical interpretation

Today’s approval / control-plane UX slice is good for:

- fixing ownership between upstream approval/audit producers and downstream operator-facing summaries
- proving repository-owned Rust types for queue, summary, hardening, notification, and reconciliation concepts
- proving deterministic bootstrap output for the current control-plane vocabulary
- giving future reviewer inbox, notification, and reconciliation work a stable contract to build on
- documenting `waiting_merge` as a first-class control-plane concern rather than hidden runner folklore

It is **not yet** good evidence of:

- a production reviewer inbox
- durable control-plane persistence
- real notification delivery
- a background reconciliation engine
- live provider resume / cancel workflows
- reviewer authorization and escalation policy
- distributed or multi-tenant control-plane behavior

## Related docs

- phase boundary: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- minimal model: [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- status / notification / reconciliation: [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)
- local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- architecture overview: [`overview.md`](overview.md)
- hostd enforcement known constraints: [`hostd-enforcement-known-constraints.md`](hostd-enforcement-known-constraints.md)
- messaging known constraints: [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md)
