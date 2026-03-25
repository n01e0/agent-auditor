# approval / control-plane audit export

This note fixes the next audit-usability gap in the approval / control-plane slice: turning the checked-in queue/status/explanation surfaces into a record/export projection that is easier to search, compare, and hand off without reopening raw request payloads.

It builds on:

- [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md)
- [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md)
- [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)

## gap being closed

Before this step, the repository had:

- `ApprovalQueueItem`
- `ApprovalDecisionSummary`
- `ApprovalRationaleCapture`
- `ApprovalStatusSummary`
- `ApprovalStatusExplanation`
- `ApprovalNotificationSummary`
- `ApprovalReconciliationSummary`

Those shapes were useful individually, but awkward for audit/export workflows because an operator still had to join multiple projections mentally in order to answer basic questions like:

- which approval/policy/event record is this tied to?
- what fields are safe to export or hand to another operator?
- which dimensions are safe to filter on without reopening raw payloads?
- what explanation text should travel with the exported record?

## checked-in model

`crates/agenta-core/src/controlplane.rs` now adds:

- `ApprovalAuditExportRecord`

This is a repository-owned projection for **searchable, export-oriented, redaction-safe** approval audit rows.

## fields carried in the export record

The projection keeps five categories of fields together.

### linkage

- `approval_id`
- `session_id`
- `event_id`
- `rule_id`

These make approval/policy/audit linkage explicit without reopening full upstream inputs.

### searchable dimensions

- `provider_id`
- `action_family`
- `action_class`
- `action_verb`
- `target_hint`
- `severity`
- `scope`
- `status`
- `outcome`
- `status_kind`
- `status_owner`
- `notification_class`
- `notification_audience`
- `reconciliation_state`

These are the minimum checked-in dimensions for operator-friendly filtering and export.

### record-consistency payload

- `reviewer_summary`
- `persisted_rationale`
- `agent_reason`
- `human_request`
- `reviewer_id`

These fields keep the minimum reviewer-facing and rationale-oriented view stable across:

- the stored approval request contract
- `ApprovalLocalJsonlInspectionRecord`
- `ApprovalDecisionSummary`
- `ApprovalRationaleCapture`
- `ApprovalAuditExportRecord`

The rule for this slice is intentionally small:

- the same reviewer-facing summary that appears in local JSONL inspection and queue projection should still be visible in audit/export-oriented output
- the persisted rationale should not disappear when an operator switches from local inspection or queue/rationale views to export-oriented rows
- requester context should stay structured enough that an evaluator does not have to parse a single concatenated string just to compare approval and audit surfaces
- reviewer identity may travel for consistency and handoff, but reviewer freeform notes still stay out of the export row

### timestamps

- `requested_at`
- `resolved_at`
- `expires_at`

### redaction-safe explanation payload

- `explanation_summary`
- `explanation_next_step`
- `policy_reason`
- `reviewer_hint`
- `requester_context`

This explanation payload is intentionally derived from already-redacted control-plane fields.
It remains separate from the record-consistency payload above: explanation answers **"what does the current control-plane state mean now?"**, while the record-consistency fields answer **"what stable reviewer/audit rationale should still line up across records?"**.

## redaction-safe rule

`ApprovalAuditExportRecord` is derived from:

- `ApprovalQueueItem`
- `ApprovalStatusSummary`
- `ApprovalStatusExplanation`
- `ApprovalNotificationSummary`
- `ApprovalReconciliationSummary`

It does **not** carry:

- raw request payloads
- arbitrary action attributes as a whole map
- reviewer freeform notes
- hidden provider-specific evidence blobs

The practical rule is:

- keep the export record useful for auditing
- keep reviewer-facing summary / persisted rationale / requester context stable enough that approval and audit views can be compared directly
- do not widen it into a raw event dump

## why this improves usability

This closes four concrete usability gaps:

1. **record linkage becomes explicit**
   - the export row already carries approval/session/event/rule linkage

2. **search dimensions become stable**
   - operators can filter by provider/action family/severity/status owner without reconstructing them across separate records

3. **reviewer-facing summary and rationale stop disappearing in export**
   - the same reviewer-facing summary / persisted rationale / requester context now remain visible when an operator moves from local JSONL inspection or approval-oriented surfaces to audit/export rows

4. **explanation travels with the export**
   - the exported row already answers “what is this?” and “what happens next?” in redaction-safe form

## bootstrap / smoke contract

`cmd/agent-auditor-controld` now emits deterministic export preview lines alongside the queue/status/explanation surfaces.

Representative lines include:

- `approval_audit_export_model=...`
- `approval_audit_export_pending_review=...`
- `approval_audit_export_waiting_downstream=...`
- `approval_audit_export_waiting_merge=...`
- `approval_audit_export_stale_waiting_merge=...`
- `approval_audit_export_resolved=...`

The matching local-inspection preview is documented in [`../runbooks/approval-jsonl-inspection-local.md`](../runbooks/approval-jsonl-inspection-local.md).

These lines prove that the repository has a checked-in audit/export projection shape.
They do **not** prove a live export API, report builder, warehouse sync, or long-term audit index.

## tests fixed here

This step adds coverage in two places:

1. **`agenta-core` unit tests**
   - verify the export row preserves approval/session/event/rule linkage
   - verify searchable dimensions such as `provider_id` and `action_family`
   - verify reviewer-facing summary / persisted rationale / requester context stay aligned with queue and rationale projections
   - verify the exported explanation remains redaction-safe by excluding raw attribute maps and reviewer notes

2. **`agent-auditor-controld` smoke test**
   - verifies deterministic export rows for pending review, waiting downstream, waiting merge, stale follow-up, and resolved paths
   - verifies the checked-in export model advertises the record-consistency payload explicitly

## explicit non-goals

Still out of scope:

- durable audit storage
- export pagination / sorting APIs
- CSV/Parquet/report generation
- evidence attachment blobs
- advanced analytics or dashboards
- warehouse sync or retention management

## related docs

- status explanation: [`approval-control-plane-status-explanation.md`](approval-control-plane-status-explanation.md)
- status / notification / reconciliation: [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md)
- local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- known constraints: [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md)
