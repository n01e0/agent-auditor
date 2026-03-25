# approval JSONL inspection local runbook

This runbook is the smallest path for checking **local approval JSONL artifacts** against the checked-in **audit export** and **redaction-safe explanation** contract.

Use it when you want to answer:

- what reviewer-facing summary is preserved in `approval-requests.jsonl`?
- what rationale / requester context stays visible in local inspection?
- which fields should still line up with `ApprovalAuditExportRecord`?
- what counts as the redaction-safe explanation summary for local JSONL review?

## baseline validation

Run the repository baseline first:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

## 1. emit the checked-in local inspection preview

Run:

```bash
cargo run -p agent-auditor-hostd --quiet | rg '^approval_local_jsonl_inspection_model=|^persisted_messaging_local_jsonl_inspection_require_approval='
```

Expected output includes:

- `approval_local_jsonl_inspection_model=...`
- `persisted_messaging_local_jsonl_inspection_require_approval=...`

The current checked-in inspection record is `ApprovalLocalJsonlInspectionRecord`.

It keeps these local-inspection fields stable:

- `approval_id`
- `event_id`
- `rule_id`
- `reviewer_summary`
- `persisted_rationale`
- `agent_reason`
- `human_request`
- `reviewer_hint`
- `explanation_summary`
- `explanation_source`

## 2. inspect the raw JSONL directly

For any approval-producing hostd slice, inspect `approval-requests.jsonl` with:

```bash
jq -c '{
  approval_id,
  event_id,
  reviewer_summary: .presentation.reviewer_summary,
  persisted_rationale: (.presentation.rationale // .policy.reason),
  agent_reason: .requester_context.agent_reason,
  human_request: .requester_context.human_request,
  reviewer_hint: .policy.reviewer_hint
}' path/to/approval-requests.jsonl
```

This is the raw-file equivalent of the checked-in local inspection record.

The current rule is intentionally small:

- `reviewer_summary` comes from the reviewer-facing presentation when present
- `persisted_rationale` comes from the persisted rationale / policy reason
- `explanation_summary` for local inspection is redaction-safe and prefers `persisted_rationale`
- when persisted rationale is missing, local inspection falls back to `reviewer_summary`

That fallback is surfaced as `explanation_source`:

- `persisted_rationale`
- `reviewer_summary_fallback`

## 3. compare local JSONL inspection to audit export

Run the checked-in control-plane export preview:

```bash
cargo run -p agent-auditor-controld --quiet | rg '^approval_audit_export_pending_review=|^approval_audit_export_waiting_merge=|^approval_audit_export_resolved='
```

For the minimum consistency check, compare these pairs:

- local `reviewer_summary`
  ↔ export `reviewer_summary`
- local `persisted_rationale`
  ↔ export `persisted_rationale`
- local `agent_reason` / `human_request`
  ↔ export `agent_reason` / `human_request`
- local `reviewer_hint`
  ↔ export `reviewer_hint`

The export record adds control-plane-only fields such as:

- `status_kind`
- `status_owner`
- `notification_class`
- `reconciliation_state`
- `explanation_next_step`

Those are not expected to exist in raw local JSONL inspection.

## 4. read redaction-safe explanation correctly

For local JSONL review, treat:

- `explanation_summary`
- `explanation_source`

as the smallest redaction-safe explanation contract.

It means:

- the local inspection view should explain *why this approval exists* without exposing raw payload blobs
- the summary should stay comparable to the export-oriented view
- reviewer freeform notes are still excluded from the local inspection contract

## current limits

This runbook does **not** prove:

- a durable audit database or export API
- cross-file joins across all JSONL artifacts automatically
- a production review UI
- live downstream reconciliation from the local JSONL alone

It only proves that the repository keeps a stable, redaction-safe local inspection view that can be compared directly to the checked-in export model.

## related docs

- [`approval-control-plane-audit-export.md`](../architecture/approval-control-plane-audit-export.md)
- [`approval-control-plane-ux-local.md`](approval-control-plane-ux-local.md)
- [`policy-authoring-explainability-local.md`](policy-authoring-explainability-local.md)
