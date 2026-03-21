# approval / control-plane UX: local runbook

This runbook covers the current local workflow for the repository-wide approval / control-plane UX slice after the boundary, minimal queue model, ops-hardening vocabulary, and status / notification / reconciliation summaries landed.

## What this slice currently proves

The checked-in control-plane path is intentionally small but concrete:

- `agenta-core` exposes repository-owned control-plane types in `crates/agenta-core/src/controlplane.rs`
- the checked-in control-plane model can derive:
  - reviewable queue entries via `ApprovalQueueItem`
  - reviewer-facing summaries via `ApprovalDecisionSummary` and `ApprovalRationaleCapture`
  - ops-hardening state via `ApprovalOpsHardeningStatus`
  - operator-facing status, notification, and reconciliation summaries
- `agent-auditor-controld` can emit deterministic preview lines that show the current queue, stale-queue projection, and `waiting_merge` projection without re-running upstream taxonomy or policy
- the checked-in smoke path proves stale / drift / recovery / waiting-state language plus notification / reconciliation summaries stay stable from the control-plane perspective
- the slice is covered by focused `agenta-core` tests plus a dedicated `agent-auditor-controld` smoke test

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

This workflow does **not** require root today.

It also does **not** require live Slack, Discord, GitHub, or GWS credentials because the current control-plane slice still runs on deterministic preview records rather than a production reviewer inbox, durable database, notification transport, or reconciliation daemon.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-controld --quiet
```

Expected output includes these control-plane categories of lines:

- `approval_queue_model=...`
- `approval_queue_item=...`
- `approval_decision_summary=...`
- `approval_rationale_capture=...`
- `approval_ops_hardening_model=...`
- `approval_ops_hardening_status_stale=...`
- `approval_ops_hardening_status_waiting_merge=...`
- `approval_control_plane_surface_model=...`
- `approval_status_summary_stale=...`
- `approval_notification_summary_stale=...`
- `approval_reconciliation_summary_stale=...`
- `approval_status_summary_waiting_merge=...`
- `approval_notification_summary_waiting_merge=...`
- `approval_reconciliation_summary_waiting_merge=...`

Example shape:

```text
agent-auditor-controld bootstrap
request_id=req_bootstrap_controld action_class=Filesystem
approval_queue_model=components=approval_queue_item,approval_decision_summary,approval_rationale_capture ...
approval_queue_item={...}
approval_ops_hardening_model=components=approval_ops_signals,approval_ops_hardening_status ...
approval_ops_hardening_status_stale={"freshness":"stale","drift":"in_sync","recovery":"refresh_queue_projection","waiting":"reviewer_decision"}
approval_control_plane_surface_model=components=approval_status_summary,approval_notification_summary,approval_reconciliation_summary ...
approval_status_summary_stale={"kind":"stale_queue",...}
approval_notification_summary_stale={"class":"stale_queue_alert","audience":"ops",...}
approval_reconciliation_summary_stale={"state":"needs_queue_refresh",...}
approval_status_summary_waiting_merge={"kind":"waiting_merge",...}
approval_notification_summary_waiting_merge={"class":"waiting_merge_reminder","audience":"requester",...}
approval_reconciliation_summary_waiting_merge={"state":"awaiting_completion",...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the dedicated control-plane smoke test

```bash
cargo test -p agent-auditor-controld --test control_plane_smoke
```

### Run only the control-plane unit tests in `agenta-core`

```bash
cargo test -p agenta-core controlplane:: --lib
```

### Run only the control-plane bootstrap locally

```bash
cargo run -p agent-auditor-controld --quiet
```

### Run the upstream smoke tests that still feed this slice

```bash
cargo test -p agent-auditor-hostd --test messaging_governance_smoke
cargo test -p agent-auditor-hostd --test generic_rest_governance_smoke
cargo test -p agent-auditor-hostd --test github_semantic_governance_smoke
```

The upstream hostd tests still matter because the control-plane slice depends on redaction-safe approval and audit records produced below it.

## Where the current behavior lives

- control-plane phase boundary:
  - `docs/architecture/approval-control-plane-ux-foundation.md`
- minimal queue / summary model:
  - `docs/architecture/approval-control-plane-ux-minimal-model.md`
- stale / drift / recovery / `waiting_merge` vocabulary:
  - `docs/architecture/approval-control-plane-ops-hardening.md`
- status / notification / reconciliation summaries:
  - `docs/architecture/approval-control-plane-status-notification-reconciliation.md`
- shared control-plane types:
  - `crates/agenta-core/src/controlplane.rs`
- control-plane bootstrap preview:
  - `cmd/agent-auditor-controld/src/main.rs`
- dedicated control-plane smoke test:
  - `cmd/agent-auditor-controld/tests/control_plane_smoke.rs`
- upstream approval / audit producers the control-plane slice still depends on:
  - `cmd/agent-auditor-hostd/src/poc/`

## How to interpret the preview outputs honestly

Use this rule when reading the current control-plane bootstrap output:

- if you see `approval_status_summary_stale={...}`, read it as **"the checked-in control-plane model can render a stale queue projection"**, not **"the repository has a production stale-item refresh loop"**
- if you see `approval_notification_summary_stale={...}` or `approval_notification_summary_waiting_merge={...}`, read them as delivery-ready summary shapes, not evidence that an email, DM, webhook, or pager notification was actually sent
- if you see `approval_reconciliation_summary_stale={...}` or `approval_reconciliation_summary_waiting_merge={...}`, read them as reconciliation guidance, not proof of a background reconciliation worker or downstream executor
- if you see `approval_status_summary_waiting_merge={...}`, read it as explicit control-plane waiting-state vocabulary, not proof that a live merge or provider callback was observed

In other words: the current control-plane slice proves that the repository agrees on queue, status, notification, and reconciliation summary shapes. It does **not** yet prove an operator-facing product or live workflow orchestration.

## What to validate before trusting the preview outputs

If you change this path locally, the quickest honest confidence check is:

1. run `cargo test -p agenta-core controlplane:: --lib` to verify the queue, ops-hardening, status, notification, and reconciliation helpers still agree on the checked-in sample cases
2. run `cargo test -p agent-auditor-controld --test control_plane_smoke` to verify the bootstrap preview lines still match the expected control-plane surface
3. run `cargo run -p agent-auditor-controld --quiet` and inspect the preview lines directly if you changed wording or bootstrap examples
4. if your change depends on upstream approval/audit shape, run the relevant `agent-auditor-hostd` smoke tests too

Passing these checks means the repository still agrees on the control-plane preview contract. It still does **not** prove a durable inbox, notification transport, or background reconciler.

## Local persistence path

There is **no dedicated control-plane persistence path yet**.

The current `agent-auditor-controld` bootstrap only prints deterministic preview lines to stdout. It does not create a local queue database, notification outbox, or reconciliation checkpoint store.

## Known constraints

See [`../architecture/approval-control-plane-ux-known-constraints.md`](../architecture/approval-control-plane-ux-known-constraints.md) for the explicit limitations that still apply to this slice.

## When this runbook should change

Update this document when any of the following happens:

- `agent-auditor-controld` stops being a stdout-only bootstrap and begins persisting queue or reconciliation state
- a real reviewer inbox or operator workflow lands
- notification summaries start feeding actual delivery transports
- reconciliation summaries start feeding a real background worker
- the control-plane type surface in `crates/agenta-core/src/controlplane.rs` changes materially
- the smoke test stops being the canonical control-plane preview contract
- live provider resume / cancel or merge-completion callbacks become part of the checked-in slice
