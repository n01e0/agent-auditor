# gap-closing gap matrix

This document freezes the current gap matrix for the gap-closing / productization / hardening phase.

It translates the outcomes from **P1-P14** into a prioritized view of what is still missing, using three buckets:

- **must-have**: required before the system should be treated as dependable for regular operator use
- **should-have**: high-value improvements that make the product materially better, but are not the immediate stop-ship line
- **later**: useful follow-on work that should wait until the must-have / should-have layers are stable

This matrix follows the ownership boundary defined in:

- `docs/architecture/gap-closing-productization-hardening-foundation.md`

## baseline from P1-P14

By the end of P1-P14, the repository has already established:

- provider abstraction and event envelope foundations
- local policy evaluation and decision contracts
- approval-control-plane queue / rationale / summary foundations
- policy authoring model v1
- explanation schema v1
- rationale / reviewer-facing summary persistence in approval records
- local smoke coverage proving the current explanation/rationale path

That means the gap-closing phase is mostly about **operational completeness**, not inventing new core concepts.

## gap matrix

| area | P1-P14 delivered | must-have | should-have | later |
| --- | --- | --- | --- | --- |
| runtime reliability | provider abstraction, event envelope, policy decision contract, approval flow foundations | retry / timeout / failure-mode rules for real integrations; idempotency guarantees for approval/event replay; explicit degraded-mode behavior when control-plane or provider adapters fail | richer runtime health signals; tighter backoff tuning by provider/action class; more targeted recovery controls | adaptive retry heuristics, workload-aware throttling, simulation-driven reliability tuning |
| control-plane UX | queue item foundation, rationale capture, reviewer-facing summary persistence | stable reviewer workflow for approve/deny/hold/expire; queue item summaries that remain consistent across API / CLI / local smoke paths; clear empty/error/loading states | better reviewer hint presentation; richer queue filtering/grouping; operator-focused detail panes and action previews | advanced queue personalization, workflow shortcuts, richer reviewer collaboration surfaces |
| audit usability | audit-oriented record shape foundations, redaction-safe explanation schema, persisted rationale/presentation fields | searchable/filterable audit views by provider/action/severity/outcome/rule; stable retained fields for explanation + rationale; reliable history joins between policy decision, approval request, and outcome | export/reporting-friendly audit projections; richer diff/history rendering for policy-relevant fields | longer-horizon analytics, anomaly summaries, cross-run audit dashboards |
| deployment hardening | local runbooks, known constraints, ops hardening notes, control-plane local smoke | safe config defaults; startup/health/runbook expectations for services; durable storage/migration expectations; secret/env handling rules; explicit rollout/rollback guidance | packaging conveniences, environment templates, bootstrap helpers, more complete operational dashboards | multi-environment orchestration guidance, advanced HA/rollout patterns, deeper infra automation |

## detailed view by priority

### must-have

#### runtime reliability
- document and implement concrete retry/timeout policy for provider + control-plane calls
- define replay/idempotency guarantees for approval and audit-affecting operations
- define stop/continue behavior when one subsystem is partially unavailable

#### control-plane UX
- keep reviewer-facing summary / rationale consistent across stored record, queue projection, and smoke flow
- define the minimum viable reviewer workflow states (`pending`, `approved`, `denied`, `expired`, `held` where applicable)
- ensure failure states are understandable to operators, not just developers

#### audit usability
- define the minimum searchable audit dimensions
- ensure explanation + rationale fields remain redaction-safe and durable
- make approval/policy/audit linkage explicit and stable

#### deployment hardening
- define required env/config knobs and safe defaults
- define service startup, readiness, and rollback expectations
- document storage and migration assumptions before broader rollout

### should-have

#### runtime reliability
- provider/action-specific retry classification
- more targeted fault-injection or resilience smoke coverage
- runtime metrics aligned with operator questions

#### control-plane UX
- better grouping/filtering for approval items
- more explicit reviewer hint rendering
- operator-focused detail projections beyond the current summary/rationale pair

#### audit usability
- export-oriented record projections
- richer presentation of evidence fragments and matched scope
- operator-friendly summarization for large approval histories

#### deployment hardening
- packaging/templates for local-to-shared environment setup
- stronger operational observability guidance
- more explicit incident response playbooks around approval/control-plane failure

### later

#### runtime reliability
- adaptive backoff tuning
- integration-specific circuit breaking strategies
- model-assisted failure diagnosis

#### control-plane UX
- collaborative reviewer workflows
- personalized queues
- richer explanation-to-action navigation

#### audit usability
- long-term trend analytics
- cross-provider investigation dashboards
- advanced audit summarization/reporting layers

#### deployment hardening
- HA/multi-region guidance
- full environment promotion automation
- broader production topology recipes

## mapping back to P1-P14 outputs

The gap-closing phase should treat these prior outputs as fixed inputs:

- **P1-P4 style foundations** → provider abstraction / envelope / contract layers
- **P5-P9 style control-plane work** → queue/status/reconciliation/ops notes
- **P10-P14 style explainability work** → authoring model / explanation schema / rationale persistence / smoke coverage

The practical rule is:

- do not reopen foundational contract debates unless a must-have gap proves they are insufficient
- prefer adding operational completeness around those contracts first

## review rule for follow-on PRs

A P15 follow-on PR should say which bucket it primarily addresses:

- runtime reliability
- control-plane UX
- audit usability
- deployment hardening

And which priority it belongs to:

- must-have
- should-have
- later

If the PR cannot state both clearly, it is probably mixing concerns and should be split.

## related docs

- `gap-closing-productization-hardening-foundation.md`
- `deployment-hardening-minimums.md`
- `approval-control-plane-ux-foundation.md`
- `approval-control-plane-ops-hardening.md`
- `policy-authoring-explainability-foundation.md`
- `policy-authoring-explainability-known-constraints.md`
