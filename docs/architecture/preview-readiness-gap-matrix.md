# separate-machine audit preview readiness gap matrix

This document freezes the current gap matrix for the **separate-machine audit preview readiness** target.

It takes the responsibility split from [`preview-readiness-boundary.md`](preview-readiness-boundary.md) and turns it into a prioritized view of what is still missing before `agent-auditor` can be evaluated honestly on another Linux machine as an audit preview.

This matrix uses three buckets:

- **must-have**: needed before the separate-machine preview should be treated as ready for real evaluation
- **should-have**: high-value improvements that materially improve the preview, but are not the immediate stop line
- **later**: useful follow-on work that should wait until the preview target itself is stable

## baseline for the A1 track

Before this matrix, the repository already had most of the raw ingredients for an audit preview:

- checked-in preview/bootstrap binaries (`agent-auditor-hostd`, `agent-auditor-controld`, `agent-auditor-cli`)
- focused smoke coverage across runtime, provider, and live-preview slices
- approval/control-plane status vocabulary for stale follow-up, `waiting_merge`, drift, and recovery guidance
- audit/export projection and redaction-safe explanation/rationale persistence
- live preview coverage/failure-posture vocabulary in records
- repository-level deployment minimums for revision pinning, writable paths, and rollback posture
- a dedicated boundary note separating runtime reliability, audit usability, coverage visibility, and deployment guidance for the separate-machine preview target

That means the A1 track is not about inventing a new architecture. It is about making the checked-in preview **reproducible, inspectable, and honest** on another Linux machine.

## preview-readiness gap matrix

| area | already established | must-have | should-have | later |
| --- | --- | --- | --- | --- |
| runtime reliability | checked-in preview binaries, focused smoke tests, initial stale/drift/recovery vocabulary | make `cargo run -p agent-auditor-hostd` and the focused smoke/test path reproducible on another Linux machine; close the biggest stale run / `waiting_merge` / recovery / status-drift pain points that make preview results untrustworthy; ensure preview failures report as explicit degraded or blocked states instead of silent ambiguity | tighter restart/retry guidance per slice; more targeted smoke coverage for recovery paths and artifact persistence; operator-oriented readiness signals beyond raw test success | stronger long-running service supervision, adaptive runtime recovery, and broader non-local/runtime integration hardening |
| audit usability | approval/audit reflection, rationale persistence, audit export projection, redaction-safe explanation schema | make approval / audit / rationale / reviewer-facing summary surfaces consistent enough that an evaluator can inspect local outputs without re-deriving linkage by hand; define the minimum local inspection path for JSONL/export artifacts; keep explanation/rationale/history linkage stable across preview records | richer filtering/summarization for local investigations; more example-driven inspection docs; improved export/report projections for larger preview sessions | long-horizon analytics, cross-run investigation views, and richer operator dashboards |
| coverage visibility | live preview coverage/failure-posture vocabulary, coverage matrix docs, fail-open / unsupported explanations | make docs, records, and smoke expectations agree on what is preview-supported, unsupported, fail-open, or merely modeled intent; ensure per-slice coverage claims are easy to verify from the checked-in docs and reflected record fields; remove wording that could let a second-machine evaluator mistake reflected policy intent for real inline enforcement | more consolidated coverage tables/checklists across slices; sharper operator examples for supported vs unsupported records; stronger smoke assertions that coverage wording stays aligned | future fail-closed subsets, broader enforcement-capable coverage maps, and richer policy/evidence navigation |
| deployment guidance | deployment minimums, README/docs entrypoints, local runbooks, revision-pinned developer workflow | provide one clear separate-machine path for prerequisites, build, run, focused validation, artifact inspection, and cleanup; make writable-path/config expectations explicit enough that another operator does not have to improvise; document the smallest honest rollback/retry workflow for the preview target | environment templates/helpers for repeated preview setup; more explicit troubleshooting and incident-response notes; stronger mapping between runbooks and focused tests | packaging/distribution conventions, container/Kubernetes deployment assets, and multi-environment rollout automation |

## detailed view by priority

### must-have

#### runtime reliability
- make the second-machine preview path reproducible with the checked-in binaries and focused validation commands
- reduce the main trust-breaking runtime pain points around stale run state, `waiting_merge`, recovery, and status drift
- make preview failure/degraded states explicit enough that operators do not confuse setup failure with successful observation

#### audit usability
- keep approval, audit, rationale, and reviewer-facing summary fields coherent across the local preview path
- define the minimum inspection flow for local JSONL/export artifacts
- preserve stable linkage between action, decision, approval, and reflected outcome

#### coverage visibility
- keep preview-supported / unsupported / fail-open wording aligned across docs and records
- make it obvious when a record is showing reflected policy intent rather than realized inline enforcement
- ensure the checked-in coverage claim for each preview slice can be verified from docs plus reflected fields

#### deployment guidance
- document one minimal separate-machine setup path end-to-end
- make prerequisite, writable-path, and artifact-location expectations explicit
- document the smallest honest rollback/retry path for preview evaluation

### should-have

#### runtime reliability
- targeted recovery and restart smoke coverage
- more explicit runtime readiness/debug output for preview operators
- slice-specific guidance for when a preview result is partial but still useful

#### audit usability
- better local filtering and summarization patterns for preview artifacts
- concrete examples that show what to inspect first for approval/audit/rationale review
- export projections that are easier to compare across repeated preview runs

#### coverage visibility
- one consolidated preview checklist spanning docs, smoke tests, and reflected record fields
- clearer examples of unsupported vs preview-supported records
- stronger drift checks that catch coverage wording mismatches earlier

#### deployment guidance
- reusable setup helpers or templates for repeated machine bring-up
- better troubleshooting notes for missing prerequisites or path assumptions
- clearer mapping between README, runbooks, deploy notes, and focused tests

### later

#### runtime reliability
- service-grade supervision and richer health signaling
- adaptive retry/backoff behavior for more realistic external integrations
- broader resilience hardening beyond the current preview loop

#### audit usability
- cross-run dashboards and longer-horizon analysis
- richer operator investigation surfaces
- advanced reporting beyond local preview inspection

#### coverage visibility
- validated fail-closed subsets with stronger enforcement claims
- broader coverage maps that include future live interception paths
- deeper explanation-to-evidence navigation

#### deployment guidance
- canonical packaging/distribution assets
- containerized/shared-environment deployment recipes
- multi-host rollout and lifecycle automation

## mapping to the A1 task sequence

This matrix maps cleanly onto the current A1 task list:

- **A1-3** primarily targets runtime reliability
- **A1-4** and **A1-6** primarily target audit usability
- **A1-5** primarily targets coverage visibility
- **A1-7** and **A1-8** primarily target deployment guidance

That mapping is intentional. The matrix should help keep those PRs narrow instead of re-mixing all preview-readiness concerns.

## review rule for follow-on A1 PRs

A follow-on A1 PR should be able to say two things clearly:

1. which preview-readiness bucket it primarily addresses:
   - runtime reliability
   - audit usability
   - coverage visibility
   - deployment guidance
2. which priority tier it belongs to:
   - must-have
   - should-have
   - later

If a PR cannot state both clearly, it is probably too broad for this preview-readiness track.

## related docs

- `preview-readiness-boundary.md`
- `gap-closing-productization-hardening-foundation.md`
- `gap-closing-gap-matrix.md`
- `deployment-hardening-minimums.md`
- `live-preview-coverage-visibility.md`
- `approval-control-plane-ops-hardening.md`
- `approval-control-plane-audit-export.md`
