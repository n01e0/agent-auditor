# separate-machine audit preview readiness boundary

This note defines the boundary for the current **separate-machine audit preview** target.

The goal is intentionally narrow:

- keep `agent-auditor` honest about what another Linux machine can evaluate today
- make it possible to run `cargo run -p agent-auditor-hostd` and focused validation on that machine
- separate follow-on work into reviewable buckets instead of mixing runtime fixes, record semantics, coverage claims, and deployment advice in one PR

This boundary exists for the A1 preview-readiness track. It is narrower than the broader gap-closing phase.

## preview target

The current preview target is:

- a second Linux machine can build the checked-in revision
- that machine can run the checked-in preview/bootstrap binaries, especially `agent-auditor-hostd`
- focused tests and smoke checks can reproduce the checked-in contract on that machine
- an evaluator can inspect approval / audit / record outputs and tell what the repository is modeling today
- an evaluator can tell the difference between:
  - preview-supported vs unsupported
  - fail-open vs any future fail-closed claim
  - runtime behavior vs reflected audit intent
- the setup / validation / cleanup path is documented tightly enough that another operator does not have to reverse-engineer the repository layout

This target is an **audit preview**, not a production claim.

It does **not** mean:

- validated inline interception on live traffic
- production-ready approval workflow UX
- durable multi-host control-plane deployment
- complete provider coverage
- stable packaging or upgrade automation

## why this split is different from the broader gap-closing phase

[`gap-closing-productization-hardening-foundation.md`](gap-closing-productization-hardening-foundation.md) splits the broader phase into runtime reliability, control-plane UX, audit usability, and deployment hardening.

For the separate-machine audit preview target, the immediate question is slightly different:

- can another machine run the preview consistently?
- can an evaluator trust what the records are saying?
- can an evaluator tell what coverage is real, preview-only, or unsupported?
- can they follow the setup/run/cleanup path without guesswork?

That is why this preview-readiness boundary uses these four responsibilities instead:

- **runtime reliability**
- **audit usability**
- **coverage visibility**
- **deployment guidance**

`control-plane UX` still matters to the broader product, but it is not the primary gating lens for this preview target. Until the repository is trying to ship a fuller reviewer-facing workflow, the more urgent requirement is to make the preview reproducible and honest.

## responsibility split

### 1. runtime reliability

Runtime reliability owns whether the checked-in preview behaves predictably on another Linux machine.

It owns:

- successful startup/shutdown of the checked-in preview binaries
- deterministic or well-bounded preview/bootstrap behavior for the current slices
- focused test and smoke reproducibility on a second machine
- restart, stale-state, recovery, and status-drift handling where those affect whether the preview can be trusted to keep running
- writable-path behavior for local preview artifacts
- failure reporting when a preview path cannot complete honestly

It does **not** own:

- how audit history should be summarized for an investigator
- the wording of coverage/fail-open explanations beyond the minimum runtime facts
- step-by-step deployment/setup instructions

### 2. audit usability

Audit usability owns whether a human can inspect the current preview outputs and understand what happened.

It owns:

- stable linkage between normalized event, policy decision, approval request, and reflected outcome
- reviewer/operator-facing record fields that explain why an action was allowed, denied, or marked approval-required
- export-oriented or reviewer-facing summary fields that make local records useful during preview evaluation
- redaction-safe retained fields for explanation, rationale, and operator review
- consistency between stdout preview examples and persisted record shapes where those are meant to describe the same event

It does **not** own:

- startup/readiness/restart behavior of the binaries
- the canonical distinction between preview-supported and unsupported coverage
- packaging, host prerequisites, or rollback steps

### 3. coverage visibility

Coverage visibility owns the honesty layer around what the preview means.

It owns:

- the distinction between preview-supported, unsupported, and future stricter coverage claims
- fail-open / fail-closed vocabulary for records and docs
- explicit record/docs markers for preview-only behavior vs realized runtime effect
- consistent operator-facing wording for coverage gaps, unsupported paths, and modeled-but-not-enforced actions
- alignment between coverage matrices, runbooks, and reflected audit fields

It does **not** own:

- retry/backoff/state-recovery mechanics
- audit linkage or export ergonomics beyond the coverage-specific fields
- host setup, install steps, or rollback packaging guidance

### 4. deployment guidance

Deployment guidance owns how another machine is expected to reproduce the preview safely.

It owns:

- host prerequisites and build expectations
- exact binaries/commands used for the preview target
- where writable state should live during evaluation
- startup/readiness/validation/cleanup steps an operator follows on another machine
- revision pinning, rollback expectations, and environment/config notes needed to avoid footguns
- the runbook path that turns repository docs into a repeatable preview exercise

It does **not** own:

- whether the runtime itself handles failures correctly once started
- the meaning of audit/export fields
- the truthfulness of coverage labels beyond preserving and documenting them

## primary review rule for follow-on A1 work

A follow-on A1 PR should be able to name one primary bucket:

- runtime reliability
- audit usability
- coverage visibility
- deployment guidance

A PR may touch neighboring layers, but if it tries to redefine all four at once, it is probably too broad.

## artifact map for this preview target

When deciding where a change belongs, use this map first.

### runtime reliability

Usually lives in:

- `cmd/agent-auditor-hostd/`
- `cmd/agent-auditor-controld/`
- runtime-focused smoke tests
- state/recovery notes tied to actual preview execution behavior

### audit usability

Usually lives in:

- record/approval/audit reflection code
- export/summary/explanation surfaces
- docs that describe how to inspect persisted preview artifacts

### coverage visibility

Usually lives in:

- coverage matrices
- failure-behavior docs
- live preview mode / record reflection docs
- operator-facing coverage fields in records and smoke fixtures

### deployment guidance

Usually lives in:

- `README.md`
- `README_ja.md`
- `docs/runbooks/`
- deployment notes under `docs/architecture/` and `deploy/`

## preview-readiness exit question

Before saying the separate-machine preview is ready to evaluate, an operator should be able to answer these four questions without guesswork:

1. **runtime reliability** — does the checked-in preview run and reproduce focused validation on another Linux machine?
2. **audit usability** — can I inspect the resulting records and understand the action, decision, approval linkage, and summary?
3. **coverage visibility** — can I tell what is supported preview, unsupported, fail-open, or merely modeled intent?
4. **deployment guidance** — can I set up, validate, and clean up the preview from the docs alone?

If any one of those answers is still "not really", the preview target is not ready yet.

## explicit non-goals for this boundary task

This task does **not** define:

- the full gap matrix or its must-have / should-have / later prioritization
- the concrete runtime fixes for stale run / waiting_merge / recovery / drift
- the final export/rationale/reviewer-summary shape
- the final separate-machine deployment recipe
- any production enforcement claim

It only fixes the responsibility seams for the preview-readiness work.

## related docs

- gap-closing foundation: [`gap-closing-productization-hardening-foundation.md`](gap-closing-productization-hardening-foundation.md)
- preview gap matrix: [`preview-readiness-gap-matrix.md`](preview-readiness-gap-matrix.md)
- broader gap matrix: [`gap-closing-gap-matrix.md`](gap-closing-gap-matrix.md)
- deployment minimums: [`deployment-hardening-minimums.md`](deployment-hardening-minimums.md)
- coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- architecture overview: [`overview.md`](overview.md)
