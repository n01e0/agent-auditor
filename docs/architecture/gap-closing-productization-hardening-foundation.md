# gap-closing phase boundary

This note defines the boundary for the gap-closing / productization / hardening phase.

The goal of this phase is not to invent a new policy model. It is to close the operational and product gaps around the existing evaluator, control-plane, audit, and deployment surfaces so the repository can behave like a reliable system instead of a collection of isolated foundations.

## phase goal

The phase is split into four responsibilities:

- **runtime reliability**
- **control-plane UX**
- **audit usability**
- **deployment hardening**

These responsibilities interact, but they should not collapse into one workstream.

## boundary contract

### 1. runtime reliability

Runtime reliability owns whether the system behaves correctly and predictably while it is running.

It owns:

- retry / timeout / backoff policy for runtime integrations
- idempotency and dedupe expectations for repeated events or policy decisions
- failure-mode handling for control-plane actions and provider adapters
- state transition safety for approval / deny / hold flows
- health checks, error propagation, and resilience behavior in local and service runtimes

It does **not** own:

- reviewer wording or queue presentation
- audit record usability and operator search design
- installation packaging, secrets distribution, or deployment topology

### 2. control-plane UX

Control-plane UX owns what an operator or reviewer sees and acts on in the control plane.

It owns:

- approval queue readability
- reviewer-facing summaries, rationale presentation, and action labels
- reviewer workflows for allow / deny / hold / expire / retry class decisions
- local smoke examples that prove human-facing operator flows remain coherent

It does **not** own:

- core runtime retry semantics
- raw audit storage design
- deployment bootstrap / secret management / rollout strategy

### 3. audit usability

Audit usability owns whether captured policy and approval data can be interpreted, filtered, and reviewed after the fact.

It owns:

- stable audit-facing record shape
- operator-readable event / approval history fields
- search/filter dimensions for policy, rationale, severity, provider, action, and outcome
- redaction-safe audit detail and explanation retention rules

It does **not** own:

- reviewer queue interaction design
- runtime retry / recovery policy
- deployment packaging or infra hardening

### 4. deployment hardening

Deployment hardening owns whether the system can be run safely and repeatedly outside the local dev loop.

It owns:

- config defaults and env handling that are safe enough for real deployment
- service bootstrap expectations
- persistence / migration / rollout safety constraints
- production-facing runbooks and operational constraints
- security posture for exposed processes, credentials, and local state

It does **not** own:

- reviewer-facing copy
- policy explanation schema itself
- audit projection semantics beyond what deployment must preserve safely

## code ownership guidance

### `crates/agenta-policy`

Owns policy evaluation behavior and decision projection inputs.

In this phase it may participate in runtime reliability work, but it should not become the place that owns reviewer UI behavior or deployment policy.

### `crates/agenta-core`

Owns shared contracts crossing runtime, control-plane, and audit boundaries.

In this phase it is the natural home for:

- runtime-safe shared types
- reviewer-facing record contracts
- audit-facing record contracts

But it should not absorb service-specific rollout logic.

### `crates/agenta-core::controlplane`

Owns operator/reviewer-facing projections.

It should absorb queue/readability improvements and approval summary shaping, while leaving retry semantics and deployment concerns elsewhere.

### `cmd/*`

Own service/runtime entrypoints.

They are where deployment hardening and runtime integration behavior show up concretely, but they should continue consuming shared contracts rather than inventing conflicting local formats.

## why this split matters now

Without this split, follow-on tasks tend to blur together:

- runtime retries get mixed with reviewer UX wording
- audit shape gets mixed with temporary smoke output
- deployment defaults get mixed with product semantics

This phase should instead allow the next tasks to land as separate, reviewable PRs:

- runtime reliability can harden execution behavior without re-litigating UI concerns
- control-plane UX can improve reviewer/operator experience without changing core runtime contracts
- audit usability can improve retained evidence/searchability without dictating deployment details
- deployment hardening can tighten bootstrap/runbook posture without becoming the source of truth for approval UX

## explicit non-goals for this boundary task

This task does **not** define:

- the concrete retry policy values
- the full approval queue redesign
- the full audit schema redesign
- a production deployment architecture
- CI/CD or infra implementation details

It only defines the responsibility seams that later tasks should respect.

## review rule for follow-on PRs

If a follow-on PR cannot clearly answer which of these four buckets it primarily belongs to, it is probably mixing concerns and should be split.

A PR may touch adjacent layers, but it should still have one primary ownership bucket:

- runtime reliability
- control-plane UX
- audit usability
- deployment hardening

## related docs

- `overview.md`
- `deployment-hardening-minimums.md`
- `approval-control-plane-ux-foundation.md`
- `approval-control-plane-ops-hardening.md`
- `policy-authoring-explainability-foundation.md`
- `policy-authoring-explainability-known-constraints.md`
