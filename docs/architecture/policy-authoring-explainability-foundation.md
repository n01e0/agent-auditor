# policy authoring / explainability phase boundary

This note fixes the first boundary for the policy authoring / explainability phase before the repository grows a richer authoring model, structured explanations, and reviewer-facing approval rationale.

## Goal of P14-1

Keep the next policy work honest about ownership before the repository introduces:

- a human-oriented policy authoring model for provider / action / posture
- a structured explanation schema for `deny` / `require_approval` / `hold`
- reviewer-facing rationale and approval summaries derived from policy decisions

The immediate rule is:

- **policy authoring** owns the human-writable policy surface and the stable rule intent a human edits
- **explanation** owns the redaction-safe machine-readable reason the evaluator returns for a concrete decision
- **reviewer-facing rationale** owns the operator / reviewer summary shown in approval queues and audit-oriented UX

These are related, but they are not the same object and should not collapse into one overloaded `reason` field.

## Boundary contract

### 1. Policy authoring

Policy authoring is the layer a human edits.

It owns:

- provider / action / posture vocabulary that is readable and maintainable by operators
- policy rule identity, matching intent, and stable authoring-time defaults
- authoring-time policy metadata such as severity defaults and approval posture intent
- the durable rule contract that the evaluator can interpret later

It does **not** own:

- the fully rendered explanation for one concrete event
- reviewer-specific wording for an approval queue
- request-time human context from the requester
- UI-specific summaries or audit projections

### 2. Explanation

Explanation is the evaluator output for one concrete decision.

It owns:

- why a specific event matched a specific rule
- the normalized outcome shape for `deny`, `require_approval`, and `hold`
- redaction-safe evidence fragments such as matched provider, action, posture, or classifier labels
- machine-readable fields that downstream control-plane or audit code can consume without re-running policy

It does **not** own:

- the human-authored policy DSL or catalog shape itself
- reviewer workflow wording like escalation guidance or queue headline text
- mutable approval state or reviewer decisions
- transport- or UI-specific formatting

### 3. Reviewer-facing rationale

Reviewer-facing rationale is a projection built for operators or reviewers.

It owns:

- concise approval / denial summary text for queue and review surfaces
- reviewer hints, escalation hints, and actionability cues
- joining policy explanation with requester context when needed
- human-facing wording that stays stable even if the internal explanation schema grows

It does **not** own:

- policy matching logic
- raw event payload retention
- policy authoring syntax
- the evaluator's internal explanation schema as its canonical source of truth

## Code layout for this phase

### `crates/agenta-policy`

Owns the policy evaluation boundary.

For this phase it should be treated as the place that:

- accepts policy authoring inputs
- evaluates them against a concrete `PolicyInput`
- returns decision outputs that can later grow structured explanation payloads

It should **not** become the place that bakes in reviewer-facing queue wording.

### `crates/agenta-core`

Owns shared contracts crossing process / crate boundaries.

For this phase it should be treated as the place that will eventually hold:

- structured explanation schema shared across evaluator and control-plane consumers
- reviewer-facing rationale payloads once they must cross crate boundaries
- approval record fields that persist rationale and summary state

It should **not** own the authoring DSL itself.

### `crates/agenta-core::controlplane`

Owns downstream reviewer / operator projections.

It already contains approval summary / rationale projections and should remain the consumer-facing layer that turns policy outputs plus request context into queue-oriented status summaries.

## Why this split now

This keeps the next tasks cleaner:

- **P14-2** can reorganize provider / action / posture into a human-oriented authoring model without coupling it to queue wording
- **P14-3** can add a structured explanation schema in `agenta-core` without re-litigating authoring ownership
- **P14-4** can make `agenta-policy` return explanation / rationale / reviewer hints with clearer seams
- **P14-5** can project rationale into approval records without forcing approval UX concerns back into authoring
- **P14-6** can add tests separately for authoring normalization, explanation generation, and reviewer-facing projections

## Redaction rule for this phase

The boundary is redaction-safe from the start:

- policy authoring may refer to provider / action / posture abstractions
- explanation may expose matched rule ids, posture labels, provider/action ids, and redaction-safe target hints
- reviewer-facing rationale may summarize approval posture and reviewer hints

But none of these boundaries should require storing raw message bodies, full document contents, full pull request diffs, or other high-retention payloads just to explain a decision.

## Explicitly out of scope for P14-1

- the concrete authoring model schema itself
- the concrete explanation schema itself
- full reviewer-facing rationale payloads in `agenta-core`
- approval record persistence changes
- UI rendering details
- policy simulator or policy generation features

## Related docs

- architecture overview: [`overview.md`](overview.md)
- policy contract notes: [`../policies/rego-contract.md`](../policies/rego-contract.md)
- approval control-plane UX foundation: [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
- approval control-plane ops hardening: [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md)
- roadmap/tasklist source: `../.ralph/tasklists/policy-authoring-explainability-tasklist.locked.md`
