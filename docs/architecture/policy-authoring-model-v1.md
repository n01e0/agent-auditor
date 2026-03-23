# policy authoring model v1

This note defines the first human-writable policy authoring model for the explainability phase.

It follows the boundary introduced in `policy-authoring-explainability-foundation.md`:

- **policy authoring** defines what a human writes
- **explanation** defines redaction-safe decision output for one concrete event
- **reviewer-facing rationale** defines approval/operator wording derived later

## Goal

Make provider / action / posture readable and writable without forcing authors to think in evaluator-internal structures.

The v1 authoring model is intentionally small:

- `provider` / `providers`
- `action` / `actions`
- `posture`
- optional reviewer-oriented metadata that still belongs to authoring time, not decision-time explanation

## v1 shape

A single rule is modeled as:

```json
{
  "id": "gmail-send-requires-approval",
  "summary": "Require approval before sending Gmail messages",
  "provider": "gws",
  "action": "gmail.users.messages.send",
  "posture": "require_approval",
  "reviewer_hint": "Check recipient domain and message sensitivity",
  "labels": ["workspace-mail", "outbound-send"]
}
```

The same model can also accept plural forms:

```json
{
  "id": "high-risk-github-writes",
  "summary": "Block selected high-risk GitHub write operations",
  "providers": ["github"],
  "actions": [
    "pull_requests.merge",
    "branch_protection.update",
    "repository.delete"
  ],
  "posture": "deny"
}
```

## Field ownership

### provider / providers

Human-facing provider scope.

- singular and plural forms are both accepted
- normalized to a canonical provider-id list internally
- should stay stable at the human policy layer

Examples:

- `gws`
- `github`
- `slack`
- `discord`

### action / actions

Human-facing action scope.

- singular and plural forms are both accepted
- normalized to canonical action keys internally
- action keys stay close to provider semantics, not UI wording

Examples:

- `gmail.users.messages.send`
- `drive.permissions.update`
- `pull_requests.merge`
- `channel.permission.update`

### posture

Human policy intent.

Current v1 values:

- `allow`
- `require_approval`
- `deny`
- `hold`

`hold` is kept in the authoring model even where current evaluator/control-plane contracts still map only a subset of postures directly into `PolicyDecisionKind`.

## What belongs here vs elsewhere

### belongs in authoring model

- provider scope
- action scope
- posture intent
- stable authoring metadata like labels and reviewer hints

### does not belong here

- fully rendered explanation text for one decision
- reviewer queue headline text
- runtime evidence payloads
- mutable approval state

## Code contract in this phase

`crates/agenta-policy` now exposes the authoring model types used to normalize human-written policy scope:

- `PolicyAuthoringPosture`
- `PolicyAuthoringRule`
- `PolicyAuthoringCatalog`

These types are intentionally distinct from:

- `PolicyInput` (request-time evaluator input)
- `PolicyDecision` (request-time decision output)
- reviewer-facing approval summaries in `agenta-core::controlplane`

## Normalization rules

v1 normalization is intentionally conservative:

- singular and plural provider/action fields are accepted
- provider/action lists are normalized and deduplicated
- posture remains explicit and machine-readable
- no reviewer-facing prose is auto-generated here

## Why this is enough for P14-2

This gives the next tasks a stable policy-authoring contract without prematurely coupling it to explanation or reviewer-UX payloads.

That means:

- authoring can evolve independently from concrete decision explanations
- explanation schema can grow in `agenta-core` later
- reviewer-facing rationale can be projected later without changing the human authoring surface

## Related docs

- [`policy-authoring-explainability-foundation.md`](policy-authoring-explainability-foundation.md)
- [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
