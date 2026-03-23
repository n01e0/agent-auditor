# policy explanation schema v1

This document defines the first structured explanation schema shared through `agenta-core` for policy outcomes that need explicit downstream explanation handling.

## Scope

The schema currently covers three policy dispositions:

- `deny`
- `require_approval`
- `hold`

It intentionally does **not** define reviewer-facing rationale text. That remains a downstream projection concern.

## Why this schema exists

The explainability phase now has three separate responsibilities:

- **policy authoring**: what a human writes
- **explanation**: redaction-safe structured reasoning for one concrete decision
- **reviewer-facing rationale**: operator/reviewer wording derived later

This schema covers only the middle layer.

## Core types

`crates/agenta-core` now defines:

- `PolicyExplanationDisposition`
- `PolicyExplanationMatch`
- `PolicyExplanationEvidence`
- `PolicyExplanation`

## Meaning of each field

### `disposition`

The explanation-level outcome being described.

Allowed values:

- `deny`
- `require_approval`
- `hold`

This is intentionally broader than `PolicyDecisionKind`, because `hold` is an explainability/control-plane concern even where the current policy decision enum only models direct decision kinds.

### `summary`

A short redaction-safe summary of why the outcome happened.

Examples:

- `Block repository deletion`
- `Require approval before sending Gmail messages`
- `Hold outbound mail until a reviewer resolves the queue item`

### `rule_id`

Optional stable rule identifier for the matched policy.

### `severity`

Optional severity classification inherited from policy or policy execution context.

### `scope`

A structured match surface describing what the explanation matched.

Current fields:

- `provider_id`
- `action_key`
- `target_hint`
- `labels`

The intent is to keep enough context for downstream explainability and audit use without requiring raw payload retention.

### `evidence`

Structured redaction-safe evidence fragments.

Each entry has:

- `code`: stable machine-readable classifier / match code
- `detail`: redaction-safe explanation fragment

Examples:

- `matched.provider_action`
- `matched.posture`
- `matched.hold_posture`

### `reviewer_hint`

Optional reviewer-oriented hint carried through the explanation contract, but still distinct from reviewer-facing final rationale rendering.

This can be used later when building approval queue summaries without collapsing explanation and reviewer UI concerns into one string field.

## Example

```json
{
  "disposition": "require_approval",
  "summary": "Require approval before sending Gmail messages",
  "rule_id": "gmail-send-approval",
  "severity": "medium",
  "scope": {
    "provider_id": "gws",
    "action_key": "gmail.users.messages.send",
    "target_hint": "external-recipient",
    "labels": ["workspace-mail"]
  },
  "evidence": [
    {
      "code": "matched.posture",
      "detail": "outbound mail posture requires approval"
    }
  ],
  "reviewer_hint": "Check recipient domain and message sensitivity"
}
```

## Design constraints

- explanation must remain redaction-safe
- explanation must not depend on UI formatting
- explanation must not become the reviewer queue model itself
- explanation must be stable enough to cross crate boundaries through `agenta-core`

## Follow-on use

This schema is meant to unblock the next step where policy evaluation can start returning structured explanation payloads without re-defining the cross-crate contract.

## Related docs

- [`policy-authoring-explainability-foundation.md`](policy-authoring-explainability-foundation.md)
- [`policy-authoring-model-v1.md`](policy-authoring-model-v1.md)
- [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md)
