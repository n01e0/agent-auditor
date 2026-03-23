# policy authoring / explainability known constraints

This document captures the current known constraints for the policy authoring / explainability phase.

It is meant to keep future work honest about what is already structured, what is only partially wired, and what still remains intentionally separated.

## 1. Authoring model exists, but it is still a phase-local model

The repository now has a human-writable authoring model in `crates/agenta-policy`:

- `PolicyAuthoringPosture`
- `PolicyAuthoringRule`
- `PolicyAuthoringCatalog`

Current limitation:

- this is a phase-local authoring contract, not yet a complete policy distribution / loading / runtime authoring pipeline
- it normalizes provider/action/posture shape, but does not yet imply a full end-user DSL lifecycle

## 2. Explanation schema exists, but not every policy path emits it yet

`agenta-core` now defines structured explanation types for:

- `deny`
- `require_approval`
- `hold`

Current limitation:

- the cross-crate schema exists, but not every evaluator path is guaranteed to populate `PolicyDecision.explanation`
- some paths may still rely on legacy `reason` text unless explicitly upgraded

## 3. `hold` is representable in explanation, but not a first-class `PolicyDecisionKind`

This is intentional for the current phase boundary.

Current limitation:

- `PolicyExplanationDisposition::Hold` exists
- `PolicyDecisionKind` still models the narrower executable decision set
- callers must not assume that every explanation disposition maps directly back into a `PolicyDecisionKind`

## 4. Reviewer-facing summary is a projection, not the source of truth

Approval records now persist presentation data through `ApprovalRequest.presentation`.

Current limitation:

- reviewer-facing summary and rationale are still derived/persisted presentation fields
- they must not be treated as the canonical policy-authoring contract
- future UI/API layers may still refine how these strings are rendered without changing authoring semantics

## 5. Approval-record persistence is contract-level, not storage-schema-final

The current repository persists rationale / reviewer-facing summary in the approval-request contract itself.

Current limitation:

- this is sufficient for the current control-plane and smoke coverage
- it is not yet a statement about final storage-schema shape for every downstream backend or service boundary

## 6. Smoke coverage is focused, not full end-to-end provider coverage

Current smoke coverage proves that:

- reviewer-facing summary is visible in the approval queue item
- rationale is visible in rationale capture output

Current limitation:

- smoke coverage is currently centered on `agent-auditor-controld` sample/bootstrap paths
- it is not yet exhaustive provider-by-provider end-to-end validation for every runtime integration

## 7. Redaction safety still depends on field discipline

The phase boundary is designed to keep explanation redaction-safe.

Current limitation:

- nothing prevents future contributors from accidentally stuffing raw payload detail into explanation/rationale fields unless review discipline is maintained
- changes touching explanation or rationale should be reviewed with redaction safety explicitly in mind

## 8. Docs must move together

This phase is split across multiple documents:

- boundary doc
- authoring model doc
- explanation schema doc
- local runbook
- this known-constraints doc

Current limitation:

- these docs can drift if only one is updated during follow-on work
- a PR that changes authoring/explanation/rationale behavior should update whichever of these docs it affects in the same change

## Practical rule

If a change blurs any of the following, it should be treated as suspicious and reviewed carefully:

- authoring vs explanation
- explanation vs reviewer-facing rationale
- structured explanation vs UI wording
- persisted approval presentation vs final end-user rendering

## Related docs

- `policy-authoring-explainability-foundation.md`
- `policy-authoring-model-v1.md`
- `policy-explanation-schema-v1.md`
- `../runbooks/policy-authoring-explainability-local.md`
