# live preview mode semantics

This note fixes the repository-owned semantics for the three live preview modes:

- `shadow`
- `enforce_preview`
- `unsupported`

## Goal of P13-8

Make the mode labels mean something concrete in checked-in Rust code and reflected records.

After this task, the live preview path no longer treats mode as just a string. The mode now changes:

- coverage posture
- fail-open / fail-closed visibility
- preview-supported vs unsupported visibility
- mode behavior
- record status
- approval materialization behavior
- coverage-gap wording in reflected records

## Shared mode model

`cmd/agent-auditor-hostd/src/poc/live_proxy/mode.rs` now defines:

- `LiveMode`
- `LiveModeBehavior`
- `LiveCoveragePosture`
- `ApprovalEligibility`
- `LiveModeProjection`

That projection is now used by the live preview policy, approval, and audit stages.

The operator-facing coverage / fail-open / unsupported visibility derived from that same projection is documented in [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md).

## Mode semantics

### `shadow`

`shadow` means:

- evaluate policy normally
- record the policy signal
- never create inline enforcement
- never materialize approval queue state
- reflect the outcome as observe-only preview coverage

Current checked-in values:

- `coverage_posture=observe_only_preview`
- `failure_posture=fail_open`
- `coverage_support=preview_supported`
- `mode_behavior=observe_only`
- `mode_status=shadow_observe_only`
- `approval_eligibility=advisory_only` for `require_approval`

If policy returns `require_approval` in shadow mode, the result is recorded as an advisory-only signal with no `ApprovalRequest`.

### `enforce_preview`

`enforce_preview` means:

- evaluate policy normally
- record the intended allow / deny / approval effect
- materialize preview-only approval state for `require_approval`
- still report that runtime enforcement fell back to observe-only behavior

Current checked-in values:

- `coverage_posture=record_only_preview`
- `failure_posture=fail_open`
- `coverage_support=preview_supported`
- `mode_behavior=record_only`
- `mode_status=enforce_preview_record_only`
- `approval_eligibility=record_only` for `require_approval`

This is the only mode that now creates preview-only `ApprovalRequest` records.

### `unsupported`

`unsupported` means:

- evaluate policy for diagnostics
- record the signal and the coverage gap
- never materialize approval queue state
- make it explicit that no supported live preview contract exists for the path

Current checked-in values:

- `coverage_posture=unsupported_preview`
- `failure_posture=fail_open`
- `coverage_support=unsupported`
- `mode_behavior=unsupported`
- `mode_status=unsupported_preview_only`
- `approval_eligibility=unsupported` for `require_approval`

`unsupported` is therefore stricter than `shadow`: it is not just observe-only; it explicitly says that the live preview contract for the path is not supported.

## Record-status examples

The new mode projection also fixes per-mode record status strings.

Examples:

- `shadow_require_approval_recorded`
- `enforce_preview_approval_request_recorded`
- `unsupported_deny_recorded`

These values appear together with:

- `failure_posture`
- `coverage_support`
- `coverage_summary`

so operators can tell whether an approval request was merely observed, actually materialized as preview-only state, or not supported at all, without mistaking any of those states for fail-closed inline enforcement.

## Coverage-gap examples

The mode projection also fixes mode-specific coverage-gap wording:

- `shadow_mode_has_no_inline_hold_deny_or_resume`
- `enforce_preview_has_no_inline_hold_deny_or_resume`
- `unsupported_mode_has_no_supported_live_preview_contract`

That makes the audit trail clearer than a single generic preview gap.

## Where the mode projection is used

### Policy

`live_proxy/policy.rs` now projects:

- `coverage_posture`
- `mode_behavior`
- `mode_status`
- `record_status`
- `approval_eligibility`

onto the normalized live preview event.

### Approval

`live_proxy/approval.rs` now uses the mode projection to decide whether a `require_approval` decision should become:

- advisory-only (`shadow`)
- preview-record-only approval state (`enforce_preview`)
- unsupported / unmaterialized (`unsupported`)

### Audit

`live_proxy/audit.rs` now uses the same mode projection to reflect:

- mode behavior
- mode status
- record status
- mode-specific coverage gap
- mode-specific status reason

into persisted audit records.

That reflected record visibility is documented in more detail in [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md).

## What the new tests prove

The new tests prove that:

- `shadow`, `enforce_preview`, and `unsupported` no longer collapse into the same reflected status
- shadow `require_approval` stays advisory-only and does not create an approval request
- enforce-preview `require_approval` creates a preview-only approval request
- unsupported mode records the policy signal and coverage gap without claiming a supported live preview path
- reflected records keep `failure_posture=fail_open` while distinguishing `preview_supported` vs `unsupported`

## Related docs

- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- live proxy phase boundary: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live coverage posture: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
