# live preview coverage / failure posture visibility

This note fixes the checked-in operator-facing vocabulary for how live preview coverage, fail-open / fail-closed posture, and unsupported mode should appear in records.

It builds on:

- [`failure-behavior.md`](failure-behavior.md)
- [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)

## gap being closed

Before this step, the live preview path already reflected:

- `coverage_posture`
- `mode_behavior`
- `mode_status`
- `record_status`
- `coverage_gap`

That was enough to show which preview mode ran, but it still made operators mentally reconstruct two important questions:

- is this path currently **fail-open** or allowed to claim **fail-closed**?
- is this a **supported preview path** or an **unsupported diagnostic-only path**?

The repository had the right semantics in docs, but those semantics were not yet surfaced as a compact record-facing explanation.

## checked-in record-facing fields

`cmd/agent-auditor-hostd/src/poc/live_proxy/mode.rs` now extends `LiveModeProjection` with:

- `failure_posture`
- `coverage_support`
- `coverage_display_rule`
- `coverage_summary`

`cmd/agent-auditor-hostd/src/poc/live_proxy/policy.rs` reflects `coverage_display_rule` into normalized preview records, and `cmd/agent-auditor-hostd/src/poc/live_proxy/audit.rs` reflects the same field into live preview audit records as an action attribute.

The checked-in record-facing fields are now:

- `failure_posture`
- `coverage_support`
- `coverage_display_rule`
- `coverage_summary`

## what each field means

### `failure_posture`

This is the direct fail-open / fail-closed claim for the current runtime path.

Checked-in values are designed to stay conservative:

- `fail_open`
- `fail_closed`

For the current live preview path, all checked-in records still emit:

- `failure_posture=fail_open`

That is intentional. The repository still does **not** claim a validated inline fail-closed live path here.

### `coverage_support`

This distinguishes whether the preview path is part of the checked-in supported preview contract or outside it.

Values:

- `preview_supported`
- `unsupported`

This keeps unsupported mode separate from ordinary shadow-mode observe-only preview.

### `coverage_display_rule`

This is the checked-in rendering rule for preview-facing records.

Current values are intentionally small:

- `show_preview_supported_and_fail_open`
- `show_unsupported_and_fail_open`

The rule is not a second policy engine. It is the compact record contract that says how `coverage_support` and `failure_posture` should be presented together.

### `coverage_summary`

This is the compact operator sentence that ties the posture together.

Representative checked-in summaries:

- `preview-supported observe-only path; policy intent is recorded but the live request remains fail-open`
- `preview-supported record-only path; approval or deny intent is reflected locally but the live request remains fail-open`
- `unsupported live preview path; policy signals are diagnostic only and the live request remains fail-open`

## current mode mapping

| mode | coverage_posture | failure_posture | coverage_support | coverage_display_rule | practical reading |
| --- | --- | --- | --- | --- | --- |
| `shadow` | `observe_only_preview` | `fail_open` | `preview_supported` | `show_preview_supported_and_fail_open` | supported preview path that observes policy intent only |
| `enforce_preview` | `record_only_preview` | `fail_open` | `preview_supported` | `show_preview_supported_and_fail_open` | supported preview path that can record approval/deny intent locally, but not enforce inline |
| `unsupported` | `unsupported_preview` | `fail_open` | `unsupported` | `show_unsupported_and_fail_open` | diagnostic-only path with no supported live preview contract |

## why `unsupported` is not the same as `fail_closed`

This is the most important visibility rule fixed here.

`unsupported` means:

- the repository can still evaluate policy for diagnostics
- the record should say no supported live preview contract exists
- the live request still must not be misrepresented as blocked inline

So an unsupported path is **not**:

- a stronger enforcement claim
- a hidden fail-closed path
- proof that the runtime denied the request before completion

It is still recorded as `failure_posture=fail_open`, with a stronger `coverage_support=unsupported` explanation.

## why `fail_closed` still exists as a label

The checked-in visibility model keeps `fail_closed` available because `failure-behavior.md` already defines the broader repository rule:

- only validated enforced subsets may claim fail-closed behavior

The live preview path does not satisfy that bar today, but the label exists so future validated inline paths can reflect that honestly instead of inventing a second vocabulary later.

## record reflection rule

If a live preview audit record is read in isolation, an operator should now be able to answer all of these directly from the reflected fields:

- what preview mode ran?
- was the path fail-open or fail-closed?
- was the path part of the supported preview contract or unsupported?
- what short sentence explains the real runtime posture?
- what exact coverage gap still blocks stronger claims?

That is why the current record bundle is now:

- `mode_behavior`
- `mode_status`
- `record_status`
- `failure_posture`
- `coverage_support`
- `coverage_display_rule`
- `coverage_summary`
- `coverage_gap`

## tests fixed here

This step extends live preview tests so they verify:

- fixture expectations for `failure_posture`
- fixture expectations for `coverage_support`
- fixture expectations for `coverage_display_rule`
- fixture expectations for `coverage_summary`
- reflected normalized-event and audit-record attributes for those same fields
- catalog-wide smoke invariants that live preview still stays fail-open and does not mislabel unsupported mode as supported
- unit-level summary contract checks for the reflected audit surface

## related docs

- failure posture policy: [`failure-behavior.md`](failure-behavior.md)
- mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- semantic coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
