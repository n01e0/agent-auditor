# live proxy known constraints

This note records the known constraints for the current live proxy PoC so future changes do not accidentally overclaim capability.

## Scope of these constraints

These are **current repository constraints**, not generic design principles.

They describe what the checked-in PoC can and cannot do today.

## 1. No real inline interception yet

The repository still does **not** prove:

- in-flight request pause
- in-flight request deny
- request resume after review
- retry-aware enforcement coordination
- provider timeout coordination

The checked-in path is still preview-oriented, even when policy says `deny` or `require_approval`.

## 2. The seam is intentionally redaction-safe and lossy

The shared proxy contract deliberately strips:

- raw header values
- cookies
- bearer tokens
- request bodies
- response bodies
- query strings
- fragments
- message text
- file bytes
- provider-opaque payloads

That keeps the seam safe, but it also means some downstream classifications need explicit hints instead of raw payload access.

## 3. Query-string-dependent behavior cannot rely on raw query data

The live proxy contract does not carry query strings.

Current consequence:

- GWS `drive.files.get_media` cannot rely on `?alt=media`
- it instead depends on an explicit redaction-safe `target_hint`

If future contributors add more query-sensitive routes, they must either:

- project a safe hint upstream, or
- document that the route is unsupported on the live proxy path

## 4. Some classifications still depend on explicit `target_hint`

Because the seam strips bodies and other provider-specific payloads, several preview adapters currently need explicit `target_hint` values.

Examples already checked in:

- GitHub `repos.update_visibility`
  - `PATCH /repos/{owner}/{repo}` is not specific enough on its own
- Slack `chat.postMessage`
- Slack `conversations.invite`
- Slack `files.uploadV2`
  - the body would normally carry channel/member/file targeting data, but the seam does not retain it

If `target_hint` is missing, the adapter should fail explicitly instead of guessing.

## 5. `shadow`, `enforce_preview`, and `unsupported` are not equivalent

The current mode semantics are intentionally different:

- `shadow`
  - observe-only preview
  - no approval request materialization
- `enforce_preview`
  - record-only preview
  - may materialize preview-only approval state
- `unsupported`
  - diagnostic-only unsupported preview
  - no approval request materialization

Contributors should not collapse these back into one generic preview status.

## 6. `require_approval` does not mean a real hold exists

Today, `require_approval` means one of three things depending on mode:

- advisory-only signal (`shadow`)
- preview-only approval record (`enforce_preview`)
- unsupported diagnostic signal (`unsupported`)

It does **not** prove a real live request was held.

## 7. Audit reflection is append-only and still preview-scoped

The reflected records are useful, but still limited.

They show:

- policy intent
- realized enforcement directive
- mode behavior/status
- coverage gap
- approval linkage when applicable

They do **not** prove:

- runtime blocking succeeded
- a provider call was actually paused
- the provider retried safely after review

## 8. The provider preview adapters are intentionally narrow

The current route catalogs are small on purpose.

Checked-in preview scopes include only a handful of routes for:

- generic REST
- GWS
- GitHub
- Slack / Discord messaging

These adapters should be treated as **preview route catalogs**, not broad provider coverage.

## 9. Messaging policy normalization is intentionally generic

The messaging path reuses a generic flat event shape for policy evaluation.

That is good enough for current preview policy and audit reflection, but it is still a PoC compromise. It is not yet a fully distinct production-grade messaging event contract.

## 10. Persistence-heavy tests must isolate their local store directories

The live preview audit tests write to local append-only stores under `target/`.

Shared directories can cause nondeterministic CI failures from leftover records or parallel test races.

Current rule:

- persistence-heavy tests must use unique per-test store directories

If a future test reuses one shared PoC store path, expect flaky CI.

## 11. The current runbook is local-only

The repository now has a local runbook, but it still assumes:

- one developer machine
- local cargo commands
- local PoC fixtures
- no real proxy deployment

There is still no checked-in production runbook for operating a real interception service.

## 12. Coverage claims must stay conservative

A future contributor should **not** claim support just because the repository has:

- a policy evaluator
- an approval request
- an audit record
- a preview adapter

The honest standard remains:

- preview-only until inline behavior is proven
- unsupported when a safe hint or route shape is missing
- record-only when policy intent is captured but not enforced

## Related docs

- local runbook: [`live-proxy-local-runbook.md`](live-proxy-local-runbook.md)
- mode semantics: [`live-preview-mode-semantics.md`](live-preview-mode-semantics.md)
- record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
- provider adapter boundaries: [`provider-live-preview-adapter-boundaries.md`](provider-live-preview-adapter-boundaries.md)
