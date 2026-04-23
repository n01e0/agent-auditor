# real-traffic observation boundary

This note fixes the documentation boundary for the repository's next step beyond fixture-only live preview work.

The purpose of P16-1 is simple:

- stop blurring checked-in preview fixtures with real request capture
- define when the repository may say it **observed** a real request
- define the higher bar required to say that request became a **validated observation**

The repository already has fixture-backed live preview docs and tests. Those remain useful, but they are not the same thing as proving that a non-fixture request crossed a real ingress seam and reached the checked-in audit path.

## three distinct evidence tiers

The repository now uses three separate terms.

### 1. fixture preview

`fixture preview` means a checked-in synthetic event or fixture catalog entry drives the preview pipeline.

It is allowed to prove:

- policy / approval / audit shape compatibility
- mode semantics (`shadow`, `enforce_preview`, `unsupported`)
- record reflection and coverage wording
- stable smoke-test expectations for the checked-in preview catalog

It is **not** allowed to claim:

- that a live request source was involved
- that the request was observed from real traffic
- that inline interception or end-to-end live validation happened

Minimum conditions to call something `fixture preview`:

- the source is repository-owned fixture data, a synthetic test event, or a docs-backed preview catalog case
- the path may skip real ingress capture entirely
- the resulting record/test output is labeled or described as preview/fixture-driven rather than observed live traffic

### 2. observed request

`observed request` means the repository captured redaction-safe metadata from a **non-fixture live request source**.

This is the first real-traffic bar. It proves the ingress seam saw an actual request, but it does **not** yet prove the whole semantic / policy / audit path is validated.

Minimum conditions to call something an `observed request`:

- the upstream source is live traffic rather than a checked-in fixture
- capture happens through a documented ingress seam such as a forward proxy, sidecar, browser relay, or another explicitly documented live source
- the captured payload is reduced to the repository-owned redaction-safe request contract
- the result retains stable provenance showing it came from a non-fixture source
- docs and records do not describe it as validated end to end unless the higher bar below is also satisfied

An observed request may still be:

- uncorrelated
- partially classified
- recorded only as ingress evidence
- fail-open and preview-scoped

That is still useful. It proves the repository saw real traffic, which is stronger than fixture preview, even if downstream validation is still incomplete.

### 3. validated observation

`validated observation` is the highest claim in this phase.

It means one observed request has been shown to traverse a documented repository path all the way through the minimum auditable pipeline, and a third party can verify that fact from checked-in docs plus local artifacts.

Minimum conditions to call something a `validated observation`:

- all `observed request` conditions are satisfied
- the request is correlated to `session_id`, `agent_id`, and `workspace_id` rather than remaining anonymous ingress telemetry
- at least one documented end-to-end path completes `capture -> correlate -> classify/semantic-convert -> policy -> audit`
- the persisted artifact or record preserves provenance that distinguishes fixture-driven preview from observed live traffic
- the artifact or record also preserves validation status so an evaluator can tell "observed only" from "validated observation"
- a runbook, smoke/integration test, or equivalent inspection path lets a third party reproduce or verify the claim without reverse-engineering hidden steps
- failure posture and coverage posture remain explicit; a validated observation does **not** automatically mean fail-closed enforcement

In the current phase, the preferred first validated path is the GitHub API proxy path, but the definition is general so other ingress seams can be judged by the same bar.

## why these tiers must stay separate

Without this split, the repository risks making three different mistakes:

1. treating fixture-backed policy smoke tests as if they proved live ingress
2. treating one captured live request as if it proved the full downstream semantic path
3. treating end-to-end validated observation as if it proved fail-closed enforcement

Those are three different claims and must remain independently reviewable.

## ownership boundary for the real-traffic phase

The real-traffic phase is now split into three reviewable ownership areas.

### fixture preview ownership

Owns:

- checked-in fixture catalogs
- preview-only smoke and unit tests
- documentation for fixture mode semantics and record reflection

Does **not** own:

- proving a live ingress seam exists
- proving a request came from real traffic
- proving session-correlated end-to-end validation

### observed-request ownership

Owns:

- ingress seam capture from non-fixture traffic
- redaction-safe request metadata handoff
- provenance markers that distinguish live capture from fixture preview
- honest degraded states such as uncorrelated or observed-only capture

Does **not** own:

- claiming end-to-end validation before downstream correlation/policy/audit are shown
- claiming fail-closed or inline block capability

### validated-observation ownership

Owns:

- the minimum end-to-end proof for one real request path
- session/agent/workspace correlation for that path
- validation status and provenance persistence in records/local store
- runbook/test-backed third-party verification of the observed-vs-fixture distinction

Does **not** own:

- broad provider coverage claims beyond the validated path
- production-wide fail-closed enforcement claims
- reviewer UX completeness or control-plane productization

## repository-wide wording rule

When docs, tests, records, or PR descriptions talk about live traffic, they should use the strongest label they can honestly support and no stronger:

- use `fixture preview` for synthetic coverage only
- use `observed request` when live ingress is proven but end-to-end validation is not
- use `validated observation` only when the full minimum path and verification conditions are met

If a claim mixes tiers, reviewers should ask for it to be split.

## minimum evidence table

| Claim | Live non-fixture source | Redaction-safe ingress record | Session / agent / workspace correlation | Policy + audit path completed | Third-party verification path | Allowed today? |
| --- | --- | --- | --- | --- | --- | --- |
| fixture preview | no | optional synthetic summary | no | optional preview-only | fixture test/runbook is enough | yes, already checked in |
| observed request | yes | yes | not required yet | not required yet | at least ingress inspection | target of current real-traffic phase |
| validated observation | yes | yes | yes | yes | yes | target of current real-traffic phase |

## interaction with existing live-preview docs

The existing live-preview documents stay valid, but they should now be read conservatively:

- fixture catalogs and preview smoke tests prove `fixture preview`
- preview policy / approval / audit reflection docs prove record semantics for preview paths
- none of those docs alone prove `observed request` or `validated observation`

Real-traffic follow-on work should update runbooks, local store semantics, and end-to-end tests so at least one path can move from `fixture preview` to `observed request`, and then from `observed request` to `validated observation`.

## review question for follow-on P16 work

Before merging a follow-on real-traffic PR, reviewers should be able to answer:

1. did this PR improve fixture preview only?
2. did it prove non-fixture observed ingress?
3. did it raise one path to validated observation?

If the answer is unclear, the PR is probably mixing evidence tiers too loosely.

## related docs

- architecture overview: [`overview.md`](overview.md)
- live proxy interception foundation: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live proxy HTTP request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- generic live action envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- live preview record reflection: [`live-preview-record-reflection.md`](live-preview-record-reflection.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- live proxy coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
- live proxy test fixtures: [`live-proxy-test-fixtures.md`](live-proxy-test-fixtures.md)
