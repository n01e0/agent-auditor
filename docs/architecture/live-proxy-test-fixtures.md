# live proxy test fixtures

This note documents the checked-in unit-test fixture catalog and smoke test coverage for the live proxy seam.

## Goal of P13-9

Add repository-owned fixtures and smoke tests that exercise the live proxy seam as one coherent pipeline instead of only per-module preview helpers.

## Checked-in code

The new test support lives in:

- `cmd/agent-auditor-hostd/src/poc/live_proxy/fixtures.rs`
- `cmd/agent-auditor-hostd/tests/live_proxy_seam_smoke.rs`

## Fixture catalog

`live_proxy/fixtures.rs` now defines `LiveProxyFixtureCase` plus `seam_fixture_catalog()`.

Each fixture captures:

- the live preview consumer
- the live mode
- one annotated event
- the expected policy decision
- expected coverage posture / mode behavior / mode status / record status
- the expected coverage gap
- whether approval state should be materialized
- the expected wait state

The checked-in catalog currently covers:

- generic REST `enforce_preview` hold
- generic REST `shadow` advisory-only hold
- GWS `shadow` allow
- GitHub `unsupported` deny
- messaging `enforce_preview` hold

That mix is intentional: it covers all three live modes and all four downstream semantic consumers.

## Unit tests

`live_proxy/fixtures.rs` also adds unit coverage that checks:

- the fixture catalog spans all supported live modes
- the fixture catalog spans generic REST / GWS / GitHub / messaging consumers
- each fixture event is already annotated with the expected mode and live-request summary

## Smoke test

`tests/live_proxy_seam_smoke.rs` adds a crate-level smoke test that runs every fixture through:

1. live preview policy evaluation
2. approval projection
3. audit reflection

The smoke test then verifies that the reflected record matches the fixture expectations for:

- policy decision
- coverage posture
- mode behavior
- mode status
- record status
- approval materialization
- wait state
- coverage gap

## Why this matters

Before P13-9, the repository had strong per-module tests, but it did not have one shared fixture catalog that proved the seam still behaved coherently end to end.

Now the repository has:

- per-module unit tests
- a reusable seam fixture catalog
- a pipeline smoke test over those fixtures

That gives later tasks a safer place to extend the live proxy seam without accidentally drifting mode semantics or reflected record status.
