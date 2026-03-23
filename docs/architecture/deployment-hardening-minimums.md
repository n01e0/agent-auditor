# deployment hardening minimums

This note fixes the minimum checked-in guidance for packaging, deployment, observability, and rollback during the gap-closing / productization / hardening phase.

It builds on:

- [`gap-closing-productization-hardening-foundation.md`](gap-closing-productization-hardening-foundation.md)
- [`gap-closing-gap-matrix.md`](gap-closing-gap-matrix.md)
- [`overview.md`](overview.md)
- [`failure-behavior.md`](failure-behavior.md)

## gap being closed

Before this step, the repository already had:

- local runbooks for the major PoC slices
- known-constraints notes for those slices
- smoke coverage proving the checked-in bootstrap contracts
- control-plane and audit docs that explain what the repository can model

What was still missing was one repository-level minimum deployment note that answers:

- what should count as the current packageable unit?
- what is the minimum safe deployment shape?
- what observability signals should an operator check first?
- what rollback guidance is acceptable before a fuller product deployment story exists?

This document fixes that minimum contract without pretending the repository already has a complete installer, orchestrator, or production service platform.

## current packageable units

Today the minimum packageable artifacts are still the Rust binaries produced by this workspace:

- `cmd/agent-auditor-hostd`
- `cmd/agent-auditor-controld`
- `cmd/agent-auditor-cli`

The checked-in packaging minimum is:

1. build the exact workspace revision you intend to deploy
2. produce release binaries from that revision
3. keep the matching docs / policy bundle / config expectations tied to the same revision
4. treat that revision as the rollback unit

The repository does **not** yet claim:

- Debian/RPM packages
- container images as the canonical release artifact
- Kubernetes manifests
- Helm charts
- systemd units checked into the repo
- database migrations or durable control-plane schema upgrades

So the honest packaging baseline is still **revisioned release binaries plus matching docs/config**.

## minimum deployment shape

The minimum supported deployment posture for the current repository should stay conservative:

### preferred near-term shape

- one host
- one `agent-auditor-hostd` process for host-side collection / enforcement preview
- one `agent-auditor-controld` process for control-plane/bootstrap preview when that slice is needed
- optional `agent-auditor-cli` on the same host for local operator inspection

### separation expectations

Even in a single-host deployment, operators should keep these separate:

- **binary revision**
- **config / policy inputs**
- **writable state / artifact paths**
- **service identity / permissions**

The repository already distinguishes boundary ownership in code. Deployment should not collapse those boundaries back into one mutable shared directory with unclear ownership.

## minimum config and filesystem expectations

Until the repository gains a fuller config story, a minimum safe deployment should preserve these rules:

1. **pin the exact revision**
   - do not deploy from an uncommitted working tree
   - do not mix binaries from one revision with docs/policies from another

2. **use explicit writable locations**
   - bootstrap-local artifacts under `target/` are fine for development
   - broader deployment should move writable paths to an operator-chosen service directory
   - writable data should not require editing the checked-out source tree in place

3. **keep code/config more immutable than state**
   - binaries, docs, and checked-in policies should be revisioned inputs
   - approval/audit/bootstrap artifacts should live in separate writable paths

4. **treat secrets and privileged access as external deployment concerns**
   - the repo documents redaction-safe records and least-privilege intent
   - it does not yet provide a full secret-distribution system
   - deployments should inject secrets or credentials through host-native mechanisms, not by baking them into the repo

5. **assume least privilege first**
   - if only `hostd` needs elevated host access, do not give the same access to `controld` or `cli`
   - do not grant write access to policy/config paths when read-only access is sufficient

## startup and readiness minimums

Before calling a deployment "up", the minimum checks should be:

1. the intended binaries start successfully from the deployed revision
2. the binary can produce the expected bootstrap output without crashing
3. the workspace smoke contract still passes for the deployed revision
4. the operator can identify where logs / preview artifacts / local records are going

For the current repository, readiness is still mostly **contract readiness**, not product-UI readiness.

That means the most honest minimum checks are still based on:

- `cargo test`
- focused smoke tests per slice
- successful local bootstrap execution for the relevant binary

## observability minimums

The repository does not yet expose a full production metrics stack, but it does already define several minimum observability surfaces.

### 1. bootstrap stdout is a first-class signal

Today many slices intentionally expose deterministic preview lines from:

- `agent-auditor-hostd`
- `agent-auditor-controld`

Operators should treat those lines as the first readiness/debug surface for the current phase.

### 2. smoke tests are part of observability, not just CI

For this repository phase, smoke tests are the minimum machine-checkable health proof that the checked-in contracts still agree.

Examples include:

- `cargo test -p agent-auditor-hostd --test poc_smoke`
- `cargo test -p agent-auditor-hostd --test live_proxy_seam_smoke`
- `cargo test -p agent-auditor-controld --test control_plane_smoke`

If these fail for a candidate revision, operators should treat that revision as not deployment-ready.

### 3. reflected audit/approval artifacts remain part of the operator surface

Several slices already persist bootstrap-local JSONL artifacts under `target/`.

Those artifacts are not durable product storage, but they are still useful minimum observability signals because they let operators inspect:

- reflected policy decisions
- approval materialization
- redaction-safe audit projection
- live preview coverage / failure posture reflection

### 4. coverage visibility must be explicit

Operators should always be able to answer:

- what is truly enforced?
- what is preview-only?
- what is fail-open?
- what is unsupported?

The repository now documents this explicitly in:

- [`coverage-matrix.md`](coverage-matrix.md)
- [`failure-behavior.md`](failure-behavior.md)
- [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)

A deployment that cannot surface those distinctions clearly should be treated as operationally incomplete.

## rollback minimums

The current rollback unit is still the repository revision.

That means the minimum rollback procedure is:

1. identify the last known-good revision
2. rebuild or redeploy the binaries from that exact revision
3. restore the matching config/policy/docs expectations for that same revision
4. rerun the minimum smoke/readiness checks
5. only then resume operator trust in new approval/audit/bootstrap output

### what rollback should not mean yet

Rollback should **not** be described as:

- automatic state migration reversal
- zero-downtime fleet promotion
- coordinated multi-node traffic shifting
- durable queue/audit schema downgrade support

The repository does not yet implement those claims.

### current practical rule

If a rollout changes the meaning of preview output, approval records, or audit reflection, operators should prefer **reverting the whole revision** rather than trying to hot-edit only one doc, binary, or policy file in place.

## deployment change checklist

A deployment-affecting PR in the current phase should be able to answer these questions clearly:

### packaging
- what binary or checked-in artifact changed?
- what exact revision should operators deploy as a unit?

### deployment
- does this change require a new writable path, config knob, or privilege boundary?
- does it change which binary/process owns a responsibility?

### observability
- what new stdout line, smoke expectation, persisted artifact, or record field proves the change worked?
- how does an operator tell success from preview-only or degraded behavior?

### rollback
- what is the previous known-good revision?
- can the operator safely revert at the revision boundary without inventing ad-hoc repair steps?

If a PR cannot answer those four sections, it is probably not documenting deployment hardening clearly enough.

## explicit non-goals

This minimum doc still does **not** define:

- a production installer
- container packaging conventions
- a metrics backend
- systemd/kubernetes manifests
- durable control-plane persistence
- automated migration/rollback tooling
- HA or multi-region deployment patterns

Those belong to later deployment-hardening work once the current contracts stabilize further.

## related docs

- phase boundary: [`gap-closing-productization-hardening-foundation.md`](gap-closing-productization-hardening-foundation.md)
- gap matrix: [`gap-closing-gap-matrix.md`](gap-closing-gap-matrix.md)
- architecture overview: [`overview.md`](overview.md)
- failure posture: [`failure-behavior.md`](failure-behavior.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- control-plane local runbook: [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md)
- hostd enforcement local runbook: [`../runbooks/hostd-enforcement-foundation-local.md`](../runbooks/hostd-enforcement-foundation-local.md)
