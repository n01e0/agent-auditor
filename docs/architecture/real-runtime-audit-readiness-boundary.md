# real-runtime audit readiness boundary

This note defines what the repository may honestly claim when it says **real-runtime audit ready** for the container proxy path.

The target is intentionally narrower than "real traffic already verified".

It exists to separate:

- checked-in stand-in runtime topology smoke
- repository-owned preparation for OpenClaw / Hermes real-runtime verification
- actual observed or validated real-runtime evidence that only appears after a human runs the real containers

## goal

P18 is about getting the repository to the point where `n01e0` can replace the stand-in runtime containers with real OpenClaw / Hermes containers and run a real audit exercise without reverse-engineering the wiring.

That means the repository should provide:

- explicit container wiring for topology **A / forward proxy** and topology **B / sidecar proxy**
- the minimum proxy trust bootstrap needed to attempt HTTPS interception in development
- a runbook for reading hostd observed-runtime and audit evidence
- human handoff instructions for OpenClaw and Hermes verification
- compose-based verification and troubleshooting guidance

It does **not** mean the repository has already observed real OpenClaw / Hermes traffic.

## the three evidence tiers around this phase

### 1. stand-in topology preview

`stand-in topology preview` means the checked-in Compose stack uses smoke-friendly placeholder runtimes such as `curlimages/curl` and proves only that the repository-owned proxy path can emit redaction-safe envelopes into hostd.

It is allowed to prove:

- Compose topology shape for A / forward proxy and B / sidecar proxy
- proxy-to-hostd handoff into the observed-runtime contract
- smoke-friendly request generation against checked-in example providers
- local config rendering and proxy script validity

It is **not** allowed to prove:

- that a real OpenClaw or Hermes container has been wired successfully
- that proxy CA/trust installation has been completed for a real runtime
- that a human has exercised the real runtime and produced audit evidence

At the current repository starting point for P18, `deploy/compose.yaml` is still in this tier.

### 2. real-runtime audit ready

`real-runtime audit ready` means the repository has all checked-in assets needed for a human to run the real OpenClaw / Hermes verification next, but the human-run verification itself is still outside the repository-owned proof.

This is the acceptance target for the P18 preparation track.

Minimum conditions to call the repository `real-runtime audit ready`:

- the checked-in deployment assets explain how to replace the stand-in runtime with the real OpenClaw / Hermes container for topology **A / forward proxy**
- the checked-in deployment assets also explain how to do the same for topology **B / sidecar proxy** when that topology is in scope
- override/env contracts fix the runtime-facing proxy variables and the paired proxy-side session lineage contract
- the dev minimum for proxy CA/trust distribution is documented tightly enough to attempt HTTPS traffic through mitmproxy without guessing hidden steps
- a runbook explains where hostd writes observed-runtime envelopes, audit records, and local inspection output and how to inspect them
- OpenClaw and Hermes handoff docs define the commands to run, the expected evidence to collect, and the first troubleshooting branches
- the repository can still pass the checked-in preparation gates such as Compose config rendering and proxy-script syntax validation
- docs remain explicit that this is a preparation claim, not an observed-request or validated-observation claim for the real runtimes

`real-runtime audit ready` is therefore a **handoff-readiness** claim, not a **traffic-observed** claim.

### 3. verified real-runtime evidence

`verified real-runtime evidence` begins only after a human actually runs OpenClaw or Hermes through the prepared proxy path.

This tier is intentionally outside the repository-owned P18 preparation claim.

Once the real runtime is exercised, the stronger evidence labels come from [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md):

- `observed request`
- `validated observation`

Those labels should be applied to the resulting artifacts, not to the repository merely because the handoff docs exist.

## what real-runtime audit ready does and does not mean

### allowed claim

If the P18 preparation work is complete, the repository may say:

> the Compose/deploy/docs path is ready for `n01e0` to run OpenClaw / Hermes real-runtime verification through the checked-in proxy seam and inspect the resulting hostd audit artifacts

### disallowed claims

It must **not** say any of the following unless a later human-run verification produced the evidence:

- OpenClaw real traffic has already been observed
- Hermes real traffic has already been observed
- OpenClaw or Hermes has already produced a validated observation through the Compose path
- proxy CA/trust distribution is production-ready
- inline hold/deny is now production-safe

## acceptance checklist for this boundary

Use this checklist before calling the repository `real-runtime audit ready`.

### topology and runtime wiring

- [ ] topology **A / forward proxy** has checked-in runtime replacement guidance for both OpenClaw and Hermes
- [ ] topology **B / sidecar proxy** has checked-in runtime replacement guidance for both OpenClaw and Hermes
- [ ] the runtime/proxy lineage contract is explicit for session / agent / workspace identity

### trust bootstrap

- [ ] the dev minimum CA/trust bootstrap path exists for HTTPS interception trials
- [ ] the docs say what is manual, what is runtime-specific, and what is intentionally out of scope

### audit inspection

- [ ] the observed-runtime path is documented
- [ ] the audit/local-inspection path is documented
- [ ] the docs tell the operator how to distinguish mere wiring success from stronger observed/validated evidence

### human handoff

- [ ] OpenClaw has a handoff section with commands, expected evidence, and troubleshooting
- [ ] Hermes has a handoff section with commands, expected evidence, and troubleshooting
- [ ] the handoff docs state which evidence would count only as readiness and which would count as observed/validated real-runtime proof

### checked-in validation gates

- [ ] `docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample config`
- [ ] `docker compose -f deploy/compose.yaml --env-file deploy/compose.env.sample --profile sidecar config`
- [ ] `python3 -m py_compile deploy/proxy/mitmproxy-live-proxy.py`

## evidence boundary relative to P16

P16 fixed the evidence vocabulary for the repository-owned traffic path:

- `fixture preview`
- `observed request`
- `validated observation`

P18 adds an earlier readiness boundary in front of those labels for real OpenClaw / Hermes runtime verification.

In short:

- **P16 evidence words** describe what the captured traffic artifacts prove
- **P18 readiness words** describe whether the repository is prepared for a human to produce those artifacts with the real runtimes

If a PR only improves deployment/handoff prep, it should not describe itself as adding new observed-request or validated-observation evidence.

## review rule for follow-on P18 work

Before merging a P18 follow-on PR, reviewers should be able to answer:

1. did this change improve only stand-in topology preview?
2. did it raise the repository to real-runtime audit ready?
3. did it actually add human-run observed or validated real-runtime evidence?

If the answer is blurry, the PR is mixing preparation and evidence too loosely.

## related docs

- container proxy topologies: [`container-proxy-topologies.md`](container-proxy-topologies.md)
- real-traffic evidence boundary: [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md)
- live proxy interception foundation: [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md)
- live proxy coverage matrix: [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)
- deployment notes: [`../../deploy/README.md`](../../deploy/README.md)
- dev trust bootstrap runbook: [`../runbooks/real-runtime-proxy-trust-bootstrap-dev.md`](../runbooks/real-runtime-proxy-trust-bootstrap-dev.md)
- audit inspection runbook: [`../runbooks/real-runtime-audit-inspection-local.md`](../runbooks/real-runtime-audit-inspection-local.md)
- OpenClaw handoff runbook: [`../runbooks/openclaw-real-runtime-handoff-local.md`](../runbooks/openclaw-real-runtime-handoff-local.md)
- Hermes handoff runbook: [`../runbooks/hermes-real-runtime-handoff-local.md`](../runbooks/hermes-real-runtime-handoff-local.md)
