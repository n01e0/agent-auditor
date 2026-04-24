# remote audit integrity boundary

This note fixes the minimum integrity / threat boundary for the repository's remote-audit phase.

The purpose of P19-1 is narrow:

- stop treating "we wrote a record somewhere" as sufficient audit evidence
- define the trust boundary required before the repository may claim durable audit integrity
- make explicit that a store living with the monitored target is useful for preview/debugging, but insufficient as the final audit trail

This note does **not** pick the final remote topology, store engine, or tamper-evident mechanism. Those are follow-on tasks.

## core rule

The monitored target is not trusted to preserve its own final evidence.

That means:

- the runtime being observed
- its container/sidecar
- the same mutable host or volume boundary that runtime can normally influence

must all be treated as inside the monitored threat boundary.

A store that lives inside that same boundary may still be useful as:

- a local preview cache
- a replay buffer
- a transient operator convenience copy

But it is **not sufficient** to count as the durable audit trail.

## explicit wording rule

Repository docs, tests, runbooks, and PRs should follow this rule:

> a store colocated with the monitored target is insufficient as audit evidence

More specifically:

- if the monitored workload can delete, rewrite, truncate, replace, or roll back the only persisted copy, the repository must not describe that copy as the final audit trail
- if the only store is on the same host/volume trust boundary as the monitored target, the repository may describe it as local preview state or a spool, but not as sufficient durable audit evidence
- `tamper-evident` claims require a later boundary where silent mutation by the monitored target is no longer ordinary local write access

## three storage roles that must stay separate

### 1. local runtime state

This is storage that exists next to the monitored runtime for convenience, buffering, or smoke validation.

It may support:

- local JSONL inspection
- temporary disconnect buffering
- smoke-friendly previews
- operator debugging during bring-up

It does **not** support the stronger claim that the final audit evidence survived compromise or mutation of the monitored target boundary.

### 2. boundary-crossing audit ingress

This is the first point where observed runtime data leaves the monitored target boundary and enters a separately operated audit path.

This layer owns:

- a documented handoff from observed runtime/proxy/hostd capture into audit ingest
- provenance that the record crossed out of the monitored target boundary
- buffering/retry semantics that preserve evidence lineage rather than hiding drops

This layer does **not** by itself guarantee durable integrity, but it is the minimum seam required before the repository can start making a stronger remote-audit claim.

### 3. durable evidence store

This is the final store used for investigator-facing audit evidence.

Minimum properties for this role:

- separate trust boundary from the monitored target
- append-oriented persistence or an equivalently constrained write path
- integrity metadata such as hash chaining, signatures, or another tamper-evident mechanism
- inspection/reconstruction path that lets a third party verify provenance and integrity claims

The exact mechanism is a later design choice. The boundary requirement is fixed now.

## threat-model consequence

If an attacker or faulty runtime can compromise the monitored target boundary, the repository should assume they can also alter any colocated store on that same boundary.

Therefore a colocated store cannot be the only copy that supports claims such as:

- durable audit record
- append-only evidence path
- tamper-evident audit trail
- independent third-party verification

At best, that colocated store is a staging area whose contents must be exported across the boundary before they count as final evidence.

## allowed and disallowed claims in this phase

### allowed today

The repository may say:

- local preview or local inspection data was written next to the monitored runtime
- observed runtime data reached a boundary-crossing ingress seam
- a later remote store is intended to become the durable evidence path

### not allowed without the later boundary

The repository must **not** say:

- the monitored runtime's own local store is sufficient durable audit evidence
- a same-host Docker volume is by itself a trustworthy final audit trail
- remote-audit integrity is achieved before evidence crosses out of the monitored target boundary

## review rule for follow-on P19 work

Before merging a follow-on remote-audit PR, reviewers should be able to answer:

1. does this change still rely on colocated preview/spool state only?
2. where is the first boundary-crossing audit ingress?
3. what separate durable evidence boundary will make the final integrity claim honest?

If the PR cannot answer those questions, it is still mixing preview storage with audit evidence too loosely.

## interaction with other evidence docs

This integrity boundary sits underneath the repository's existing evidence vocabulary.

- [`real-runtime-audit-readiness-boundary.md`](real-runtime-audit-readiness-boundary.md) says when the repo is ready for a human to run the real runtime path
- [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md) says when a request is merely observed vs fully validated

This document answers a different question:

- **where must the final evidence live so the audit-integrity claim is honest?**

A path may be real-runtime ready, or even produce an observed request, while still failing this stronger integrity boundary if the only durable copy remains colocated with the monitored target.

## related docs

- architecture overview: [`overview.md`](overview.md)
- real-runtime audit readiness boundary: [`real-runtime-audit-readiness-boundary.md`](real-runtime-audit-readiness-boundary.md)
- real-traffic observation boundary: [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md)
- deployment hardening minimums: [`deployment-hardening-minimums.md`](deployment-hardening-minimums.md)
