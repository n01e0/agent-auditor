# observed-runtime remote ingress contract

This note fixes the minimum contract for sending `observed-runtime` data from the live proxy on the monitored target boundary to `remote hostd` on the remote-audit boundary.

The purpose of P19-3 is narrow:

- define what must cross the boundary when the proxy stops writing directly into a same-host shared volume
- keep the existing redaction-safe live-request vocabulary intact
- make explicit how the remote handoff differs from the checked-in local-volume preview path

This note does **not** choose the final wire protocol, auth/mTLS mechanism, durable-store engine, or tamper-evident format.

## core rule

The remote ingress contract is a **boundary-crossing handoff**, not a shared-filesystem layout.

That means:

- the monitored-side live proxy may still keep local spool state
- `remote hostd` owns ingress acceptance on the remote side
- the monitored target does **not** get ordinary write access to the remote audit path just because it can emit requests toward it

The checked-in redaction rule also stays unchanged: this contract moves **metadata**, not raw content.

## what stays stable from the current live-proxy seam

P19-3 does **not** redefine the live request shape.

The request payload handed across the remote ingress boundary is still the checked-in redaction-safe [`GenericLiveActionEnvelope`](generic-live-action-envelope.md).
That means the remote handoff keeps the same vocabulary already fixed for the local observed-runtime path:

- `source`
- `request_id`
- `correlation_id`
- `session_id`
- `agent_id`
- `workspace_id`
- `provider_hint`
- `correlation_status`
- `live_surface`
- `transport`
- `method`
- `authority`
- `path`
- `headers`
- `body_class`
- `auth_hint`
- `target_hint`
- `mode`
- `content_retained`

So the contract change here is about **how the envelope crosses the boundary**, not about inventing a new provider or request schema.

## minimum logical units

The remote ingress contract needs three logical pieces.

### 1. session-lineage bootstrap

Before `remote hostd` can treat request envelopes as part of one observed runtime session, it must know the same lineage that the checked-in local session directory currently carries.

Minimum lineage fields:

- `session_id`
- `agent_id`
- optional `workspace_id`

Rules:

- this bootstrap must be idempotent for a given session lineage
- a retry with the same lineage is allowed
- a conflicting rewrite for the same session identity is not allowed
- the remote transport may encode this as an explicit handshake, a first-record declaration, or an equivalent session-open message

In other words, the current local session-directory naming rule becomes an explicit remote ingress contract instead of an implicit shared-volume convention.

### 2. observed request append

The actual observed request unit is one redaction-safe `GenericLiveActionEnvelope`.

Rules:

- each append belongs to one session lineage
- per-session ordering must be preserved
- the transport may provide ordering either with an explicit monotonic sequence or with an equivalent ordered append channel
- `request_id` must stay stable across retries so the remote side can deduplicate safely
- the monitored-side proxy may batch multiple envelopes, but batching must not change envelope contents or lineage

This keeps the current proxy seam vocabulary while moving from filesystem append to remote append semantics.

### 3. ingress acceptance / replay boundary

Remote ingress must make acceptance explicit.

Minimum semantics:

- `remote hostd` must be able to say which session-lineage declaration and which request appends it has accepted
- the monitored-side proxy may keep an optional local retry spool for unacknowledged appends
- duplicate delivery is acceptable if remote ingest can deduplicate by stable request identity
- retries, drops, and replay state must be visible operationally rather than hidden inside silent local overwrite behavior

This is the main behavioral difference from the current local-volume path: the remote side now owns acceptance state instead of relying on a same-host file plus hostd-local cursor scanning.

## sender / receiver responsibilities

### monitored-side live proxy

The live proxy on the monitored target boundary owns:

- generating the redaction-safe live envelope
- attaching stable session lineage
- preserving retryable sender state when the remote side is unavailable
- never expanding the contract to raw bodies, raw headers, tokens, or message content

It does **not** own:

- the authoritative remote cursor
- the remote durable evidence store
- final audit integrity claims

### remote hostd

`remote hostd` on the remote audit boundary owns:

- accepting the session-lineage and request-append handoff
- recording remote-side receipt/acceptance as the first cross-boundary audit ingress fact
- deduplicating/replaying safely when sender retries occur
- handing accepted records into the later remote audit persistence path

It does **not** need to decide the final durable-store engine in this task, but it is the first receiver that is outside the monitored target boundary.

## redaction and evidence semantics

This task does **not** change the repository's evidence vocabulary.

### fixture preview

Still means synthetic repository-owned preview input.
No remote ingress is required.

### observed request

Still means a real redaction-safe observed request reached the checked-in live-request path.
For the remote topology, that means `remote hostd` accepted the boundary-crossing ingress handoff.

### validated observation

Still requires a later provider/audit record to correlate back to the observed request.
Remote ingress alone is not enough.

So P19-3 changes the **handoff boundary**, not the meaning of `fixture preview`, `observed request`, or `validated observation`.

## delta from the checked-in local-volume contract

The repository's current Compose/dev path uses a same-host local-volume dependency:

```text
runtime -> live proxy -> shared local volume (/state) <- hostd
```

That path is still useful for preview, smoke tests, and bring-up. But the remote ingress contract differs in a few important ways.

### transport

- **current local-volume path:** the proxy writes session-shaped files directly into a shared filesystem path under `/state/agent-auditor-hostd-live-proxy-observed-runtime/...`
- **remote ingress path:** the proxy sends session lineage + request appends over a boundary-crossing transport to `remote hostd`

### authority

- **current local-volume path:** the monitored-side proxy can directly create or rewrite the local preview path
- **remote ingress path:** the monitored side may submit records, but `remote hostd` owns whether the remote ingress accepted them

### replay

- **current local-volume path:** replay/cursor behavior is largely expressed as local file append plus hostd-side cursor scanning
- **remote ingress path:** replay is expressed as sender retry + remote acceptance/dedup semantics

### trust claim

- **current local-volume path:** same-host state is preview/spool only and is insufficient as final audit evidence
- **remote ingress path:** this is the first honest boundary crossing that can feed a stronger remote-audit story

### inspection source of truth

- **current local-volume path:** operators inspect the same-host `/state` tree for preview/debugging
- **remote ingress path:** operators should read acceptance and downstream audit state from the remote side; any sender-local copy is only spool/debug state

## non-goals fixed by this note

P19-3 does **not** yet choose:

- HTTP vs gRPC vs message-bus vs another wire protocol
- mTLS / authn / authz details for the remote receiver
- whether the remote durable store lives on the same remote audit node or a later split host
- the final append-only or tamper-evident mechanism
- operator UI / export surfaces for the remote path

Those are follow-on tasks. The contract here is only the minimum honest ingress boundary.

## review questions for follow-on remote-ingest work

Before merging a follow-on implementation PR, reviewers should be able to answer:

1. where does session lineage get declared to `remote hostd`?
2. what is the exact unit of append: one `GenericLiveActionEnvelope`, a batch, or a transport wrapper around that envelope?
3. how does the sender know what the remote side accepted?
4. what local state remains only a spool/debug copy rather than the final audit record?
5. does the change preserve the existing `fixture preview` / `observed request` / `validated observation` meanings?

If those answers are unclear, the implementation is probably still relying too much on the old local-volume mental model.

## related docs

- container proxy topologies: [`container-proxy-topologies.md`](container-proxy-topologies.md)
- live proxy HTTP request contract: [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md)
- generic live action envelope: [`generic-live-action-envelope.md`](generic-live-action-envelope.md)
- remote audit integrity boundary: [`remote-audit-integrity-boundary.md`](remote-audit-integrity-boundary.md)
- remote audit deployment topology: [`remote-audit-deployment-topology.md`](remote-audit-deployment-topology.md)
- real-traffic observation boundary: [`real-traffic-observation-boundary.md`](real-traffic-observation-boundary.md)
