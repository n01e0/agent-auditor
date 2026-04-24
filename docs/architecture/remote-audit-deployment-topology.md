# remote audit deployment topology

This note fixes the **minimum checked-in deployment topology** for the remote-audit phase.

The purpose of P19-2 is narrow:

- define where `remote hostd` is allowed to live
- define where the `remote durable store` is allowed to live
- make the trust boundary explicit so follow-on implementation work does not slide back into same-host preview storage

This note builds on [`remote-audit-integrity-boundary.md`](remote-audit-integrity-boundary.md).
The concrete `live proxy -> remote hostd` handoff that crosses this topology boundary is documented in [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md).
It does **not** choose the final store engine, wire protocol, or production hardening posture. The checked-in tamper-evident format choice is documented in [`remote-audit-tamper-evident-strategy.md`](remote-audit-tamper-evident-strategy.md).

## minimum topology at a glance

The minimum honest remote-audit shape is:

```text
[ monitored target boundary ]
Hermes/OpenClaw runtime
    -> forward proxy or sidecar proxy
    -> optional local preview/spool state
    => network handoff

[ remote audit boundary ]
remote hostd ingest
    -> remote audit persistence path
    -> operator/local inspection path

[ durable evidence boundary ]
remote durable store
```

The important rule is simple:

- `remote hostd` must be outside the monitored target boundary
- the `remote durable store` must also be outside the monitored target boundary
- the monitored target must not own the only writable copy of the final evidence

## minimum deployment roles

### 1. monitored runtime node

This is the machine or container host running the workload being observed.

It may contain:

- Hermes or OpenClaw runtime containers
- the checked-in forward proxy or sidecar proxy
- a local preview cache, spool, or observed-runtime staging directory

It must be treated as **not trusted** to preserve final evidence.

Anything on this node is allowed to help with:

- request interception
- redaction-safe ingress preparation
- temporary buffering during disconnects
- debugging during bring-up

It is **not** allowed to be the final durable audit store.

### 2. remote audit node

This is the first separately operated machine/VM/node that receives the observed-runtime handoff.

It owns:

- `remote hostd`
- the first boundary-crossing audit ingress endpoint
- policy/audit transformation work that should no longer depend on the monitored target's local filesystem
- operator-facing inspection of the remote audit path

Minimum rule:

- this node must not share the monitored target's mutable host/volume boundary

For the minimum checked-in topology, this node may also run the first version of the durable store **if** that store remains outside the monitored target boundary and is not writable from the monitored runtime side.

### 3. remote durable store

This is the final evidence location used for durable audit claims.

In the minimum checked-in topology, it may be implemented either as:

- a dedicated store service on the remote audit node, or
- a separate remote store host behind the remote audit node

Both are acceptable **only if** all of the following stay true:

- the monitored target cannot write to or rewrite the store directly as ordinary local state
- the store is not mounted back into the monitored target as a writable volume
- the final evidence path is owned from the remote audit side, not the monitored runtime side

A separate store host is a stronger later shape, but it is **not required** for the minimum topology fixed by this task.

## trust-boundary rule

The minimum trust split for P19 is therefore:

### boundary A: monitored target

Contains:

- runtime containers
- local proxy containers
- any same-host preview/spool/cache paths

Security assumption:

- compromise here must be assumed to allow mutation or deletion of local state

### boundary B: remote audit ingress

Contains:

- the network hop that leaves the monitored target boundary
- `remote hostd` as the first separately operated receiver

Security assumption:

- this is the first place where the repository may start making a stronger audit-integrity claim than local preview state

### boundary C: durable evidence

Contains:

- the append-oriented final store
- later tamper-evident metadata/materialization

Security assumption:

- this boundary must remain under remote audit ownership rather than monitored-target ownership

## minimal accepted shape

The minimum accepted checked-in topology is a **two-boundary remote deployment**:

```text
host A / monitored target
  runtime + proxy + optional local spool

host B / remote audit
  remote hostd + remote durable store
```

This is acceptable because:

- host B is outside host A's mutable trust boundary
- host A's local spool is no longer the only persisted copy
- the durable evidence path is owned on the remote side

This is the minimum because it keeps the topology reviewable while still satisfying the integrity rule from P19-1.

## stronger later shape

A stronger later deployment may split the remote side further:

```text
host A / monitored target
  runtime + proxy + optional local spool

host B / remote audit ingest
  remote hostd

host C / durable evidence
  append-only/tamper-evident store
```

That is a valid future direction, but it is not the minimum required by this task.

## explicitly insufficient shapes

The repository must treat all of these as insufficient for the final remote-audit claim:

### same-host all-in-one

```text
runtime + proxy + hostd + durable store
all on the monitored host
```

Why insufficient:

- no trust boundary crossing happened before the final evidence copy

### same-compose shared volume

```text
runtime container -> shared Docker volume <- hostd/store container
```

Why insufficient:

- the final evidence still lives on the monitored target's same mutable host/volume boundary

### remote store mounted writable back into the monitored host

Why insufficient:

- remote naming does not help if the monitored target still has ordinary write access to the final copy

## deployment rules that follow from this topology

Any checked-in remote-audit deployment/runbook/compose work should preserve these rules:

1. the monitored runtime sends data **out** to `remote hostd`; it does not own the remote store path
2. local spool/replay state is optional and non-authoritative
3. investigator-facing durable evidence is read from the remote side
4. if connectivity breaks, any local retry buffer must remain explicitly a spool rather than the final audit trail
5. later tamper-evident metadata attaches to the remote durable store boundary, not to same-host preview storage

## review questions for follow-on P19 work

Before merging a follow-on PR, reviewers should be able to answer:

1. which machine/node is the monitored target boundary?
2. where does the first network handoff into `remote hostd` happen?
3. where is the final durable store?
4. can the monitored target still rewrite that final store as ordinary local state?

If question 4 is "yes", the topology is still not sufficient.

## related docs

- remote audit integrity boundary: [`remote-audit-integrity-boundary.md`](remote-audit-integrity-boundary.md)
- observed-runtime remote ingress contract: [`observed-runtime-remote-ingress-contract.md`](observed-runtime-remote-ingress-contract.md)
- remote audit tamper-evident strategy: [`remote-audit-tamper-evident-strategy.md`](remote-audit-tamper-evident-strategy.md)
- architecture overview: [`overview.md`](overview.md)
- container proxy topologies: [`container-proxy-topologies.md`](container-proxy-topologies.md)
- real-runtime audit readiness boundary: [`real-runtime-audit-readiness-boundary.md`](real-runtime-audit-readiness-boundary.md)
- deployment hardening minimums: [`deployment-hardening-minimums.md`](deployment-hardening-minimums.md)
