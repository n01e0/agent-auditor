# Coverage Matrix

This document fixes the initial coverage model for MVP planning.

Coverage states used throughout the product:

- `none` — no meaningful visibility
- `observe` — event visibility exists, but blocking / gating is not guaranteed
- `enforce` — the system can reliably block or gate before completion in the supported case
- `partial` — only some sub-cases are covered; the gap must be surfaced

## 1. Process coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| exec / fork visibility | eBPF | enforce-ish / partial | visibility should be strong; pre-exec blocking semantics need precise validation |
| child process linkage | eBPF + session linker | observe | depends on reliable parent / cgroup attribution |
| command line capture | eBPF | observe | subject to masking and truncation policy |
| cwd capture | runtime hint + procfs enrichment | partial | not guaranteed purely from kernel hook path |
| exit code capture | eBPF tracepoint | observe | needed for session replay |
| destructive command deny | policy + enforcement path | partial | exact block point must be validated in prototype |

## 2. Filesystem coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| sensitive path read monitoring | fanotify | observe / enforce | strong initial target |
| sensitive path write monitoring | fanotify | observe / enforce | strong initial target |
| rename / delete visibility | fanotify | observe | enforcement must be validated carefully |
| recursive directory protection | fanotify + path policy | partial | path explosion and mount behavior need care |
| file content capture | none by default | out of scope | metadata-first; content capture should not be default |
| mounted secret directory protection | fanotify | enforce | high-value early coverage area |

## 3. Network coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| outbound connect visibility | eBPF | observe | core MVP requirement |
| destination IP / port attribution | eBPF | observe | should be solid |
| domain attribution | userspace enrichment | partial | DNS correlation is inherently lossy |
| HTTP method / path | not kernel-first | out of MVP | application-layer parsing deferred |
| outbound deny / allowlist | policy + host integration | partial | exact enforcement mechanism may vary by environment |
| unexpected destination alerts | event + policy | observe | easy early win |

## 4. Secret coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| secret file path access | fanotify + policy | enforce | best early approximation |
| mounted secret path access | fanotify + policy | enforce | important for Kubernetes / container secrets |
| brokered secret retrieval | control-plane event | observe / enforce | requires integration point |
| env var secret usage | none initially | weak / open problem | hard to model safely at MVP |
| plaintext secret logging prevention | redaction pipeline | observe / enforce | must be handled in storage / UI path |

## 5. Session attribution coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| container id attribution | cgroup / runtime metadata | observe | required for all container runtimes |
| pod attribution | Kubernetes metadata enrichment | observe | cluster integration needed |
| agent session id mapping | runtime hint + linker | partial to strong | depends on supported runtime cooperation |
| descendant process inheritance | linker state | partial | must survive short-lived processes |

## 6. Browser / GWS phase-2 coverage

| Capability | Primary mechanism | MVP target | Notes |
|---|---|---:|---|
| browser action visibility | runtime / browser integration | phase 2 | not MVP |
| semantic GWS action logs | browser semantic layer | phase 2 | first SaaS target |
| sharing-permission gating | browser + policy | phase 2 | high-value target |
| outbound email / message gating | browser + policy | phase 2 | high-value target |

## 7. Live proxy semantic-governance coverage

The repository now fixes a dedicated live proxy semantic-governance coverage matrix for the downstream generic REST, GWS, GitHub, and messaging slices:

- [`live-proxy-coverage-matrix.md`](live-proxy-coverage-matrix.md)

That note is the authoritative place for:

- the shared live proxy input consumed by each slice
- the expected session-correlation method on the live path
- the currently checked-in semantic-action sample for each slice
- current fail-open / fail-closed posture
- current approval-hold feasibility
- the explicit difference between preview record projection and real inline interception

## 8. Coverage principles

1. `observe` is not equivalent to `enforce`.
2. The UI must show effective coverage per session and host.
3. Partial coverage must be operator-visible.
4. Unsupported cases must not silently pretend to be protected.
5. The first prototype should optimize for strong coverage in a narrow set of high-risk actions rather than broad weak coverage.
6. Fail-closed claims are only valid for action families that have a validated pre-completion enforcement path; everything else must fail open with explicit fallback reporting.

See [`failure-behavior.md`](failure-behavior.md) for the initial action-class policy.
