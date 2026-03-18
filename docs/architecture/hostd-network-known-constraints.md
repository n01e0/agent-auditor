# hostd network PoC: known constraints

This note records the current constraints of the `agent-auditor-hostd` network PoC after P3-7.

## Current limitations

1. **No live outbound eBPF attachment yet**
   - the PoC names an `ebpf` collector boundary, but the documented local path does not attach real connect hooks yet
   - current bootstrap output is produced from deterministic preview records assembled in userspace

2. **No live kernel event transport yet**
   - the current path does not consume live ring-buffer/perf-buffer traffic from kernel space
   - there is no validation yet of dropped events, backpressure, attach ordering, or teardown behavior on a real host

3. **Observation scope is intentionally tiny**
   - the preview path proves outbound `connect` event shaping only
   - it does not yet cover accept paths, long-lived flow tracking, DNS transport observation, or broader socket lifecycle behavior

4. **Destination classification is still provisional**
   - current classification focuses on destination IP / port / protocol, address family, destination scope, and an optional domain hint
   - this is good enough for the PoC shape, but it is not a complete network-destination model yet

5. **Domain attribution remains weak by design**
   - the checked-in strategy only emits `domain_candidate` from unique exact-IP matches in a recent DNS-answer cache
   - it does not yet use TTL/freshness, resolver identity, TLS SNI, HTTP host headers, or broader attribution heuristics

6. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/network_destination.rego`
   - the default path proves three outcomes only:
     - allowlisted public TLS domain -> `allow`
     - public unknown destination -> `require_approval`
     - public SMTP destination -> `deny`
   - it is not yet a comprehensive outbound policy model

7. **Persistence is bootstrap-local and resettable**
   - network audit records are appended to JSONL under `target/agent-auditor-hostd-network-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, or multi-process coordination

8. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, resolution path, or resumed action execution after approval yet

9. **No real network enforcement or gating yet**
   - the PoC proves observation, normalization, Rego evaluation, approval-request derivation, and audit persistence
   - it does not yet block connects, hold sockets, or coordinate with agent execution before outbound traffic proceeds

10. **Fixture-backed smoke coverage is intentional**
    - the dedicated network smoke test validates stable bootstrap preview output from hostd
    - it is not evidence that the same behavior has been validated against live kernel connect traffic

11. **Linux-local assumptions still apply**
    - this path assumes Linux and a Rust development workflow
    - container runtime nuances, Kubernetes production behavior, NAT edge cases, and host hardening requirements are still outside this runbook-level PoC

## Practical interpretation

Today’s network PoC is good for:

- stabilizing the internal observe / classify / emit split
- proving the shape of normalized `network_connect` events
- proving a minimal domain-attribution hint path
- proving a narrow Rego decision path with `allow` / `deny` / `require_approval`
- proving approval-request creation and local audit-record inspection
- keeping CI coverage around the current eBPF-shaped design

It is **not yet** good evidence of:

- production-ready outbound eBPF attach behavior
- robust hostname attribution accuracy
- broad outbound-policy coverage
- real-time enforcement safety
- durable multi-process audit storage
- Kubernetes-grade or multi-host operational behavior

## Related docs

- module boundary: [`hostd-network-poc.md`](hostd-network-poc.md)
- domain attribution strategy: [`hostd-network-domain-attribution.md`](hostd-network-domain-attribution.md)
- local runbook: [`../runbooks/hostd-network-poc-local.md`](../runbooks/hostd-network-poc-local.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- product requirements: [`../PRD.md`](../PRD.md)
