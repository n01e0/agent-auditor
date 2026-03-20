# hostd secret access PoC: known constraints

This note records the current constraints of the `agent-auditor-hostd` secret-access PoC after P4-7.

## Current limitations

1. **No live fanotify or broker interception yet**
   - the PoC models fanotify-shaped path access and broker-adapter requests, but the documented local path does not attach real kernel watchers or live broker hooks yet
   - current bootstrap output is produced from deterministic preview records assembled in userspace

2. **Observation scope is intentionally narrow**
   - the current path proves three secret-input families only:
     - secret files
     - mounted secrets
     - brokered secret requests
   - it does not yet cover environment-variable materialization, stdin-passed secrets, clipboard flows, process-memory access, or browser-based secret retrievals

3. **Secret taxonomy is still provisional**
   - current filesystem-side heuristics focus on `.ssh`, `.env`, `/run/secrets`, `/var/run/secrets`, and Kubernetes service-account paths
   - current broker-side modeling assumes a redaction-safe locator hint plus broker identity and action
   - this is good enough for the PoC seam, but it is not yet a complete secret inventory model

4. **Redaction behavior is shallow by design**
   - the current path preserves locator hints, classifier labels, and source metadata while avoiding plaintext secret values
   - however, locator hints are still raw identifiers such as paths or broker references, so downstream privacy posture depends on how those identifiers are chosen
   - there is no hashing, tokenization, or sensitivity-tiered redaction policy yet

5. **Policy behavior is intentionally tiny**
   - the checked-in preview policy is `examples/policies/secret_access.rego`
   - the default path proves a few outcomes only:
     - unmatched env-file access -> `allow`
     - SSH secret-file access -> `require_approval`
     - brokered secret retrieval -> `require_approval`
     - Kubernetes service-account mounted secret access -> `deny`
   - it is not yet a comprehensive secret-governance policy model

6. **Approval flow stops at record creation**
   - `require_approval` currently enriches the event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, resolution path, or resumed secret action execution after approval yet

7. **Persistence is bootstrap-local and resettable**
   - secret audit records and approval requests are appended to JSONL under `target/agent-auditor-hostd-secret-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, redaction reprocessing, or multi-process coordination

8. **Initial failure behavior is split and still mostly fail-open**
   - filesystem-backed secret paths may eventually inherit a narrow fail-closed sensitive-path subset, and broker retrievals may eventually fail closed at a real broker boundary
   - today’s preview-only paths should still be interpreted as observe / fallback behavior rather than live pre-access secret enforcement

9. **No real enforcement or pre-access gating yet**
   - the PoC proves taxonomy, normalization, Rego evaluation, approval-request derivation, and local record persistence
   - it does not yet block file opens, delay mounted-secret reads, intercept broker RPCs, or resume actions after approval resolution

10. **Fixture-backed smoke coverage is intentional**
   - the dedicated secret smoke test validates stable bootstrap preview output from hostd
   - it is not evidence that the same behavior has been validated against live fanotify streams, container-mounted secret paths in production, or real broker integrations

11. **Linux-local and single-host assumptions still apply**
    - this path assumes Linux and a Rust development workflow
    - container runtime nuances, Kubernetes production behavior, broker credential exchange, host hardening, and cross-host coordination are still outside this runbook-level PoC

## Practical interpretation

Today’s secret-access PoC is good for:

- stabilizing the internal classify / evaluate / record split
- proving the shape of normalized `secret_access` events
- proving a first secret taxonomy for files, mounts, and broker requests
- proving a narrow Rego decision path with `allow` / `deny` / `require_approval`
- proving approval-request creation and local audit-record inspection
- keeping CI coverage around the current secret-access design

It is **not yet** good evidence of:

- production-ready fanotify secret monitoring
- production-ready brokered secret interception
- complete secret discovery coverage
- durable privacy-preserving audit storage
- real-time enforcement safety around secret reads or retrievals
- Kubernetes-grade or multi-host operational behavior

## Related docs

- module boundary: [`hostd-secret-access-poc.md`](hostd-secret-access-poc.md)
- local runbook: [`../runbooks/hostd-secret-access-poc-local.md`](../runbooks/hostd-secret-access-poc-local.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- product requirements: [`../PRD.md`](../PRD.md)
