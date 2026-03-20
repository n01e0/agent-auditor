# hostd filesystem PoC: known constraints

This note records the current constraints of the `agent-auditor-hostd` filesystem PoC after P2-7.

## Current limitations

1. **No live fanotify attachment yet**
   - the PoC names a `fanotify` collector boundary, but the documented local path does not call `fanotify_init`, install live marks, or consume kernel events yet
   - current bootstrap output is produced from preview records assembled in userspace

2. **Watch coverage is still design-level, not runtime-level**
   - `watch.rs` defines ownership and handoff shape for sensitive roots and mounted-secret directories
   - it does not yet validate recursive mark behavior, mount transitions, rename/delete visibility, or enforcement semantics on a real host

3. **Sensitive path detection is intentionally provisional**
   - current classification only targets:
     - `.ssh`
     - `.env` / `.env.*`
     - mounted secrets under `/run/secrets`, `/var/run/secrets`, and Kubernetes service-account paths
   - this is useful for an MVP PoC, but it is not a complete secret-detection model

4. **Policy behavior is intentionally narrow**
   - the checked-in preview policy is `examples/policies/sensitive_fs.rego`
   - the default path proves `allow`, `require_approval`, and a narrow `deny` case for sensitive writes
   - this is still a minimal policy surface rather than a complete filesystem authorization model

5. **Persistence is bootstrap-local and resettable**
   - audit records and approval requests are appended to JSONL files under `target/agent-auditor-hostd-poc-store/`
   - the PoC store resets that directory on bootstrap, so this is not durable product storage yet
   - there is no lookup API, retention policy, compaction, or multi-process coordination

6. **Approval flow stops at record creation**
   - `require_approval` currently enriches event metadata and creates a pending `ApprovalRequest`
   - there is no approval inbox, reviewer workflow, resolution path, or event replay after approval yet

7. **Initial failure behavior is still mostly fail-open in practice**
   - the docs now reserve fail-closed claims for a future validated fanotify enforcement subset only
   - today’s preview path should still be interpreted as observe / fallback behavior, not as proof of a live fail-closed read/write gate

8. **No live kernel enforcement yet**
   - the PoC now proves observation, normalization, Rego evaluation, preview hold / deny routing, and record creation
   - it still does not block reads/writes on a live host, hold file descriptors, or coordinate with agent execution before access proceeds

9. **Fixture-driven smoke coverage is intentional**
   - the smoke test validates stable preview output from the hostd bootstrap path
   - it is not evidence that the same behavior has been validated against live kernel fanotify traffic

10. **Linux-local assumptions still apply**
   - this path assumes Linux and a Rust development workflow
   - container runtime nuances, Kubernetes production behavior, and host hardening requirements are still outside this runbook-level PoC

## Practical interpretation

Today’s filesystem PoC is good for:

- stabilizing internal module boundaries
- proving the shape of normalized filesystem events
- proving a minimal Rego decision path
- proving approval/audit record creation and local inspection
- keeping CI coverage around the current fanotify-shaped design

It is **not yet** good evidence of:

- production-ready fanotify attachment behavior
- broad secret-path detection accuracy
- real enforcement safety
- durable approval/audit storage
- multi-host or Kubernetes-grade operational behavior

## Related docs

- module boundary: [`hostd-filesystem-poc.md`](hostd-filesystem-poc.md)
- local runbook: [`../runbooks/hostd-filesystem-poc-local.md`](../runbooks/hostd-filesystem-poc-local.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- product requirements: [`../PRD.md`](../PRD.md)
