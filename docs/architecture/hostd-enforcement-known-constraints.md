# hostd enforcement foundation: known constraints

This note records the current cross-cutting constraints of the `agent-auditor-hostd` enforcement foundation after the P5 documentation slice.

It sits above the filesystem/process-specific PoCs and records what is true about the shared enforcement seam itself.

## Current limitations

1. **The shared enforcement seam is still preview-only**
   - the current path routes policy output into `allow` / `hold` / `deny` preview outcomes
   - it does not prove that the host can actually interrupt a live filesystem access or process exec before completion

2. **Directive selection is stronger than runtime enforcement today**
   - the system can express what should happen for a normalized event
   - the runtime still lacks the live interception layer needed to guarantee that outcome on a real host

3. **Approval-hold currently stops at reflected metadata**
   - a `hold` outcome can create or enrich a pending approval record with approval id / expiry
   - there is still no reviewer inbox, resume path, timeout recovery action, or replay of the original work after approval resolution

4. **Deny currently stops at recorded intent**
   - a `deny` outcome can be reflected into events and local audit records
   - it does not yet mean the underlying filesystem access or process exec was prevented on a running host

5. **Coverage-gap behavior is defined earlier than coverage validation**
   - the shared seam already has vocabulary for fallback and coverage gaps
   - host-level validation of when filesystem/process enforcement is truly enforce-capable still needs later runtime work

6. **The seam currently covers only filesystem and process previews**
   - those are the two action classes threaded through the foundation today
   - network and secret-access have policy/audit-shaped records, but they are not yet live consumers of this same local deny/hold runtime seam
   - the new GWS posture catalog only prioritizes actions and fixes preview posture labels; it is not evidence of inline GWS hold or deny capability

7. **Smoke coverage is record-level, not host-level**
   - focused smoke tests prove stable bootstrap output for filesystem and process preview cases
   - they do not validate behavior against live fanotify, live pre-exec hooks, or degraded-runtime conditions

8. **Fail-open / fail-closed claims remain policy-constrained**
   - the docs now describe when fail-closed would be allowed
   - until a validated intercept path exists, the enforcement foundation should still be interpreted as fail-open preview behavior with explicit fallback vocabulary

9. **Local persistence is still bootstrap-local and resettable**
   - approval/audit artifacts remain JSONL bootstrap outputs under `target/`
   - there is still no durable service-backed audit store, multi-process coordination, or retention contract for enforcement records

10. **The current boundary is designed for evolution, not final operator semantics**
   - names like `decision`, `hold`, `deny`, and `audit` are intentionally stable ownership boundaries
   - the actual runtime mechanics beneath them are expected to change as live enforcement lands

11. **GWS priority is defined earlier than GWS runtime enforcement**
   - `drive.permissions.update` and `gmail.users.messages.send` are now fixed at `p0`, `drive.files.get_media` at `p1`, and `admin.reports.activities.list` at `p2`
   - those labels keep the preview policy and docs aligned, but they still stop at policy, approval-request projection, and audit persistence rather than live API-side interruption

## Practical interpretation

Today’s enforcement foundation is good for:

- stabilizing the ownership split between decision routing, hold, deny, and audit
- keeping filesystem/process preview behavior aligned on the same directive vocabulary
- proving that realized outcomes can be reflected back into shared event/approval shapes
- documenting what later live runtime work must preserve

It is **not yet** good evidence of:

- production-safe pause/resume behavior
- production-safe deny semantics
- validated fail-closed coverage
- operator-facing approval workflows
- durable enforcement data management

## Related docs

- enforcement boundary: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- local runbook: [`../runbooks/hostd-enforcement-foundation-local.md`](../runbooks/hostd-enforcement-foundation-local.md)
- filesystem constraints: [`hostd-filesystem-known-constraints.md`](hostd-filesystem-known-constraints.md)
- process boundary: [`hostd-process-enforcement-poc.md`](hostd-process-enforcement-poc.md)
- failure behavior policy: [`failure-behavior.md`](failure-behavior.md)
