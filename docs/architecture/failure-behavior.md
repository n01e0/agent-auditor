# initial fail-open / fail-closed policy

This note records the first explicit failure-behavior policy for MVP planning.

It is intentionally conservative about what may claim **fail-closed** behavior. The system should only claim fail-closed semantics for a narrow action family when the host can actually intercept that action before completion and keep the deny / approval-hold state intact long enough to decide.

Everything else must be treated as **fail-open with explicit fallback reporting**, not as silently protected.

## Core rule

The product must distinguish between two different cases:

1. **validated enforced subset**
   - the host has a real interception point for the action class
   - the interception point runs before completion
   - the runtime can keep a deny or approval hold active without guessing
   - health / coverage checks say that path is active

   In this case, deny / hold failures should be treated as **fail-closed**.

2. **observe-only or degraded subset**
   - the host can only observe after the fact, or
   - the host cannot prove the intercept path is active, or
   - the supported shape is only partial and the attempted action lands outside it

   In this case, behavior is **fail-open**, but the event / approval / audit path must record an explicit fallback such as:
   - `observe_only_fallback`
   - a coverage-gap reason
   - the effective coverage level shown to operators

## Initial action-class policy

### Filesystem

**Initial target posture**

- fail-closed only for the narrow, validated sensitive-path subset once live fanotify-based pre-access interception is proven
- fail-open everywhere else

**What may eventually claim fail-closed**

- sensitive path reads or writes on explicitly supported paths
- mounted secret directory access on explicitly supported paths
- approval-gated reads only when the host can truly hold the access before completion

**What must remain fail-open for now**

- the current preview-only PoC path
- rename / delete / move edge cases
- unsupported recursive-mark cases
- mount-transition ambiguity
- any host where fanotify enforcement health is unknown or degraded

**Constraint**

A filesystem path may not be labeled `enforce` just because policy returned `deny` or `require_approval`. It only becomes fail-closed after the runtime interception path is validated on that exact supported subset.

### Process

**Initial target posture**

- fail-open by default in the MVP prototype phase
- move to fail-closed only after a specific pre-exec block / gate point is validated

**Why**

- process visibility is ahead of process blocking today
- pre-exec gating semantics differ across hooks and need careful validation to avoid deadlocks, partial execution, or misleading audit claims

**Constraint**

Observed process events must never be described as blocked unless the block happened before the exec path completed.

### Network

**Initial target posture**

- fail-open by default until a concrete egress-control integration exists and is health-checked

**What may eventually claim fail-closed**

- deny / allowlist decisions backed by a validated firewall / CNI / host-egress control path

**What must remain fail-open for now**

- the current connect-observation PoC
- cases that rely only on lossy hostname attribution
- hosts where the egress-control integration is absent or degraded

**Constraint**

A deny derived from destination policy is still fail-open unless the host can stop the connection before it leaves.

### Secret access

**Initial target posture**

- filesystem-backed secret paths inherit the filesystem rule
- brokered secret retrieval may become fail-closed only at a broker boundary that can deny or hold the retrieval before materialization
- other secret forms remain fail-open / uncovered initially

**What must remain fail-open for now**

- env-var materialization
- stdin / clipboard / process-memory secret flows
- preview-only broker adapters without real interception

**Constraint**

Secret auditing may be strong before secret enforcement is strong. The docs and UI must not collapse those into one claim.

## Approval and control-plane dependency rule

For actions already inside a **validated enforced subset**:

- if policy says `deny`, inability to complete the deny path should be treated as fail-closed
- if policy says `require_approval`, inability to create or maintain the approval hold should be treated as fail-closed
- approval-service or control-plane unavailability must not silently downgrade a validated hold into an unrecorded allow

For actions **outside** the validated enforced subset:

- the system must fail-open
- the record should show that approval / enforcement could not be guaranteed

This keeps the product honest: conservative only where the runtime can really be conservative.

## Coverage degradation rule

Whenever a host loses an intercept path, policy bundle compatibility, or approval coordination needed for a validated enforced subset, it should:

1. drop the effective coverage claim from `enforce` to `partial` or `observe`
2. emit an explicit coverage-gap / degradation reason
3. keep recording what the policy would have decided
4. avoid pretending the action was blocked when it was only observed

## MVP documentation constraints

The following statements should remain true across docs until real enforcement lands:

- `observe` is not `enforce`
- `deny` policy output is not automatically fail-closed behavior
- `require_approval` policy output is not automatically a real pause
- preview records may model the intended outcome before the live runtime can guarantee it
- unsupported or degraded cases must surface explicit fallback behavior to operators

## Near-term planning consequence

This gives the next enforcement tasks a simple rule:

- **validated narrow path** -> fail-closed is allowed
- **everything else** -> fail-open with explicit fallback metadata

That preserves conservative behavior for high-risk controls without overclaiming what the current host integrations can really guarantee.

## Related docs

- architecture overview: [`overview.md`](overview.md)
- coverage matrix: [`coverage-matrix.md`](coverage-matrix.md)
- live preview coverage visibility: [`live-preview-coverage-visibility.md`](live-preview-coverage-visibility.md)
- enforcement foundation: [`hostd-enforcement-foundation.md`](hostd-enforcement-foundation.md)
- filesystem known constraints: [`hostd-filesystem-known-constraints.md`](hostd-filesystem-known-constraints.md)
- network known constraints: [`hostd-network-known-constraints.md`](hostd-network-known-constraints.md)
- secret-access known constraints: [`hostd-secret-access-known-constraints.md`](hostd-secret-access-known-constraints.md)
- product requirements: [`../PRD.md`](../PRD.md)
