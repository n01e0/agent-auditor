# hostd network PoC module boundary

This note fixes the first internal split for the `agent-auditor-hostd` network PoC.

## Goal of P3-1

Keep the early outbound-connect prototype honest about ownership before real eBPF observe hooks, destination classification, and event normalization land.

The immediate rule is:

- **observe** owns outbound-connect eBPF lifecycle and raw socket tuple handoff
- **classify** owns destination semantics, transport / scope hints, and the seam for lossy domain attribution
- **emit** owns normalization and publish fanout toward logs and later control-plane sinks
- the shared seams are small **observe** and **classification** boundary contracts that describe what each downstream stage may rely on

## Code layout

`cmd/agent-auditor-hostd/src/poc/network/`

- `contract.rs`
  - shared seams between observe → classify and classify → emit
  - eBPF collector label + outbound connect handoff field lists
- `observe.rs`
  - PoC-facing outbound-connect observe plan
  - future home for eBPF attach strategy and raw connect event extraction
- `classify.rs`
  - destination classification plan
  - future home for IP / port / protocol shaping, scope hints, and domain attribution seam
- `emit.rs`
  - normalization / publish plan after classification
  - future home for `agenta-core` event shaping and sink fanout
- `mod.rs`
  - assembles the network PoC plan and tests the split

## Responsibility split

### Observe

Owns:

- attaching outbound-connect eBPF hooks and managing their lifecycle
- capturing raw socket-connect tuples, address family, and transport hints
- preserving pid / socket context needed for later session attribution
- handing off raw outbound-connect candidates downstream without policy semantics

Does **not** own:

- destination scope or external / private classification
- domain attribution heuristics
- `agenta-core` normalization
- publish fanout to logs or control-plane sinks

### Classify

Owns:

- translating raw socket tuples into stable destination IP / port / protocol candidates
- attaching address-family, destination-scope, and transport hints for policy evaluation
- reserving the seam for lossy domain attribution without coupling it to kernel observation
- handing off semantic network connect candidates downstream

Does **not** own:

- eBPF program attachment or raw event collection lifecycle
- sink publication or transport fanout
- final `agenta-core` event emission

### Emit

Owns:

- normalizing classified outbound-connect candidates toward `agenta-core`
- preserving classifier metadata for later policy / audit stages
- publishing structured records to logs and later control-plane sinks

Does **not** own:

- eBPF attachment or raw socket tuple extraction
- destination scope / domain classification logic
- deciding how domains are inferred from DNS history

## Why this split now

This keeps the next tasks cleaner:

- **P3-2** can implement outbound connect observation without mixing in destination policy semantics
- **P3-3** can normalize classified destination candidates toward `agenta-core` without owning eBPF lifecycle
- **P3-4** can add minimal domain attribution against a stable classify seam instead of reaching back into observe-side raw tuples
- later policy / audit tasks can consume a stable classified-connect seam instead of poking directly at raw kernel-facing records

## Explicitly out of scope for P3-1

- real outbound eBPF hook attachment
- live connect-event reads from the kernel
- concrete destination IP / port normalization logic
- domain attribution implementation
- `agenta-core` network event normalization
- policy evaluation, approval creation, or persistence wiring

## Related docs

- implementation direction: [`rust-implementation.md`](rust-implementation.md)
- roadmap: [`../roadmaps/network-observe-destination-policy-tasklist.md`](../roadmaps/network-observe-destination-policy-tasklist.md)
