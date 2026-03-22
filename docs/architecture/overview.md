# Architecture Overview

## Purpose

`agent-auditor` is a container-first execution security layer for autonomous agents on Linux. It observes and governs what an agent does at runtime, then stores a tamper-evident session-centric audit trail.

This document fixes the initial architecture direction for Milestone 0 and Milestone 1.

## Design principles

- Linux-first, container-first
- session-centric rather than host-centric
- observe and control, not just collect logs
- explicit coverage boundaries
- tamper-evident audit as a first-class output
- policy logic separated from low-level instrumentation

## High-level components

### 1. Host monitor

Runs on the Linux host and is responsible for low-level visibility and selected enforcement hooks.

Initial responsibilities:

- eBPF-based process and network event capture
- fanotify-based filesystem monitoring / gating where practical
- container / namespace / cgroup attribution
- forwarding normalized events to the control plane or local buffer
- receiving compiled policy bundles and enforcement directives

This component is the most privileged runtime piece and should remain small.

### 2. Session linker

Maps low-level host events back to an agent session.

Responsibilities:

- assign or resolve `session_id`
- associate events with agent identity, initiator identity, container, node, and policy version
- ingest explicit runtime hints from supported agent platforms when available
- preserve linkage for child processes and descendant activity

Without this, the system degrades into generic host telemetry, which is not enough.

### 3. Policy engine

Evaluates action requests and observed events.

Initial direction:

- OPA / Rego bundle evaluation
- allow / deny / require_approval outcomes
- explanation metadata returned with every decision
- support for observe-only rules during rollout

The policy engine should be logically independent from kernel instrumentation.

### 4. Approval controller

Manages approval-gated actions.

Responsibilities:

- create approval requests
- surface context to operators
- accept approve / deny decisions
- release or reject pending actions
- record reviewer, scope, TTL, and rationale

### 5. Audit pipeline and store

Responsible for durable event ingest and integrity protection.

Requirements:

- append-oriented event storage
- buffering and replay on temporary disconnects
- chained-hash, signature, or equivalent tamper evidence
- efficient session reconstruction and filtering

### 6. Operator API / UI

The control plane for humans.

Initial responsibilities:

- session list
- session timeline
- alert list
- approval queue
- policy bundle visibility
- emergency containment controls

## Data flow

### Allowed action path

1. Agent runs inside a container.
2. Host monitor captures action intent or action event.
3. Session linker enriches the event with session metadata.
4. Policy engine evaluates the event or request.
5. If allowed, the action proceeds and the event is recorded.
6. Audit store persists the normalized record.

### Approval-gated action path

1. Agent attempts a high-risk action.
2. Host monitor / control plane produces a normalized action request.
3. Policy engine returns `require_approval`.
4. Approval controller opens a request.
5. Operator approves or denies.
6. Final decision and action result are persisted in the audit trail.

### Denied action path

1. Agent attempts a denied action.
2. Policy returns `deny`.
3. Enforcement layer blocks when technically feasible.
4. Denial event and policy metadata are stored.
5. Optional alert is emitted.

## Trust boundaries

### Boundary A: agent container

The agent workload is not trusted to preserve its own evidence.

### Boundary B: host monitor

The host monitor is trusted for collection and selected enforcement, but should not be the sole source of operator-facing policy truth.

### Boundary C: control plane

The control plane is trusted to evaluate policy, manage approvals, and preserve durable audit.

### Boundary D: audit store

The audit store must be protected against silent mutation by workloads or ordinary operators.

## Enforcement model

The product will use multiple enforcement modes depending on the action class.

The initial fail-open / fail-closed posture is documented in [`failure-behavior.md`](failure-behavior.md): only validated enforced subsets may claim fail-closed behavior; everything else must fail open with explicit fallback reporting.

### Process

- observe on all supported hosts
- block / gate where technically feasible
- retain explicit coverage flags when a host can observe but not block

### Filesystem

- observe with fanotify where practical
- protect sensitive paths first
- route filesystem policy results through explicit decision / hold / deny / audit stages when enforcement is introduced
- treat unsupported path coverage as explicit gaps, not silent success

### Process

- observe exec / exit on all supported hosts first
- route future pre-exec deny / approval-gated work through the same decision / hold / deny / audit split as filesystem
- make observe-only fallback explicit when the host cannot block safely

### Network

- record outbound connections and destination metadata
- support policy decisions and selected egress control integrations
- keep the design open to CNI / firewall-based enforcement later

## Deployment shapes

### Single-node / lab

- one host monitor
- one local or nearby control plane
- one audit store

This is the initial easiest deployment target.

### Kubernetes / fleet

- one monitor per node
- central control plane
- central audit store
- policy bundles distributed to node-local components

## Phase 2 extension point: API / network semantic governance

API / network governance should attach to the same `session_id` model. The first semantic layer should emit GWS actions such as:

- update Drive sharing permission
- download Drive file content
- send Gmail message
- list Admin activity reports

Google Workspace is the first planned semantic surface, but the contract should stay general.

The first internal API / network GWS phase split is documented in [`hostd-api-network-gws-poc.md`](hostd-api-network-gws-poc.md).
The follow-on cross-provider boundary that separates provider-specific taxonomy, the shared provider contract, and shared provider metadata is documented in [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md).
The next cross-provider boundary above that, which separates provider-specific taxonomy from a generic REST / OAuth governance contract, is documented in [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md).
The next collaboration boundary above generic REST, which separates provider-specific taxonomy and generic REST lineage from provider-neutral messaging / collaboration action families, is documented in [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md), and the first Slack / Discord minimal taxonomy catalog is documented in [`messaging-collaboration-action-catalog.md`](messaging-collaboration-action-catalog.md).
The local workflow and current limitations for the provider-abstraction slice are documented in [`../runbooks/provider-abstraction-foundation-local.md`](../runbooks/provider-abstraction-foundation-local.md) and [`provider-abstraction-known-constraints.md`](provider-abstraction-known-constraints.md).
The local workflow and current limitations for the generic REST / OAuth slice are documented in [`../runbooks/generic-rest-oauth-governance-local.md`](../runbooks/generic-rest-oauth-governance-local.md) and [`generic-rest-oauth-governance-known-constraints.md`](generic-rest-oauth-governance-known-constraints.md).
The local workflow and current limitations for the messaging / collaboration slice are documented in [`../runbooks/messaging-collaboration-governance-local.md`](../runbooks/messaging-collaboration-governance-local.md) and [`messaging-collaboration-governance-known-constraints.md`](messaging-collaboration-governance-known-constraints.md).
The next operator-facing boundary above those governance slices, which separates upstream approval/audit producers from reviewer experience, policy explainability, and ops-hardening semantics, is documented in [`approval-control-plane-ux-foundation.md`](approval-control-plane-ux-foundation.md).
The first checked-in approval queue / decision summary / rationale capture model for that control-plane slice is documented in [`approval-control-plane-ux-minimal-model.md`](approval-control-plane-ux-minimal-model.md).
The checked-in stale-state / drift / recovery / `waiting_merge` vocabulary for that same control-plane slice is documented in [`approval-control-plane-ops-hardening.md`](approval-control-plane-ops-hardening.md).
The checked-in status / notification / reconciliation summaries for that same control-plane slice are documented in [`approval-control-plane-status-notification-reconciliation.md`](approval-control-plane-status-notification-reconciliation.md).
The local workflow and current limitations for that same control-plane slice are documented in [`../runbooks/approval-control-plane-ux-local.md`](../runbooks/approval-control-plane-ux-local.md) and [`approval-control-plane-ux-known-constraints.md`](approval-control-plane-ux-known-constraints.md).
The next live boundary beneath generic REST / GWS / GitHub / messaging policy surfaces, which separates proxy seam, session correlation, semantic conversion, policy, approval, and audit responsibilities for intercepted requests, is documented in [`live-proxy-interception-foundation.md`](live-proxy-interception-foundation.md). The concrete redaction-safe request model at that proxy seam is documented in [`live-proxy-http-request-contract.md`](live-proxy-http-request-contract.md).
The initial GitHub candidate action and metadata catalog for that shared provider shape is documented in [`provider-abstraction-github-candidate-catalog.md`](provider-abstraction-github-candidate-catalog.md).
The next GitHub-specific governance boundary that separates action taxonomy, provider metadata, policy, and record responsibilities is documented in [`hostd-github-semantic-governance-poc.md`](hostd-github-semantic-governance-poc.md).
The local workflow and current limitations for that GitHub slice are documented in [`../runbooks/hostd-github-semantic-governance-poc-local.md`](../runbooks/hostd-github-semantic-governance-poc-local.md) and [`hostd-github-semantic-governance-known-constraints.md`](hostd-github-semantic-governance-known-constraints.md).

## Near-term decisions fixed by this document

- container-first before microVMs
- eBPF + fanotify as the initial low-level approach
- OPA / Rego as the policy foundation
- session-centric normalized events as the canonical model
- API / network GWS work after runtime controls are in place
