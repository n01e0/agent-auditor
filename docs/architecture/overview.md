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

## Phase 2 extension point: browser / SaaS

Browser governance should attach to the same `session_id` model. The browser layer should emit semantic actions such as:

- open admin page
- change sharing permission
- download file
- send message
- create event

Google Workspace is the first planned semantic surface, but the contract should stay general.

The first internal browser / GWS phase split is documented in [`hostd-browser-gws-poc.md`](hostd-browser-gws-poc.md).

## Near-term decisions fixed by this document

- container-first before microVMs
- eBPF + fanotify as the initial low-level approach
- OPA / Rego as the policy foundation
- session-centric normalized events as the canonical model
- browser / GWS work after runtime controls are in place
