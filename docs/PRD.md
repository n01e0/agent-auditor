# Product Requirements Document

## 1. Document status

- Product: `agent-auditor`
- Status: Draft v0
- Last updated: 2026-03-18
- Owner: n01e0

---

## 2. Summary

`agent-auditor` is a Linux-first security and governance layer for autonomous agents that run with real system and SaaS permissions.

The product goal is to make it possible to deploy agents in real environments without relying on blind trust. It should provide:

- runtime visibility
- policy-based control
- human approval for risky actions
- tamper-evident audit trails
- incident investigation and replay

The first target environment is OpenClaw-style agents running inside containers on Linux hosts. The first technical focus is process, filesystem, network, and secret access governance. Browser operation governance will follow immediately after the first runtime security layer, with Google Workspace-related actions as the first browser / SaaS expansion target.

---

## 3. Problem statement

Autonomous agents are increasingly being granted access to:

- local filesystems
- shell execution
- internal APIs
- browser sessions
- SaaS platforms
- production or semi-production credentials

Existing security controls are often split across endpoint tools, SIEM, CASB, and cloud policies. Those systems are not built around the unit that matters here: the **agent session**.

This creates several gaps:

1. Teams cannot easily answer what an agent saw, executed, modified, or exfiltrated in a single session timeline.
2. Risky actions are often allowed implicitly once credentials are mounted into a container.
3. Human approval is not deeply integrated into the agent execution path.
4. Audit logs are fragmented across tools and are difficult to reconcile during incidents.
5. Security teams become a blocker because they cannot permit agent usage with bounded risk.

`agent-auditor` exists to solve those gaps with a container-first, Linux-focused execution security product for agents.

---

## 4. Product vision

Enable organizations to safely deploy autonomous agents by making agent actions observable, governable, reviewable, and interruptible.

The product should help security and platform teams move from:

- "we cannot allow agents"

into:

- "we can allow agents under enforceable policies with auditability"

---

## 5. Goals

### 5.1 Primary goals

1. Provide session-centric runtime auditing for Linux-hosted agents.
2. Enforce allow / deny / approval-required decisions before risky actions complete.
3. Record tamper-evident audit trails suitable for incident response and compliance review.
4. Support containerized agent deployments on Docker, Kubernetes, and Podman.
5. Establish a policy model flexible enough for future browser and SaaS governance.

### 5.2 Secondary goals

1. Minimize deployment friction for self-hosted and internal enterprise use.
2. Keep runtime overhead low enough for interactive agent workflows.
3. Make investigations easy for operators who are not kernel or eBPF specialists.

---

## 6. Non-goals

The following are explicitly out of scope for the initial MVP:

- microVM-based isolation and monitoring
- Windows endpoint support
- macOS endpoint support
- complete SaaS coverage across all major vendors
- advanced behavior analytics / UEBA
- fully managed multi-tenant SaaS as a day-one requirement
- in-browser content inspection across arbitrary websites
- replacing a general SIEM, EDR, or enterprise CASB

---

## 7. Target users and buyers

### 7.1 Primary buyers

- Security teams enabling internal AI agents
- Platform / infrastructure teams operating agent runtimes
- Engineering leaders deploying coding / ops / workflow agents

### 7.2 Primary operators

- Security engineers
- SRE / platform engineers
- AI platform owners

### 7.3 Secondary stakeholders

- Compliance / audit teams
- Incident responders
- Internal governance / risk teams

---

## 8. Scope assumptions

### 8.1 Runtime assumptions

The initial product assumes:

- Linux hosts
- agent runtimes launched inside containers
- OpenClaw and similar tool-using agents as the primary initial target
- mixed environments including bare containers, Docker Compose, Kubernetes, and Podman

### 8.2 Monitoring assumptions

The initial runtime security layer will rely on:

- eBPF for process / syscall / network-level observability and selected enforcement hooks where practical
- fanotify for filesystem monitoring and gating where practical
- a Rust-first implementation strategy, with `aya` as the preferred initial eBPF stack

Design must allow selective fallback where kernel capabilities differ, but the product should not hide unsupported coverage behind silent degradation.

### 8.3 Policy assumptions

- Policy evaluation will be based on OPA / Rego, not a custom YAML-only policy language.
- The product may provide higher-level generated policy templates later, but Rego is the source of truth for enforcement logic.

### 8.4 Expansion assumptions

- Browser action governance comes after filesystem / process / network / secret controls are working.
- Google Workspace operations are the first planned browser / SaaS expansion area.
- microVM support is deferred until after the initial container-first release.

---

## 9. Core user stories

### 9.1 Security engineer

- As a security engineer, I want to define policies for agent actions so that risky commands, file access, and outbound requests can be blocked or gated.
- As a security engineer, I want to see a complete session timeline so that I can investigate incidents quickly.
- As a security engineer, I want tamper-evident logs so that agents cannot erase or rewrite their own history.

### 9.2 Platform engineer

- As a platform engineer, I want to deploy monitoring with minimal per-agent code changes so that existing containerized agents can be onboarded quickly.
- As a platform engineer, I want low runtime overhead so that interactive agents remain usable.
- As a platform engineer, I want health checks and clear coverage reporting so that I know when enforcement is active and what is not being monitored.

### 9.3 Approval operator

- As an operator, I want risky actions paused with a human approval request so that I can permit specific actions without granting blanket trust.
- As an operator, I want context on why the agent wants the action so that I can make a quick decision.

### 9.4 Auditor / incident responder

- As an auditor, I want exportable session evidence so that I can review specific incidents or policy violations.
- As an incident responder, I want to stop a running agent session immediately so that ongoing damage can be contained.

---

## 10. Functional requirements

### 10.1 Agent and session identity

The system must:

1. Assign a unique session identifier to each tracked agent execution.
2. Associate each session with:
   - agent identity
   - initiating human or service identity when available
   - host / node identity
   - container / pod identity when available
   - policy set version
   - start time and end time
   - working directory or workspace metadata when available
3. Preserve identity linkage across collected events.

### 10.2 Event collection and normalization

The system must collect and normalize at least the following event classes:

1. Process execution events
2. Filesystem access events
3. Network egress events
4. Secret access events
5. Policy decision events
6. Approval request / approval decision events
7. Session lifecycle events

Each normalized event must contain at minimum:

- event id
- timestamp
- session id
- actor type
- action type
- target
- result (`allowed`, `denied`, `approval_required`, `approved`, `rejected`, `failed`, etc.)
- policy match metadata when applicable

### 10.3 Process governance

The system must support:

1. Observing command execution and child process creation.
2. Capturing:
   - executable path
   - argv / command line, subject to configured masking
   - cwd where available
   - uid / gid or container identity where available
   - parent process linkage
   - exit code or termination signal
3. Policy evaluation on process execution before completion of risky actions where technically feasible.
4. Blocking or gating process execution based on policy.

### 10.4 Filesystem governance

The system must support:

1. Monitoring reads, writes, creates, deletes, renames, and permission-sensitive opens where feasible.
2. Capturing:
   - path
   - operation type
   - container / mount context when available
   - result
3. Policy evaluation for sensitive path access.
4. Blocking or gating access to protected paths where technically feasible.
5. Coverage for common sensitive targets such as:
   - SSH material
   - cloud credentials
   - `.env` files
   - service account files
   - mounted secrets

### 10.5 Network governance

The system must support:

1. Recording outbound connection attempts and results.
2. Capturing at minimum:
   - destination address
   - destination port
   - resolved domain when available
   - transport protocol
   - container / session identity
3. Policy decisions based on destination rules.
4. Allowlist / denylist / approval-based outbound controls.
5. Support for alerting on unexpected external destinations.

### 10.6 Secret access governance

The system must support:

1. Tracking agent access to secrets, secret files, mounted credentials, or brokered secret retrievals.
2. Logging secret identifiers without logging plaintext secret values.
3. Policy decisions based on secret class, environment, and requesting agent.
4. Approval-required access for sensitive credentials.
5. Masking or redaction of secret values in logs and UI.

### 10.7 Policy engine

The system must:

1. Use OPA / Rego as the primary policy evaluation engine.
2. Provide policy input documents that include session, actor, action, target, environment, and historical context where relevant.
3. Support at least three effective outcomes:
   - allow
   - deny
   - require approval
4. Support policy reasoning metadata such as matched rule id, explanation string, and severity.
5. Version policy bundles and preserve the evaluated version in audit records.

### 10.8 Approval workflow

The system must support:

1. Pausing or intercepting approval-gated actions before completion where technically feasible.
2. Displaying approval requests with enough context to decide quickly.
3. Approving or denying actions from a control plane.
4. Recording:
   - who approved or denied
   - when they decided
   - what scope the decision applied to
   - whether the decision was one-time or time-limited
5. Releasing or rejecting the blocked action accordingly.

Initial approval scope requirements:

- one-time approval for a single action
- TTL-bound approval for repeated equivalent actions

### 10.9 Session timeline and replay

The system must provide:

1. A session detail view that reconstructs actions in time order.
2. Filtering by event type, severity, policy decision, and target.
3. Search by session id, command, file path, destination domain, or actor.
4. Export of a session timeline in machine-readable format.
5. Clear labeling of blocked, approved, retried, and failed actions.

### 10.10 Alerting

The system must support policy-based alert generation for at least:

- denied sensitive command execution
- denied sensitive file access
- unexpected outbound network destinations
- access to protected secrets
- repeated failure or repeated denied attempts over threshold
- attempts to operate without active coverage or with degraded enforcement

The system should support initial alert delivery via:

- webhook
- Slack-compatible endpoint
- Discord-compatible endpoint

### 10.11 Response and containment

The system must support:

1. Immediate termination of a tracked session.
2. Disablement of a specific agent identity or policy group.
3. Emergency deny policy rollout.
4. Visibility into whether containment succeeded.

### 10.12 Browser / SaaS governance (Phase 2 requirement)

The first post-MVP expansion target is browser-mediated SaaS governance, beginning with Google Workspace-related actions.

Phase 2 must support:

1. A browser action model that can be linked to the same session identity used for runtime events.
2. Audit logging of browser-driven actions at a semantic layer where possible.
3. Policy decisions for selected high-risk browser actions.
4. Initial coverage priorities in Google Workspace contexts, such as:
   - opening admin surfaces
   - changing sharing permissions
   - downloading sensitive files
   - sending messages or emails
   - mass-edit or bulk action flows

Detailed browser instrumentation design is deferred from the MVP, but the MVP architecture must leave room for this extension.

---

## 11. Non-functional requirements

### 11.1 Tamper evidence

1. Audit records must be append-oriented.
2. The system must provide a mechanism for tamper detection, such as chained hashes, signing, or equivalent integrity proofs.
3. Agent-controlled processes must not be able to silently delete or rewrite the authoritative audit trail.

### 11.2 Performance

1. Monitoring and policy evaluation must be low-latency enough for interactive agent use.
2. The product should keep median added latency for common low-risk actions low enough that operators do not perceive the system as unusable.
3. Approval-gated actions may incur user-visible delay, but non-gated actions should remain responsive.

### 11.3 Reliability

1. Event buffering must tolerate temporary control plane or network outages.
2. Buffered events must be retried safely.
3. The ingest pipeline must tolerate duplicate delivery without corrupting the audit view.

### 11.4 Availability and failure behavior

1. The system must explicitly define fail-open versus fail-closed behavior per action class.
2. Default failure behavior for high-risk controls should be conservative.
3. Coverage degradation must be surfaced clearly to operators.

### 11.5 Security

1. Control plane and agents must communicate over authenticated, encrypted channels.
2. Administrative actions must require authenticated identities with role-based authorization.
3. The system must follow least-privilege principles for deployment and runtime components.
4. Sensitive data in logs and UI must be masked or minimized.

### 11.6 Privacy and data minimization

1. Secret values must never be stored in plaintext audit records.
2. Sensitive fields must support redaction or hashing.
3. Retention periods must be configurable.
4. Export and search functionality must respect role-based access controls.

### 11.7 Compatibility

1. Initial supported environments are Linux distributions commonly used for container hosts, especially Ubuntu and Debian-family systems.
2. The product must document kernel feature prerequisites for eBPF and fanotify coverage.
3. Unsupported kernel / runtime combinations must produce explicit operator-visible warnings.

### 11.8 Operability

1. The system must provide health checks, metrics, and debug visibility.
2. Operators must be able to determine what monitors and enforcement hooks are active.
3. Policy bundle rollout and rollback must be observable.

### 11.9 Scalability

1. The architecture must support growth from a single-host deployment to a multi-node container fleet.
2. The MVP does not need full planet-scale distribution, but it must avoid assumptions that make multi-node expansion impossible.

### 11.10 Audit usability

1. The UI and exports must make it easy to explain what happened in a session.
2. Investigators must be able to answer basic questions quickly:
   - what did the agent try to do?
   - what succeeded?
   - what was blocked?
   - who approved what?
   - what data or systems were touched?

---

## 12. MVP scope

### 12.1 In scope for MVP

- Linux host support
- container-first deployment model
- OpenClaw-style agent runtime support
- session identity and event normalization
- process monitoring and policy decisions
- filesystem monitoring and policy decisions
- network egress monitoring and policy decisions
- secret access auditing and policy decisions
- OPA / Rego policy evaluation
- approval workflow
- session timeline UI or equivalent investigation surface
- alerting via webhook-compatible sinks
- emergency kill / containment control
- tamper-evident audit persistence

### 12.2 Explicitly out of MVP scope

- microVM support
- Windows / macOS agents
- general browser governance
- deep Google Workspace semantic coverage
- full enterprise SaaS connector catalog
- advanced analytics and anomaly detection
- managed cloud service packaging

---

## 13. Deployment model

### 13.1 Initial deployment

The product should support a self-hosted deployment with at least the following components:

1. Host-side monitoring / enforcement component
2. Central policy and ingest service
3. Audit storage layer
4. Operator API / UI

### 13.2 Container environment support

The product should work with:

- Docker
- Kubernetes
- Podman

The design should allow workload attribution across:

- host
- namespace
- container / pod
- agent session

---

## 14. Policy model requirements

### 14.1 Rego input model

Policy input should be rich enough to express decisions using:

- session identity
- agent identity
- initiating user identity where available
- action class
- target path / domain / executable / secret id
- environment label
- time constraints
- historical counters or recent events when available

### 14.2 Rego decision model

Policy evaluation output should support:

- decision
- reason
- severity
- rule id
- approval requirement metadata
- suggested reviewer group or reviewer identity where applicable

### 14.3 Policy packaging

The system should support:

- bundle versioning
- staged rollout
- rollback
- dry-run or observe-only mode for selected rules

---

## 15. Initial example policies

The initial system should be able to express policies such as:

1. Deny destructive shell commands targeting protected system paths.
2. Require approval before reading SSH private keys or cloud credential files.
3. Deny outbound connections to non-allowlisted external domains.
4. Require approval for access to production secrets from development-tagged agents.
5. Alert on repeated denied attempts within a short time window.
6. Allow read-only access to designated workspace paths while denying writes outside the workspace.

---

## 16. Success metrics

### 16.1 Product success metrics

1. Time to onboard an existing containerized agent runtime
2. Percentage of risky actions covered by enforceable policy
3. Median investigation time for a single session incident
4. Approval turnaround time for gated actions
5. False positive rate for high-severity policy alerts

### 16.2 Technical success metrics

1. Event ingestion reliability under temporary disconnects
2. Integrity verification success rate for stored audit trails
3. Added latency for common allowed actions
4. Session attribution correctness across container boundaries

---

## 17. Risks and constraints

### 17.1 Technical risks

- Kernel feature variability may limit consistent eBPF / fanotify behavior across environments.
- Enforcement semantics can differ between observability and truly blocking operations.
- Container attribution may become harder in mixed runtimes or nested execution contexts.
- Approval-gated enforcement can add complexity to highly interactive agent sessions.

### 17.2 Product risks

- Buyers may compare the product to EDR, CASB, or sandboxing tools with much broader scope.
- Audit-only value may feel insufficient unless paired with real control and approvals.
- Excessive false positives could cause operators to disable controls.

---

## 18. Open questions

1. Which actions should default to fail-closed in the MVP?
2. How much of filesystem enforcement should rely on fanotify versus policy on observed events?
3. How should secret access be modeled when secrets arrive via environment variables rather than files or brokers?
4. What is the preferred control plane deployment shape for single-node versus Kubernetes-heavy users?
5. What browser instrumentation strategy best fits the Phase 2 Google Workspace expansion?
6. What minimum kernel version matrix should be officially supported at launch?

---

## 19. Milestones

### Milestone 0: repository and product framing

- Establish repository structure
- Finalize PRD and architecture direction
- Define initial terminology and event schema

### Milestone 1: session identity and host observability foundation

- Session model
- Event schema
- eBPF-based process / network observability prototype
- fanotify-based filesystem observability prototype

### Milestone 2: policy and approval MVP

- OPA / Rego evaluation pipeline
- approval request lifecycle
- initial operator API
- initial audit storage with tamper evidence

### Milestone 3: investigation surface and containment

- session timeline UI or equivalent viewer
- search and export
- alert routing
- emergency kill / disable controls

### Milestone 4: browser / GWS phase planning

- browser action model
- session linkage design
- first Google Workspace high-risk action coverage

---

## 20. Initial repository suggestions

Suggested near-term repository layout:

```text
agent-auditor/
  README.md
  docs/
    PRD.md
    architecture/
    schemas/
    policies/
  cmd/
  crates/
  deploy/
  examples/
```

This is a suggestion, not yet a final commitment.

---

## 21. Acceptance criteria for PRD sign-off

This PRD draft can be considered ready for sign-off once:

1. MVP scope is confirmed.
2. eBPF / fanotify assumptions are accepted.
3. container-first scope is accepted.
4. OPA / Rego is accepted as the policy foundation.
5. browser / Google Workspace coverage is confirmed as Phase 2 rather than MVP.
6. the open questions are either resolved or converted into explicit follow-up design tasks.
