# hostd network PoC: local runbook

This runbook covers the current `agent-auditor-hostd` network PoC as it exists after P3-7.

## What this PoC currently proves

The current network PoC is intentionally narrow:

- `agent-auditor-hostd` can assemble an eBPF-shaped observe / classify / emit pipeline for outbound `network.connect` events without attaching live kernel hooks yet
- userspace can decode deterministic outbound connect payloads into provisional destination IP / port / protocol metadata
- the classifier can add destination scope and a minimal domain-attribution hint from the checked-in recent-DNS-answer preview path
- `agenta-policy` can evaluate normalized `network_connect` events against the checked-in Rego example and return `allow` / `deny` / `require_approval`
- `require_approval` can derive a pending `ApprovalRequest`
- enriched network audit records can be persisted to local JSONL files for inspection
- the end-to-end preview path is covered by focused unit tests plus a dedicated fixture-backed network smoke test

## Prerequisites

- Linux development environment
- Rust toolchain installed
- repository checked out locally

The documented path below does **not** require root today because the PoC still uses deterministic preview records instead of live eBPF attachment and kernel event reads.

## Quick start

From the repository root:

```bash
cargo run -p agent-auditor-hostd
```

Expected output includes these network-oriented categories of lines:

- `network_observe=...`
- `network_classify=...`
- `network_emit=...`
- `event_log_network=...`
- `normalized_network_observed=...`
- `normalized_network=...`
- `network_policy_decision=...`
- `network_approval_request=...`
- `normalized_network_require_approval=...`
- `network_policy_decision_require_approval=...`
- `network_approval_request_require_approval=...`
- `normalized_network_deny=...`
- `network_policy_decision_deny=...`
- `network_approval_request_deny=...`
- `persisted_network_audit_record_allow=...`
- `persisted_network_audit_record_require_approval=...`
- `persisted_network_audit_record_deny=...`

Example shape:

```text
agent-auditor-hostd bootstrap
session_id=sess_bootstrap_hostd agent_id=openclaw-main
network_observe=collector=ebpf hooks=outbound IPv4 connect hooks,outbound IPv6 connect hooks raw_fields=pid,sock_fd,address_family,transport,destination_addr,destination_port raw_connect_kinds=connect address_families=inet,inet6
network_classify=collector=ebpf input_fields=pid,sock_fd,address_family,transport,destination_addr,destination_port semantic_fields=destination_ip,destination_port,transport,address_family,destination_scope,domain_candidate,domain_attribution_source verbs=connect domain_strategy=recent_dns_answer_exact_ip answers=1
network_emit=collector=ebpf semantic_fields=destination_ip,destination_port,transport,address_family,destination_scope,domain_candidate,domain_attribution_source stages=normalize->publish sinks=structured_log,control_plane
event_log_network=event=network.connect collector=ebpf pid=4242 fd=7 family=inet transport=tcp destination=93.184.216.34:443
normalized_network_observed={...}
normalized_network={...}
network_policy_decision={...}
network_approval_request=null
normalized_network_require_approval={...}
network_policy_decision_require_approval={...}
network_approval_request_require_approval={...}
normalized_network_deny={...}
network_policy_decision_deny={...}
network_approval_request_deny=null
persisted_network_audit_record_allow={...}
persisted_network_audit_record_require_approval={...}
persisted_network_audit_record_deny={...}
```

## Validation commands

### Full local validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

### Run only the dedicated network smoke test

```bash
cargo test -p agent-auditor-hostd --test network_poc_smoke
```

### Run the broader hostd smoke test

```bash
cargo test -p agent-auditor-hostd --test poc_smoke
```

### Run only hostd unit tests

```bash
cargo test -p agent-auditor-hostd --lib
```

### Run only the policy crate tests

```bash
cargo test -p agenta-policy
```

## Where the current network PoC behavior lives

- network module boundary:
  - `docs/architecture/hostd-network-poc.md`
- domain-attribution strategy:
  - `docs/architecture/hostd-network-domain-attribution.md`
- observe / classify / emit scaffolding:
  - `cmd/agent-auditor-hostd/src/poc/network/`
- policy input + Rego evaluation helpers:
  - `crates/agenta-policy/src/lib.rs`
- example network policy:
  - `examples/policies/network_destination.rego`
- bootstrap preview output:
  - `cmd/agent-auditor-hostd/src/main.rs`
- dedicated network smoke expectations:
  - `cmd/agent-auditor-hostd/tests/fixtures/hostd-network-smoke-fixtures.json`
- dedicated network smoke test:
  - `cmd/agent-auditor-hostd/tests/network_poc_smoke.rs`
- shared smoke helpers:
  - `cmd/agent-auditor-hostd/tests/common/mod.rs`

## Local persistence path

The bootstrap preview currently writes network PoC audit records under:

```text
target/agent-auditor-hostd-network-poc-store/
```

Expected file:

- `audit-records.jsonl`

This file is a bootstrap artifact for local inspection only. It is intentionally reset when the network PoC store is bootstrapped.

## Known constraints

See [`../architecture/hostd-network-known-constraints.md`](../architecture/hostd-network-known-constraints.md) for the explicit limitations that still apply to this path.

## When this runbook should change

Update this document when any of the following happens:

- hostd starts attaching real outbound-connect eBPF programs
- userspace begins consuming live kernel connect events instead of deterministic fixture payloads
- destination classification expands beyond the current IP / port / protocol / scope / domain-hint shape
- the checked-in Rego example stops being the default preview policy path
- audit persistence moves away from the current bootstrap JSONL store
- local execution begins requiring elevated privileges or extra kernel setup
