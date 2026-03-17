# Rego Contract

This document fixes the initial contract between runtime collectors, the control plane, and the OPA / Rego policy layer.

## Goals

- make policy evaluation explicit and testable
- avoid burying business logic in kernel hooks
- allow dry-run and staged rollout later

## Policy package

Initial package namespace:

```rego
package agentauditor.authz
```

## Input shape

The control plane will evaluate Rego with an input document shaped like this:

```json
{
  "request_id": "req_01...",
  "timestamp": "2026-03-18T02:00:00Z",
  "session": {
    "session_id": "sess_01...",
    "agent_id": "openclaw-main",
    "initiator_id": "user:n01e0",
    "environment": "prod",
    "policy_bundle_version": "bundle-2026-03-18-001"
  },
  "actor": {
    "kind": "agent",
    "id": "openclaw-main"
  },
  "action": {
    "class": "filesystem",
    "verb": "read",
    "target": "/home/agent/.ssh/id_ed25519",
    "attributes": {
      "path": "/home/agent/.ssh/id_ed25519",
      "container_id": "ctr_123",
      "host_id": "host-a"
    }
  },
  "context": {
    "recent_denies": 0,
    "labels": ["container", "linux"],
    "coverage": {
      "collector": "fanotify",
      "enforce_capable": true
    }
  }
}
```

## Required decision output

Policy evaluation must return one object matching this shape:

```json
{
  "decision": "require_approval",
  "rule_id": "fs.ssh.read.requires_approval",
  "severity": "high",
  "reason": "reading SSH private key material requires reviewer approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["filesystem", "ssh", "secret-like"]
}
```

Allowed `decision` values:

- `allow`
- `deny`
- `require_approval`

## Suggested helper rules

The initial policy bundle should expose helper rules like:

- `default decision := { ... }`
- `is_prod`
- `is_sensitive_path(path)`
- `is_allowlisted_domain(domain)`
- `requires_security_review`

## Example policy skeleton

```rego
package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching deny or approval rule",
  "approval": null,
  "tags": []
}

sensitive_paths := {
  "/root/.ssh",
  "/home/agent/.ssh",
  "/var/run/secrets"
}

is_sensitive_path(path) if {
  some prefix in sensitive_paths
  startswith(path, prefix)
}

decision := {
  "decision": "require_approval",
  "rule_id": "fs.sensitive.read",
  "severity": "high",
  "reason": "sensitive filesystem path read requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["filesystem", "approval"]
} if {
  input.action.class == "filesystem"
  input.action.verb == "read"
  is_sensitive_path(input.action.attributes.path)
}
```

## Decision recording

The exact policy output must be copied into:

- the synchronous action response path
- the audit log event for policy decisions
- any approval request created from that decision

This prevents divergence between what was enforced and what was recorded.

## Observe-only mode

Observe-only rollout is not required for the first prototype, but the contract should remain compatible with adding fields such as:

- `enforcement_mode`
- `would_decide`
- `shadow_rule_id`

## Open points

- whether historical context is passed directly in input or pre-aggregated by the control plane
- whether separate packages are needed for `authz`, `alerting`, and `classification`
- how to represent browser / GWS semantic actions in a future compatible way
