package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

sensitive_prefixes := [
  "/root/.ssh",
  "/home/agent/.ssh",
  "/var/run/secrets",
  "/run/secrets"
]

matches_sensitive_path(path) if {
  some prefix in sensitive_prefixes
  startswith(path, prefix)
}

decision := {
  "decision": "deny",
  "rule_id": "fs.sensitive.write",
  "severity": "critical",
  "reason": "sensitive path write is denied",
  "approval": null,
  "tags": ["filesystem", "deny"]
} if {
  input.action.class == "filesystem"
  input.action.verb == "write"
  matches_sensitive_path(input.action.attributes.path)
}

decision := {
  "decision": "require_approval",
  "rule_id": "fs.sensitive.read",
  "severity": "high",
  "reason": "sensitive path access requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["filesystem", "approval"]
} if {
  input.action.class == "filesystem"
  input.action.verb == "read"
  matches_sensitive_path(input.action.attributes.path)
}
