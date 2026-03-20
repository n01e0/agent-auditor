package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_process_exec if {
  input.action.class == "process"
  input.action.verb == "exec"
}

is_remote_shell if {
  input.action.attributes.command == "ssh"
}

is_destructive_remove if {
  input.action.attributes.command == "rm"
}

decision := {
  "decision": "deny",
  "rule_id": "proc.exec.rm.denied",
  "severity": "high",
  "reason": "destructive rm execution is denied",
  "approval": null,
  "tags": ["process", "deny"]
} if {
  is_process_exec
  is_destructive_remove
}

decision := {
  "decision": "require_approval",
  "rule_id": "proc.exec.ssh.requires_approval",
  "severity": "high",
  "reason": "remote shell execution requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 900,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["process", "approval"]
} if {
  is_process_exec
  is_remote_shell
}
