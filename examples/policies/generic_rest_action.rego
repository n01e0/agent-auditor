package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_generic_rest_action if {
  input.generic_rest_action
}

rest := action if {
  action := input.generic_rest_action
}

primary_scope := scope if {
  scope := rest.oauth_scope_labels.primary
}

decision := {
  "decision": "deny",
  "rule_id": "generic_rest.secret_write.denied",
  "severity": "critical",
  "reason": "Generic REST secret write is denied",
  "approval": null,
  "tags": ["generic_rest", "secret", "deny"]
} if {
  is_generic_rest_action
  rest.method == "put"
  rest.privilege_class == "admin_write"
  primary_scope == "github.permission:secrets:write"
  contains(rest.path_template, "/secrets/")
}

decision := {
  "decision": "require_approval",
  "rule_id": "generic_rest.outbound_send.requires_approval",
  "severity": "high",
  "reason": "Outbound REST actions require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["generic_rest", "outbound_send", "approval"]
} if {
  is_generic_rest_action
  rest.method == "post"
  rest.query_class == "action_arguments"
  rest.privilege_class == "outbound_send"
  contains(rest.side_effect, "send")
}

decision := {
  "decision": "allow",
  "rule_id": "generic_rest.read_only.allow",
  "severity": "low",
  "reason": "Read-only generic REST audit retrieval is allowed",
  "approval": null,
  "tags": ["generic_rest", "read_only", "allow"]
} if {
  is_generic_rest_action
  rest.method == "get"
  rest.query_class == "filter"
  rest.privilege_class == "admin_read"
  contains(rest.host, "googleapis.com")
  contains(rest.side_effect, "lists")
}
