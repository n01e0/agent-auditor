package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

allowlisted_tls_domains := [
  "example.com"
]

is_network_connect if {
  input.action.class == "network"
  input.action.verb == "connect"
}

is_public_destination if {
  input.action.attributes.destination_scope == "public"
}

is_allowlisted_tls_domain if {
  some domain in allowlisted_tls_domains
  input.action.attributes.domain_candidate == domain
}

is_denied_public_smtp if {
  is_network_connect
  is_public_destination
  input.action.attributes.transport == "tcp"
  input.action.attributes.destination_port == 25
}

decision := {
  "decision": "allow",
  "rule_id": "net.public.allowlisted_tls_domain",
  "severity": "low",
  "reason": "allowlisted public TLS destination",
  "approval": null,
  "tags": ["network", "allowlist"]
} if {
  is_network_connect
  is_public_destination
  input.action.attributes.transport == "tcp"
  input.action.attributes.destination_port == 443
  is_allowlisted_tls_domain
}

decision := {
  "decision": "deny",
  "rule_id": "net.public.smtp.denied",
  "severity": "high",
  "reason": "public SMTP destination is denied",
  "approval": null,
  "tags": ["network", "deny"]
} if {
  is_denied_public_smtp
}

decision := {
  "decision": "require_approval",
  "rule_id": "net.public.unallowlisted.requires_approval",
  "severity": "medium",
  "reason": "public destination without allowlisted domain requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 900,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["network", "approval"]
} if {
  is_network_connect
  is_public_destination
  not is_allowlisted_tls_domain
  not is_denied_public_smtp
}
