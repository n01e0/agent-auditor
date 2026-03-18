package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_secret_access if {
  input.action.class == "secret"
}

is_secret_file if {
  input.action.attributes.taxonomy_kind == "secret_file"
}

is_mounted_secret if {
  input.action.attributes.taxonomy_kind == "mounted_secret"
}

is_brokered_secret_request if {
  input.action.attributes.taxonomy_kind == "brokered_secret_request"
}

is_ssh_material if {
  input.action.attributes.taxonomy_variant == "ssh_material"
}

is_kubernetes_service_account if {
  input.action.attributes.taxonomy_variant == "kubernetes_service_account"
}

decision := {
  "decision": "deny",
  "rule_id": "secret.mounted.kubernetes_service_account.denied",
  "severity": "high",
  "reason": "kubernetes service account secret access is denied",
  "approval": null,
  "tags": ["secret", "deny"]
} if {
  is_secret_access
  is_mounted_secret
  is_kubernetes_service_account
}

decision := {
  "decision": "require_approval",
  "rule_id": "secret.brokered.requires_approval",
  "severity": "high",
  "reason": "brokered secret retrieval requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1200,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["secret", "approval"]
} if {
  is_secret_access
  is_brokered_secret_request
}

decision := {
  "decision": "require_approval",
  "rule_id": "secret.file.ssh_material.requires_approval",
  "severity": "high",
  "reason": "ssh secret file access requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1200,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["secret", "approval"]
} if {
  is_secret_access
  is_secret_file
  is_ssh_material
}
