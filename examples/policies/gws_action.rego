package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_gws_action if {
  input.provider_action.provider_id == "gws"
}

action_key := key if {
  key := input.provider_action.action_key
}

decision := {
  "decision": "require_approval",
  "rule_id": "gws.drive.permissions_update.requires_approval",
  "severity": "high",
  "reason": "Drive permission updates require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["gws", "drive", "approval"]
} if {
  is_gws_action
  action_key == "drive.permissions.update"
}

decision := {
  "decision": "require_approval",
  "rule_id": "gws.drive.files_get_media.requires_approval",
  "severity": "medium",
  "reason": "Drive file content downloads require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 900,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["gws", "drive", "approval"]
} if {
  is_gws_action
  action_key == "drive.files.get_media"
}

decision := {
  "decision": "require_approval",
  "rule_id": "gws.gmail.users_messages_send.requires_approval",
  "severity": "high",
  "reason": "Outbound Gmail send requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["gws", "gmail", "approval"]
} if {
  is_gws_action
  action_key == "gmail.users.messages.send"
}

decision := {
  "decision": "allow",
  "rule_id": "gws.admin.reports.activities_list.allow",
  "severity": "low",
  "reason": "Admin activity listing is read-only audit retrieval",
  "approval": null,
  "tags": ["gws", "admin", "allow"]
} if {
  is_gws_action
  action_key == "admin.reports.activities.list"
}
