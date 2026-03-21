package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_messaging_action if {
  input.messaging_action
}

messaging := action if {
  action := input.messaging_action
}

rest := lineage if {
  lineage := messaging.generic_rest_action
}

decision := {
  "decision": "allow",
  "rule_id": "messaging.message_send.allow",
  "severity": "low",
  "reason": "Public-channel messaging sends are allowed by the preview policy",
  "approval": null,
  "tags": ["messaging", "message_send", "allow"]
} if {
  is_messaging_action
  messaging.action_family == "message.send"
  messaging.delivery_scope == "public_channel"
  rest.privilege_class == "outbound_send"
}

decision := {
  "decision": "require_approval",
  "rule_id": "messaging.channel_invite.requires_approval",
  "severity": "high",
  "reason": "Messaging membership expansion requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["messaging", "channel_invite", "approval"]
} if {
  is_messaging_action
  messaging.action_family == "channel.invite"
  messaging.membership_target_kind
  rest.privilege_class == "sharing_write"
}

decision := {
  "decision": "deny",
  "rule_id": "messaging.permission_update.denied",
  "severity": "critical",
  "reason": "Messaging permission updates are denied by the preview policy",
  "approval": null,
  "tags": ["messaging", "permission_update", "deny"]
} if {
  is_messaging_action
  messaging.action_family == "permission.update"
  messaging.permission_target_kind == "channel_permission_overwrite"
  rest.privilege_class == "sharing_write"
}

decision := {
  "decision": "require_approval",
  "rule_id": "messaging.file_upload.requires_approval",
  "severity": "high",
  "reason": "Messaging file uploads require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["messaging", "file_upload", "approval"]
} if {
  is_messaging_action
  messaging.action_family == "file.upload"
  messaging.file_target_kind == "channel_attachment"
  messaging.attachment_count_hint >= 1
}
