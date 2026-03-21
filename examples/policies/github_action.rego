package agentauditor.authz

default decision := {
  "decision": "allow",
  "rule_id": "default.allow",
  "severity": "low",
  "reason": "no matching rule",
  "approval": null,
  "tags": []
}

is_github_action if {
  input.provider_action.provider_id == "github"
}

action_key := key if {
  key := input.provider_action.action_key
}

decision := {
  "decision": "require_approval",
  "rule_id": "github.repos.update_visibility.requires_approval",
  "severity": "high",
  "reason": "Repository visibility changes require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["github", "repos", "approval"]
} if {
  is_github_action
  action_key == "repos.update_visibility"
}

decision := {
  "decision": "require_approval",
  "rule_id": "github.branches.update_protection.requires_approval",
  "severity": "high",
  "reason": "Branch protection updates require approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["github", "branches", "approval"]
} if {
  is_github_action
  action_key == "branches.update_protection"
}

decision := {
  "decision": "require_approval",
  "rule_id": "github.actions.workflow_dispatch.requires_approval",
  "severity": "medium",
  "reason": "Workflow dispatch requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 900,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["github", "actions", "approval"]
} if {
  is_github_action
  action_key == "actions.workflow_dispatch"
}

decision := {
  "decision": "allow",
  "rule_id": "github.actions.runs_rerun.allow",
  "severity": "low",
  "reason": "Workflow rerun is allowed by the GitHub preview policy",
  "approval": null,
  "tags": ["github", "actions", "allow"]
} if {
  is_github_action
  action_key == "actions.runs.rerun"
}

decision := {
  "decision": "require_approval",
  "rule_id": "github.pulls.merge.requires_approval",
  "severity": "high",
  "reason": "Pull request merge requires approval",
  "approval": {
    "scope": "single_action",
    "ttl_seconds": 1800,
    "reviewer_hint": "security-oncall"
  },
  "tags": ["github", "pulls", "approval"]
} if {
  is_github_action
  action_key == "pulls.merge"
}

decision := {
  "decision": "deny",
  "rule_id": "github.actions.secrets_create_or_update.denied",
  "severity": "critical",
  "reason": "Repository Actions secret writes are denied by the GitHub preview policy",
  "approval": null,
  "tags": ["github", "actions", "deny"]
} if {
  is_github_action
  action_key == "actions.secrets.create_or_update"
}
