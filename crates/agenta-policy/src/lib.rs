use std::collections::BTreeMap;

use agenta_core::{Action, Actor, CollectorKind, EventEnvelope, PolicyDecision, SessionRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub type JsonMap = BTreeMap<String, Value>;

const FILESYSTEM_POLICY_ENTRYPOINT: &str = "data.agentauditor.authz.decision";
const FILESYSTEM_POLICY_MODULE: &str = include_str!("../../../examples/policies/sensitive_fs.rego");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCoverageContext {
    pub collector: Option<String>,
    pub enforce_capable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub recent_denies: u32,
    #[serde(default)]
    pub labels: Vec<String>,
    pub coverage: Option<PolicyCoverageContext>,
    #[serde(default)]
    pub attributes: JsonMap,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub session: SessionRef,
    pub actor: Actor,
    pub action: Action,
    pub context: PolicyContext,
}

impl PolicyInput {
    pub fn new(
        request_id: impl Into<String>,
        session: SessionRef,
        actor: Actor,
        action: Action,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            timestamp: Utc::now(),
            session,
            actor,
            action,
            context: PolicyContext {
                recent_denies: 0,
                labels: Vec::new(),
                coverage: None,
                attributes: JsonMap::new(),
            },
        }
    }

    pub fn from_event(event: &EventEnvelope) -> Self {
        let mut input = Self {
            request_id: format!("req_{}", event.event_id),
            timestamp: event.timestamp,
            session: event.session.clone(),
            actor: event.actor.clone(),
            action: event.action.clone(),
            context: PolicyContext {
                recent_denies: 0,
                labels: vec![format!("event_type:{}", event_type_label(event))],
                coverage: Some(PolicyCoverageContext {
                    collector: Some(collector_label(event.source.collector).to_owned()),
                    enforce_capable: false,
                }),
                attributes: JsonMap::new(),
            },
        };

        if let Some(host_id) = &event.source.host_id {
            input
                .context
                .attributes
                .insert("host_id".to_owned(), Value::String(host_id.clone()));
        }

        if let Some(container_id) = &event.source.container_id {
            input.context.attributes.insert(
                "container_id".to_owned(),
                Value::String(container_id.clone()),
            );
        }

        if let Some(pod_uid) = &event.source.pod_uid {
            input
                .context
                .attributes
                .insert("pod_uid".to_owned(), Value::String(pod_uid.clone()));
        }

        if let Some(pid) = event.source.pid {
            input
                .context
                .attributes
                .insert("source_pid".to_owned(), Value::from(pid));
        }

        if let Some(ppid) = event.source.ppid {
            input
                .context
                .attributes
                .insert("source_ppid".to_owned(), Value::from(ppid));
        }

        input
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to serialize policy input: {0}")]
    SerializeInput(#[from] serde_json::Error),
    #[error("failed to parse rego input: {0}")]
    ParseInput(String),
    #[error("failed to load rego policy: {0}")]
    LoadPolicy(String),
    #[error("rego evaluation failed: {0}")]
    Evaluate(String),
    #[error("rego decision entrypoint returned undefined: {entrypoint}")]
    UndefinedDecision { entrypoint: String },
}

pub trait PolicyEvaluator {
    fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, PolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegoPolicyEvaluator {
    entrypoint: String,
    modules: Vec<(String, String)>,
}

impl RegoPolicyEvaluator {
    pub fn new(entrypoint: impl Into<String>, modules: Vec<(String, String)>) -> Self {
        Self {
            entrypoint: entrypoint.into(),
            modules,
        }
    }

    pub fn sensitive_filesystem_example() -> Self {
        Self::new(
            FILESYSTEM_POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/sensitive_fs.rego".to_owned(),
                FILESYSTEM_POLICY_MODULE.to_owned(),
            )],
        )
    }
}

impl PolicyEvaluator for RegoPolicyEvaluator {
    fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, PolicyError> {
        let mut engine = regorus::Engine::new();
        for (path, module) in &self.modules {
            engine
                .add_policy(path.clone(), module.clone())
                .map_err(|error| PolicyError::LoadPolicy(error.to_string()))?;
        }

        let input_json = serde_json::to_string(input)?;
        let value = regorus::Value::from_json_str(&input_json)
            .map_err(|error| PolicyError::ParseInput(error.to_string()))?;
        engine.set_input(value);

        let result = engine
            .eval_rule(self.entrypoint.clone())
            .map_err(|error| PolicyError::Evaluate(error.to_string()))?;

        if result == regorus::Value::Undefined {
            return Err(PolicyError::UndefinedDecision {
                entrypoint: self.entrypoint.clone(),
            });
        }

        serde_json::from_str(&result.to_string()).map_err(PolicyError::SerializeInput)
    }
}

fn collector_label(collector: CollectorKind) -> &'static str {
    match collector {
        CollectorKind::Ebpf => "ebpf",
        CollectorKind::Fanotify => "fanotify",
        CollectorKind::RuntimeHint => "runtime_hint",
        CollectorKind::ControlPlane => "control_plane",
        CollectorKind::Operator => "operator",
    }
}

fn event_type_label(event: &EventEnvelope) -> &'static str {
    match event.event_type {
        agenta_core::EventType::SessionLifecycle => "session_lifecycle",
        agenta_core::EventType::ProcessExec => "process_exec",
        agenta_core::EventType::ProcessExit => "process_exit",
        agenta_core::EventType::FilesystemAccess => "filesystem_access",
        agenta_core::EventType::NetworkConnect => "network_connect",
        agenta_core::EventType::SecretAccess => "secret_access",
        agenta_core::EventType::PolicyDecision => "policy_decision",
        agenta_core::EventType::ApprovalRequested => "approval_requested",
        agenta_core::EventType::ApprovalResolved => "approval_resolved",
        agenta_core::EventType::AlertRaised => "alert_raised",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenta_core::{
        ActionClass, ActorKind, ApprovalConstraint, ApprovalScope, EventEnvelope, EventType,
        PolicyDecisionKind, ResultInfo, ResultStatus, Severity, SourceInfo,
    };
    use serde_json::json;

    #[test]
    fn policy_input_new_sets_stable_defaults() {
        let input = PolicyInput::new(
            "req_1",
            SessionRef {
                session_id: "sess_1".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: Some("user:n01e0".to_owned()),
                workspace_id: None,
                policy_bundle_version: Some("bundle-1".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::Agent,
                id: Some("openclaw-main".to_owned()),
                display_name: None,
            },
            Action {
                class: ActionClass::Process,
                verb: Some("exec".to_owned()),
                target: Some("/usr/bin/git".to_owned()),
                attributes: JsonMap::new(),
            },
        );

        assert_eq!(input.request_id, "req_1");
        assert_eq!(input.context.recent_denies, 0);
        assert!(input.context.labels.is_empty());
        assert!(input.context.coverage.is_none());
        assert!(input.context.attributes.is_empty());
    }

    #[test]
    fn policy_input_round_trips_with_context_attributes() {
        let mut input = PolicyInput::new(
            "req_2",
            SessionRef {
                session_id: "sess_2".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: None,
                environment: Some("prod".to_owned()),
            },
            Actor {
                kind: ActorKind::Agent,
                id: Some("openclaw-main".to_owned()),
                display_name: Some("OpenClaw Main".to_owned()),
            },
            Action {
                class: ActionClass::Network,
                verb: Some("connect".to_owned()),
                target: Some("api.example.com:443".to_owned()),
                attributes: JsonMap::new(),
            },
        );
        input.context.coverage = Some(PolicyCoverageContext {
            collector: Some("ebpf".to_owned()),
            enforce_capable: false,
        });
        input
            .context
            .attributes
            .insert("destination_domain".to_owned(), json!("api.example.com"));

        let value = serde_json::to_value(&input).expect("policy input should serialize");
        assert_eq!(value["action"]["class"], json!("network"));
        assert_eq!(value["context"]["coverage"]["collector"], json!("ebpf"));
        assert_eq!(
            value["context"]["attributes"]["destination_domain"],
            json!("api.example.com")
        );
    }

    #[test]
    fn policy_input_from_event_uses_event_shape_as_rego_input() {
        let event = filesystem_event("/home/agent/.ssh/id_ed25519", "read");

        let input = PolicyInput::from_event(&event);

        assert_eq!(input.request_id, "req_evt_fs_1");
        assert_eq!(input.action.class, ActionClass::Filesystem);
        assert_eq!(input.action.verb.as_deref(), Some("read"));
        assert_eq!(input.context.labels, vec!["event_type:filesystem_access"]);
        assert_eq!(
            input.context.coverage,
            Some(PolicyCoverageContext {
                collector: Some("fanotify".to_owned()),
                enforce_capable: false,
            })
        );
        assert_eq!(
            input.context.attributes.get("host_id"),
            Some(&json!("hostd-poc"))
        );
        assert_eq!(
            input.context.attributes.get("source_pid"),
            Some(&json!(4242))
        );
    }

    #[test]
    fn sensitive_filesystem_rego_requires_approval_for_sensitive_reads() {
        let event = filesystem_event("/home/agent/.ssh/id_ed25519", "read");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("rego example should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(decision.rule_id.as_deref(), Some("fs.sensitive.read"));
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("sensitive path access requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(decision.tags, vec!["filesystem", "approval"]);
    }

    #[test]
    fn sensitive_filesystem_rego_allows_non_sensitive_paths() {
        let event = filesystem_event("/workspace/src/main.rs", "read");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("rego example should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("default.allow"));
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(decision.reason.as_deref(), Some("no matching rule"));
        assert!(decision.approval.is_none());
        assert!(decision.tags.is_empty());
    }

    #[test]
    fn evaluator_decodes_deny_decisions_from_rego_output() {
        let event = filesystem_event("/tmp/blocked", "read");
        let input = PolicyInput::from_event(&event);
        let evaluator = RegoPolicyEvaluator::new(
            FILESYSTEM_POLICY_ENTRYPOINT,
            vec![(
                "deny.rego".to_owned(),
                r#"
                package agentauditor.authz

                decision := {
                  "decision": "deny",
                  "rule_id": "fs.deny.demo",
                  "severity": "critical",
                  "reason": "blocked for test",
                  "approval": null,
                  "tags": ["filesystem", "deny"]
                }
                "#
                .to_owned(),
            )],
        );

        let decision = evaluator
            .evaluate(&input)
            .expect("inline rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("fs.deny.demo"));
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(decision.reason.as_deref(), Some("blocked for test"));
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["filesystem", "deny"]);
    }

    fn filesystem_event(path: &str, verb: &str) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("path".to_owned(), json!(path));
        attributes.insert("access_verb".to_owned(), json!(verb));
        attributes.insert("sensitive".to_owned(), json!(path.contains(".ssh")));

        EventEnvelope::new(
            "evt_fs_1",
            EventType::FilesystemAccess,
            SessionRef {
                session_id: "sess_bootstrap_hostd".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Filesystem,
                verb: Some(verb.to_owned()),
                target: Some(path.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd filesystem PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Fanotify,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4242),
                ppid: None,
            },
        )
    }
}
