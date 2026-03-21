use std::collections::BTreeMap;

use agenta_core::{
    Action, Actor, ApprovalPolicy, ApprovalRequest, ApprovalRequestAction, ApprovalStatus,
    CollectorKind, EnforcementInfo, EventEnvelope, PolicyDecision, PolicyDecisionKind,
    PolicyMetadata, RequesterContext, ResultStatus, SessionRef,
    messaging::{
        DeliveryScope, FileTargetKind, MembershipTargetKind, MessagingAction,
        MessagingActionFamily, PermissionTargetKind,
    },
    provider::{
        ActionKey, OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionId, ProviderId,
        ProviderSemanticAction, SideEffect,
    },
    rest::{GenericRestAction, PathTemplate, QueryClass, RestHost},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub type JsonMap = BTreeMap<String, Value>;

const POLICY_ENTRYPOINT: &str = "data.agentauditor.authz.decision";
const FILESYSTEM_POLICY_MODULE: &str = include_str!("../../../examples/policies/sensitive_fs.rego");
const PROCESS_EXEC_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/process_exec.rego");
const NETWORK_DESTINATION_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/network_destination.rego");
const SECRET_ACCESS_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/secret_access.rego");
const GWS_ACTION_POLICY_MODULE: &str = include_str!("../../../examples/policies/gws_action.rego");
const GENERIC_REST_ACTION_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/generic_rest_action.rego");
const MESSAGING_ACTION_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/messaging_action.rego");
const GITHUB_ACTION_POLICY_MODULE: &str =
    include_str!("../../../examples/policies/github_action.rego");

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_action: Option<ProviderSemanticAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_rest_action: Option<GenericRestAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messaging_action: Option<MessagingAction>,
    pub context: PolicyContext,
}

impl PolicyInput {
    pub fn new(
        request_id: impl Into<String>,
        session: SessionRef,
        actor: Actor,
        action: Action,
    ) -> Self {
        let provider_action = provider_action_from_action(&action);
        let generic_rest_action = generic_rest_action_from_action(&action);
        let messaging_action = messaging_action_from_action(&action);
        Self {
            request_id: request_id.into(),
            timestamp: Utc::now(),
            session,
            actor,
            action,
            provider_action,
            generic_rest_action,
            messaging_action,
            context: PolicyContext {
                recent_denies: 0,
                labels: Vec::new(),
                coverage: None,
                attributes: JsonMap::new(),
            },
        }
    }

    pub fn from_event(event: &EventEnvelope) -> Self {
        let provider_action = provider_action_from_action(&event.action);
        let generic_rest_action = generic_rest_action_from_action(&event.action);
        let messaging_action = messaging_action_from_action(&event.action);
        let mut input = Self {
            request_id: format!("req_{}", event.event_id),
            timestamp: event.timestamp,
            session: event.session.clone(),
            actor: event.actor.clone(),
            action: event.action.clone(),
            provider_action,
            generic_rest_action,
            messaging_action,
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

fn provider_action_from_action(action: &Action) -> Option<ProviderSemanticAction> {
    let provider_action_id = action_attribute(action, "provider_action_id")
        .and_then(|value| value.parse::<ProviderActionId>().ok());
    let provider_id = action_attribute(action, "provider_id")
        .and_then(|value| ProviderId::new(value).ok())
        .or_else(|| {
            provider_action_id
                .as_ref()
                .map(|value| value.provider_id.clone())
        })?;
    let action_key = action_attribute(action, "action_key")
        .and_then(|value| ActionKey::new(value).ok())
        .or_else(|| {
            provider_action_id
                .as_ref()
                .map(|value| value.action_key.clone())
        })
        .or_else(|| {
            action
                .verb
                .as_deref()
                .and_then(|value| ActionKey::new(value).ok())
        })?;
    let target_hint = action_attribute(action, "target_hint")
        .map(str::to_owned)
        .or_else(|| action.target.clone())
        .unwrap_or_default();

    Some(ProviderSemanticAction::new(
        provider_id,
        action_key,
        target_hint,
    ))
}

fn action_attribute<'a>(action: &'a Action, key: &str) -> Option<&'a str> {
    action.attributes.get(key).and_then(Value::as_str)
}

fn generic_rest_action_from_action(action: &Action) -> Option<GenericRestAction> {
    let provider_action = provider_action_from_action(action)?;
    let method = action_attribute(action, "method")?.parse().ok()?;
    let host = action_attribute(action, "host")?.parse::<RestHost>().ok()?;
    let path_template = action_attribute(action, "path_template")?
        .parse::<PathTemplate>()
        .ok()?;
    let query_class = action_attribute(action, "query_class")?
        .parse::<QueryClass>()
        .ok()?;
    let oauth_scope_labels = action
        .attributes
        .get("oauth_scope_labels")
        .and_then(oauth_scope_set_from_value)?;
    let side_effect =
        action_attribute(action, "side_effect").and_then(|value| SideEffect::new(value).ok())?;
    let privilege_class = action_attribute(action, "privilege_class")
        .and_then(|value| value.parse::<PrivilegeClass>().ok())?;

    Some(GenericRestAction::from_provider_action(
        provider_action,
        method,
        host,
        path_template,
        query_class,
        oauth_scope_labels,
        side_effect,
        privilege_class,
    ))
}

fn oauth_scope_set_from_value(value: &Value) -> Option<OAuthScopeSet> {
    let object = value.as_object()?;
    let primary = object
        .get("primary")
        .and_then(Value::as_str)
        .and_then(|value| OAuthScope::new(value).ok())?;
    let documented = match object.get("documented") {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().and_then(|scope| OAuthScope::new(scope).ok()))
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
        None => Vec::new(),
    };

    Some(OAuthScopeSet::new(primary, documented))
}

fn messaging_action_from_action(action: &Action) -> Option<MessagingAction> {
    let generic_rest_action = generic_rest_action_from_action(action)?;
    let action_family = action_attribute(action, "action_family")?
        .parse::<MessagingActionFamily>()
        .ok()?;
    let channel_hint = action_attribute(action, "channel_hint").map(str::to_owned);
    let conversation_hint = action_attribute(action, "conversation_hint").map(str::to_owned);
    let delivery_scope = match action_attribute(action, "delivery_scope") {
        Some(value) => Some(value.parse::<DeliveryScope>().ok()?),
        None => None,
    };
    let membership_target_kind = match action_attribute(action, "membership_target_kind") {
        Some(value) => Some(value.parse::<MembershipTargetKind>().ok()?),
        None => None,
    };
    let permission_target_kind = match action_attribute(action, "permission_target_kind") {
        Some(value) => Some(value.parse::<PermissionTargetKind>().ok()?),
        None => None,
    };
    let file_target_kind = match action_attribute(action, "file_target_kind") {
        Some(value) => Some(value.parse::<FileTargetKind>().ok()?),
        None => None,
    };
    let attachment_count_hint = match action.attributes.get("attachment_count_hint") {
        Some(value) => Some(u16::try_from(value.as_u64()?).ok()?),
        None => None,
    };

    Some(MessagingAction::from_generic_rest_action(
        generic_rest_action,
        action_family,
        channel_hint,
        conversation_hint,
        delivery_scope,
        membership_target_kind,
        permission_target_kind,
        file_target_kind,
        attachment_count_hint,
    ))
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
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/sensitive_fs.rego".to_owned(),
                FILESYSTEM_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn process_exec_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/process_exec.rego".to_owned(),
                PROCESS_EXEC_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn network_destination_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/network_destination.rego".to_owned(),
                NETWORK_DESTINATION_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn secret_access_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/secret_access.rego".to_owned(),
                SECRET_ACCESS_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn gws_action_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/gws_action.rego".to_owned(),
                GWS_ACTION_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn github_action_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/github_action.rego".to_owned(),
                GITHUB_ACTION_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn generic_rest_action_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/generic_rest_action.rego".to_owned(),
                GENERIC_REST_ACTION_POLICY_MODULE.to_owned(),
            )],
        )
    }

    pub fn messaging_action_example() -> Self {
        Self::new(
            POLICY_ENTRYPOINT,
            vec![(
                "examples/policies/messaging_action.rego".to_owned(),
                MESSAGING_ACTION_POLICY_MODULE.to_owned(),
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

pub fn apply_decision_to_event(event: &EventEnvelope, decision: &PolicyDecision) -> EventEnvelope {
    let mut enriched = event.clone();
    enriched.result.status = result_status_for_decision(decision.decision);
    enriched.result.reason = decision
        .reason
        .clone()
        .or_else(|| enriched.result.reason.clone());
    enriched.policy = Some(PolicyMetadata {
        decision: Some(decision.decision),
        rule_id: decision.rule_id.clone(),
        severity: decision.severity,
        explanation: decision.reason.clone(),
    });
    enriched
}

pub fn apply_enforcement_to_event(
    event: &EventEnvelope,
    enforcement: &EnforcementInfo,
) -> EventEnvelope {
    let mut enriched = event.clone();
    enriched.result.status = enforcement.status.result_status();
    enriched.result.reason = enforcement
        .status_reason
        .clone()
        .or_else(|| enriched.result.reason.clone());
    enriched.enforcement = Some(enforcement.clone());
    enriched
}

pub fn approval_request_from_decision(
    event: &EventEnvelope,
    decision: &PolicyDecision,
) -> Option<ApprovalRequest> {
    if decision.decision != PolicyDecisionKind::RequireApproval {
        return None;
    }

    let rule_id = decision.rule_id.clone()?;
    let constraint = decision.approval.clone()?;
    let action_verb = event.action.verb.clone()?;

    Some(ApprovalRequest {
        approval_id: format!("apr_{}", event.event_id),
        status: ApprovalStatus::Pending,
        requested_at: event.timestamp,
        resolved_at: None,
        expires_at: constraint
            .ttl_seconds
            .map(|seconds| event.timestamp + chrono::Duration::seconds(seconds as i64)),
        session_id: event.session.session_id.clone(),
        event_id: Some(event.event_id.clone()),
        request: ApprovalRequestAction {
            action_class: event.action.class,
            action_verb,
            target: event.action.target.clone(),
            summary: decision.reason.clone(),
            attributes: event.action.attributes.clone(),
        },
        policy: ApprovalPolicy {
            rule_id,
            severity: decision.severity,
            reason: decision.reason.clone(),
            scope: constraint.scope,
            ttl_seconds: constraint.ttl_seconds,
            reviewer_hint: constraint.reviewer_hint,
        },
        requester_context: Some(RequesterContext {
            agent_reason: decision.reason.clone(),
            human_request: None,
        }),
        decision: None,
        enforcement: None,
    })
}

pub fn apply_enforcement_to_approval_request(
    request: &ApprovalRequest,
    enforcement: &EnforcementInfo,
) -> ApprovalRequest {
    let mut enriched = request.clone();
    enriched.expires_at = enforcement.expires_at.or(enriched.expires_at);
    enriched.enforcement = Some(enforcement.clone());
    enriched
}

fn result_status_for_decision(decision: PolicyDecisionKind) -> ResultStatus {
    match decision {
        PolicyDecisionKind::Allow => ResultStatus::Allowed,
        PolicyDecisionKind::Deny => ResultStatus::Denied,
        PolicyDecisionKind::RequireApproval => ResultStatus::ApprovalRequired,
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
        agenta_core::EventType::GwsAction => "gws_action",
        agenta_core::EventType::GithubAction => "github_action",
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
        ActionClass, ActorKind, ApprovalConstraint, ApprovalScope, EnforcementDirective,
        EnforcementInfo, EnforcementStatus, EventEnvelope, EventType, PolicyDecisionKind,
        ResultInfo, ResultStatus, Severity, SourceInfo,
        provider::{ProviderActionId, ProviderSemanticAction},
    };
    use serde_json::json;

    #[test]
    fn policy_input_new_sets_stable_defaults() {
        let input = PolicyInput::new(
            "req_1",
            SessionRef {
                session_id: "sess_1".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: Some("user:example".to_owned()),
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
        assert!(input.provider_action.is_none());
        assert!(input.generic_rest_action.is_none());
        assert!(input.messaging_action.is_none());
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
        let value = serde_json::to_value(&input).expect("policy input should serialize");

        assert_eq!(input.request_id, "req_evt_fs_1");
        assert_eq!(input.action.class, ActionClass::Filesystem);
        assert_eq!(input.action.verb.as_deref(), Some("read"));
        assert!(input.provider_action.is_none());
        assert!(input.generic_rest_action.is_none());
        assert!(input.messaging_action.is_none());
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
        assert!(value.get("provider_action").is_none());
        assert!(value.get("generic_rest_action").is_none());
        assert!(value.get("messaging_action").is_none());
    }

    #[test]
    fn policy_input_from_event_derives_provider_action_from_shared_contract_fields() {
        let mut event = gws_event(
            "evt_gws_drive_permissions_update",
            "drive.permissions.update",
            "drive.files/abc123/permissions/perm456",
            "api_observation",
            "gws.drive",
        );
        event.action.attributes.remove("semantic_action_label");

        let input = PolicyInput::from_event(&event);
        let value = serde_json::to_value(&input).expect("policy input should serialize");

        assert_eq!(
            input.provider_action,
            Some(ProviderSemanticAction::from_id(
                ProviderActionId::from_parts("gws", "drive.permissions.update").unwrap(),
                "drive.files/abc123/permissions/perm456",
            ))
        );
        assert_eq!(value["provider_action"]["provider_id"], json!("gws"));
        assert_eq!(
            value["provider_action"]["action_key"],
            json!("drive.permissions.update")
        );
        assert_eq!(
            value["provider_action"]["target_hint"],
            json!("drive.files/abc123/permissions/perm456")
        );
    }

    #[test]
    fn policy_input_from_event_derives_generic_rest_action_from_flat_contract_fields() {
        let input = PolicyInput::from_event(&generic_rest_event(GenericRestEventFixture {
            event_id: "evt_rest_gmail_send",
            provider_id: "gws",
            action_key: "gmail.users.messages.send",
            target: "gmail.users/me",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            source_kind: "api_observation",
            semantic_surface: "gws.gmail",
            method: "POST",
            host: "gmail.googleapis.com",
            path_template: "/gmail/v1/users/{userId}/messages/send",
            query_class: "action_arguments",
            primary_scope: "https://www.googleapis.com/auth/gmail.send",
            documented_scopes: &["https://www.googleapis.com/auth/gmail.send"],
            side_effect: "sends a Gmail message to one or more recipients",
            privilege_class: "outbound_send",
        }));
        let value = serde_json::to_value(&input).expect("policy input should serialize");

        assert_eq!(
            input
                .provider_action
                .as_ref()
                .map(|item| item.action_key.as_str()),
            Some("gmail.users.messages.send")
        );
        assert_eq!(
            input
                .generic_rest_action
                .as_ref()
                .map(|item| item.host.as_str()),
            Some("gmail.googleapis.com")
        );
        assert_eq!(
            input
                .generic_rest_action
                .as_ref()
                .map(|item| item.path_template.as_str()),
            Some("/gmail/v1/users/{userId}/messages/send")
        );
        assert_eq!(
            input
                .generic_rest_action
                .as_ref()
                .map(|item| item.query_class),
            Some(QueryClass::ActionArguments)
        );
        assert_eq!(
            value["generic_rest_action"]["oauth_scope_labels"]["primary"],
            json!("https://www.googleapis.com/auth/gmail.send")
        );
        assert_eq!(
            value["generic_rest_action"]["privilege_class"],
            json!("outbound_send")
        );
    }

    #[test]
    fn policy_input_from_event_derives_messaging_action_from_flat_contract_fields() {
        let input = PolicyInput::from_event(&messaging_event(MessagingEventFixture {
            event_id: "evt_msg_slack_send",
            provider_id: "slack",
            action_key: "chat.post_message",
            target: "slack.channels/C12345678",
            event_type: EventType::NetworkConnect,
            action_class: ActionClass::Browser,
            source_kind: "api_observation",
            semantic_surface: "slack.chat",
            method: "POST",
            host: "slack.com",
            path_template: "/api/chat.postMessage",
            query_class: "action_arguments",
            primary_scope: "slack.scope:chat:write",
            documented_scopes: &["slack.scope:chat:write"],
            side_effect: "sends a message into a Slack conversation",
            privilege_class: "outbound_send",
            action_family: "message.send",
            channel_hint: Some("slack.channels/C12345678"),
            conversation_hint: None,
            delivery_scope: Some("public_channel"),
            membership_target_kind: None,
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        }));
        let value = serde_json::to_value(&input).expect("policy input should serialize");

        assert_eq!(
            input
                .messaging_action
                .as_ref()
                .map(|item| item.action_family.as_str()),
            Some("message.send")
        );
        assert_eq!(
            input
                .messaging_action
                .as_ref()
                .and_then(|item| item.channel_hint.as_deref()),
            Some("slack.channels/C12345678")
        );
        assert_eq!(
            input
                .messaging_action
                .as_ref()
                .and_then(|item| item.delivery_scope),
            Some(DeliveryScope::PublicChannel)
        );
        assert_eq!(
            value["messaging_action"]["action_family"],
            json!("message.send")
        );
        assert_eq!(
            value["messaging_action"]["delivery_scope"],
            json!("public_channel")
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
    fn sensitive_filesystem_rego_denies_sensitive_writes() {
        let event = filesystem_event("/home/agent/.ssh/config", "write");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("rego example should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("fs.sensitive.write"));
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(
            decision.reason.as_deref(),
            Some("sensitive path write is denied")
        );
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["filesystem", "deny"]);
    }

    #[test]
    fn evaluator_decodes_deny_decisions_from_rego_output() {
        let event = filesystem_event("/tmp/blocked", "read");
        let input = PolicyInput::from_event(&event);
        let evaluator = RegoPolicyEvaluator::new(
            POLICY_ENTRYPOINT,
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

    #[test]
    fn process_exec_rego_requires_approval_for_remote_shells() {
        let event = process_event("evt_proc_hold", 4545, "ssh", "/usr/bin/ssh");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .expect("process exec rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("proc.exec.ssh.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("remote shell execution requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(900),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(decision.tags, vec!["process", "approval"]);
    }

    #[test]
    fn process_exec_rego_denies_destructive_rm() {
        let event = process_event("evt_proc_deny", 4646, "rm", "/usr/bin/rm");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .expect("process exec rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("proc.exec.rm.denied"));
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("destructive rm execution is denied")
        );
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["process", "deny"]);
    }

    #[test]
    fn process_exec_rego_allows_non_destructive_execs() {
        let event = process_event("evt_proc_allow", 4242, "cargo", "/usr/bin/cargo");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .expect("process exec rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("default.allow"));
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(decision.reason.as_deref(), Some("no matching rule"));
        assert!(decision.approval.is_none());
        assert!(decision.tags.is_empty());
    }

    #[test]
    fn apply_decision_to_event_reflects_allow_result_in_metadata() {
        let event = filesystem_event("/workspace/src/main.rs", "read");
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::Allow,
            rule_id: Some("default.allow".to_owned()),
            severity: Some(Severity::Low),
            reason: Some("no matching rule".to_owned()),
            approval: None,
            tags: vec![],
        };

        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert_eq!(enriched.result.reason.as_deref(), Some("no matching rule"));
        assert_eq!(
            enriched.policy,
            Some(PolicyMetadata {
                decision: Some(PolicyDecisionKind::Allow),
                rule_id: Some("default.allow".to_owned()),
                severity: Some(Severity::Low),
                explanation: Some("no matching rule".to_owned()),
            })
        );
    }

    #[test]
    fn apply_decision_to_event_reflects_deny_result_in_metadata() {
        let event = filesystem_event("/tmp/blocked", "read");
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::Deny,
            rule_id: Some("fs.deny.demo".to_owned()),
            severity: Some(Severity::Critical),
            reason: Some("blocked for test".to_owned()),
            approval: None,
            tags: vec!["filesystem".to_owned(), "deny".to_owned()],
        };

        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(enriched.result.status, ResultStatus::Denied);
        assert_eq!(enriched.result.reason.as_deref(), Some("blocked for test"));
        assert_eq!(
            enriched.policy,
            Some(PolicyMetadata {
                decision: Some(PolicyDecisionKind::Deny),
                rule_id: Some("fs.deny.demo".to_owned()),
                severity: Some(Severity::Critical),
                explanation: Some("blocked for test".to_owned()),
            })
        );
    }

    #[test]
    fn apply_decision_to_event_reflects_require_approval_result_in_metadata() {
        let event = filesystem_event("/home/agent/.ssh/id_ed25519", "read");
        let decision = require_approval_decision();

        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched.result.reason.as_deref(),
            Some("sensitive path access requires approval")
        );
        assert_eq!(
            enriched.policy,
            Some(PolicyMetadata {
                decision: Some(PolicyDecisionKind::RequireApproval),
                rule_id: Some("fs.sensitive.read".to_owned()),
                severity: Some(Severity::High),
                explanation: Some("sensitive path access requires approval".to_owned()),
            })
        );
    }

    #[test]
    fn approval_request_from_decision_builds_pending_record_for_require_approval() {
        let event = filesystem_event("/home/agent/.ssh/id_ed25519", "read");
        let decision = require_approval_decision();

        let request = approval_request_from_decision(&event, &decision)
            .expect("require_approval should yield approval request");

        assert_eq!(request.approval_id, "apr_evt_fs_1");
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.session_id, "sess_bootstrap_hostd");
        assert_eq!(request.event_id.as_deref(), Some("evt_fs_1"));
        assert_eq!(request.request.action_class, ActionClass::Filesystem);
        assert_eq!(request.request.action_verb, "read");
        assert_eq!(
            request.request.target.as_deref(),
            Some("/home/agent/.ssh/id_ed25519")
        );
        assert_eq!(
            request.request.summary.as_deref(),
            Some("sensitive path access requires approval")
        );
        assert_eq!(request.policy.rule_id, "fs.sensitive.read");
        assert_eq!(request.policy.scope, Some(ApprovalScope::SingleAction));
        assert_eq!(request.policy.ttl_seconds, Some(1800));
        assert_eq!(
            request.policy.reviewer_hint.as_deref(),
            Some("security-oncall")
        );
        assert!(request.expires_at.is_some());
        assert_eq!(
            request
                .requester_context
                .as_ref()
                .and_then(|context| context.agent_reason.as_deref()),
            Some("sensitive path access requires approval")
        );
        assert!(request.decision.is_none());
    }

    #[test]
    fn approval_request_from_decision_skips_non_gated_decisions() {
        let event = filesystem_event("/workspace/src/main.rs", "read");
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::Allow,
            rule_id: Some("default.allow".to_owned()),
            severity: Some(Severity::Low),
            reason: Some("no matching rule".to_owned()),
            approval: None,
            tags: vec![],
        };

        assert!(approval_request_from_decision(&event, &decision).is_none());
    }

    #[test]
    fn apply_enforcement_to_event_attaches_runtime_outcome_metadata() {
        let event = apply_decision_to_event(
            &filesystem_event("/home/agent/.ssh/id_ed25519", "read"),
            &require_approval_decision(),
        );
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: Some("sensitive path access requires approval".to_owned()),
            enforced: true,
            coverage_gap: None,
            approval_id: Some("apr_evt_fs_1".to_owned()),
            expires_at: Some(event.timestamp + chrono::Duration::minutes(30)),
        };

        let enriched = apply_enforcement_to_event(&event, &enforcement);

        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched
                .enforcement
                .as_ref()
                .and_then(|value| value.approval_id.as_deref()),
            Some("apr_evt_fs_1")
        );
        assert_eq!(
            enriched.enforcement.as_ref().map(|value| value.directive),
            Some(EnforcementDirective::Hold)
        );
    }

    #[test]
    fn apply_enforcement_to_approval_request_carries_hold_metadata_into_record() {
        let event = apply_decision_to_event(
            &filesystem_event("/home/agent/.ssh/id_ed25519", "read"),
            &require_approval_decision(),
        );
        let request = approval_request_from_decision(&event, &require_approval_decision())
            .expect("require approval should create request");
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: Some("sensitive path access requires approval".to_owned()),
            enforced: true,
            coverage_gap: None,
            approval_id: Some(request.approval_id.clone()),
            expires_at: request.expires_at,
        };

        let enriched = apply_enforcement_to_approval_request(&request, &enforcement);

        assert_eq!(enriched.approval_id, request.approval_id);
        assert_eq!(enriched.expires_at, request.expires_at);
        assert_eq!(enriched.enforcement, Some(enforcement));
    }

    #[test]
    fn network_destination_rego_allows_allowlisted_public_tls_destination() {
        let event = network_event("93.184.216.34", 443, "tcp", Some("example.com"));
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&input)
            .expect("network rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("net.public.allowlisted_tls_domain")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("allowlisted public TLS destination")
        );
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["network", "allowlist"]);
    }

    #[test]
    fn network_destination_rego_requires_approval_for_public_unknown_destinations() {
        let event = network_event("203.0.113.10", 443, "tcp", None);
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&input)
            .expect("network rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("net.public.unallowlisted.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::Medium));
        assert_eq!(
            decision.reason.as_deref(),
            Some("public destination without allowlisted domain requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(900),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(decision.tags, vec!["network", "approval"]);
    }

    #[test]
    fn network_destination_rego_denies_public_smtp_destinations() {
        let event = network_event("198.51.100.25", 25, "tcp", None);
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::network_destination_example()
            .evaluate(&input)
            .expect("network rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("net.public.smtp.denied"));
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("public SMTP destination is denied")
        );
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["network", "deny"]);
    }

    #[test]
    fn secret_access_rego_allows_unmatched_env_file_access() {
        let event = secret_event(SecretEventFixture {
            event_id: "evt_secret_allow",
            verb: "read",
            target: "/workspace/.env.production",
            source_kind: "fanotify",
            taxonomy_kind: "secret_file",
            taxonomy_variant: "env_file",
            path: Some("/workspace/.env.production"),
            broker_id: None,
            broker_action: None,
        });
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("default.allow"));
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(decision.reason.as_deref(), Some("no matching rule"));
        assert!(decision.approval.is_none());
        assert!(decision.tags.is_empty());
    }

    #[test]
    fn secret_access_rego_requires_approval_for_brokered_requests() {
        let event = secret_event(SecretEventFixture {
            event_id: "evt_secret_approval",
            verb: "fetch",
            target: "kv/prod/db/password",
            source_kind: "broker_adapter",
            taxonomy_kind: "brokered_secret_request",
            taxonomy_variant: "secret_reference",
            path: None,
            broker_id: Some("vault"),
            broker_action: Some("read"),
        });
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("secret.brokered.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("brokered secret retrieval requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1200),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(decision.tags, vec!["secret", "approval"]);
    }

    #[test]
    fn secret_access_rego_requires_approval_for_ssh_secret_files() {
        let event = secret_event(SecretEventFixture {
            event_id: "evt_secret_ssh_approval",
            verb: "read",
            target: "/home/agent/.ssh/id_ed25519",
            source_kind: "fanotify",
            taxonomy_kind: "secret_file",
            taxonomy_variant: "ssh_material",
            path: Some("/home/agent/.ssh/id_ed25519"),
            broker_id: None,
            broker_action: None,
        });
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("secret.file.ssh_material.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("ssh secret file access requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1200),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(decision.tags, vec!["secret", "approval"]);
    }

    #[test]
    fn secret_access_rego_denies_kubernetes_service_account_access() {
        let event = secret_event(SecretEventFixture {
            event_id: "evt_secret_deny",
            verb: "read",
            target: "/var/run/secrets/kubernetes.io/serviceaccount/token",
            source_kind: "fanotify",
            taxonomy_kind: "mounted_secret",
            taxonomy_variant: "kubernetes_service_account",
            path: Some("/var/run/secrets/kubernetes.io/serviceaccount/token"),
            broker_id: None,
            broker_action: None,
        });
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("secret.mounted.kubernetes_service_account.denied")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("kubernetes service account secret access is denied")
        );
        assert!(decision.approval.is_none());
        assert_eq!(decision.tags, vec!["secret", "deny"]);
    }

    #[test]
    fn gws_action_rego_requires_approval_for_drive_permissions_updates() {
        let mut event = gws_event(
            "evt_gws_drive_permissions_update",
            "drive.permissions.update",
            "drive.files/abc123/permissions/perm456",
            "api_observation",
            "gws.drive",
        );
        event.action.attributes.remove("semantic_action_label");
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .expect("gws rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.drive.permissions_update.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Drive permission updates require approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(
            decision.tags,
            vec!["gws".to_owned(), "drive".to_owned(), "approval".to_owned()]
        );
    }

    #[test]
    fn gws_action_rego_requires_approval_for_drive_content_downloads() {
        let input = PolicyInput::from_event(&gws_event(
            "evt_gws_drive_get_media",
            "drive.files.get_media",
            "drive.files/abc123",
            "network_observation",
            "gws.drive",
        ));

        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .expect("gws rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.drive.files_get_media.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::Medium));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Drive file content downloads require approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(900),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
    }

    #[test]
    fn gws_action_rego_requires_approval_for_gmail_send() {
        let input = PolicyInput::from_event(&gws_event(
            "evt_gws_gmail_send",
            "gmail.users.messages.send",
            "gmail.users/me",
            "api_observation",
            "gws.gmail",
        ));

        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .expect("gws rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.gmail.users_messages_send.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Outbound Gmail send requires approval")
        );
    }

    #[test]
    fn gws_action_rego_allows_admin_activity_listing() {
        let input = PolicyInput::from_event(&gws_event(
            "evt_gws_admin_reports",
            "admin.reports.activities.list",
            "admin.reports/users/all/applications/drive",
            "api_observation",
            "gws.admin",
        ));

        let decision = RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .expect("gws rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("gws.admin.reports.activities_list.allow")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Admin activity listing is read-only audit retrieval")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec!["gws".to_owned(), "admin".to_owned(), "allow".to_owned()]
        );
    }

    #[test]
    fn github_action_rego_requires_approval_for_repository_visibility_changes() {
        let input = PolicyInput::from_event(&github_event(
            "evt_github_update_visibility",
            "repos.update_visibility",
            "repos/n01e0/agent-auditor/visibility",
            "api_observation",
            "github.repos",
        ));

        let decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&input)
            .expect("github rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("github.repos.update_visibility.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Repository visibility changes require approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(
            decision.tags,
            vec![
                "github".to_owned(),
                "repos".to_owned(),
                "approval".to_owned()
            ]
        );
    }

    #[test]
    fn github_action_rego_requires_approval_for_branch_protection_and_merge() {
        let branch_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&github_event(
                "evt_github_branch_protection",
                "branches.update_protection",
                "repos/n01e0/agent-auditor/branches/main/protection",
                "api_observation",
                "github.branches",
            )))
            .expect("github branch protection rego should evaluate");
        let merge_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&github_event(
                "evt_github_merge",
                "pulls.merge",
                "repos/n01e0/agent-auditor/pulls/72",
                "browser_observation",
                "github.pulls",
            )))
            .expect("github merge rego should evaluate");

        assert_eq!(
            branch_decision.decision,
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            branch_decision.rule_id.as_deref(),
            Some("github.branches.update_protection.requires_approval")
        );
        assert_eq!(branch_decision.severity, Some(Severity::High));
        assert_eq!(merge_decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            merge_decision.rule_id.as_deref(),
            Some("github.pulls.merge.requires_approval")
        );
        assert_eq!(merge_decision.severity, Some(Severity::High));
    }

    #[test]
    fn github_action_rego_requires_approval_for_workflow_dispatch() {
        let input = PolicyInput::from_event(&github_event(
            "evt_github_dispatch",
            "actions.workflow_dispatch",
            "repos/n01e0/agent-auditor/actions/workflows/ci.yml",
            "api_observation",
            "github.actions",
        ));

        let decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&input)
            .expect("github workflow dispatch rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("github.actions.workflow_dispatch.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::Medium));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Workflow dispatch requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(900),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
    }

    #[test]
    fn github_action_rego_allows_workflow_reruns() {
        let input = PolicyInput::from_event(&github_event(
            "evt_github_rerun",
            "actions.runs.rerun",
            "repos/n01e0/agent-auditor/actions/runs/123456",
            "api_observation",
            "github.actions",
        ));

        let decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&input)
            .expect("github rerun rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("github.actions.runs_rerun.allow")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Workflow rerun is allowed by the GitHub preview policy")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec![
                "github".to_owned(),
                "actions".to_owned(),
                "allow".to_owned()
            ]
        );
    }

    #[test]
    fn github_action_rego_denies_actions_secret_writes() {
        let input = PolicyInput::from_event(&github_event(
            "evt_github_secret_write",
            "actions.secrets.create_or_update",
            "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
            "api_observation",
            "github.actions",
        ));

        let decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&input)
            .expect("github secret write rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("github.actions.secrets_create_or_update.denied")
        );
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Repository Actions secret writes are denied by the GitHub preview policy")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec!["github".to_owned(), "actions".to_owned(), "deny".to_owned()]
        );
    }

    #[test]
    fn generic_rest_action_rego_denies_secret_writes() {
        let input = PolicyInput::from_event(&generic_rest_event(GenericRestEventFixture {
            event_id: "evt_rest_github_secret_write",
            provider_id: "github",
            action_key: "actions.secrets.create_or_update",
            target: "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
            event_type: EventType::GithubAction,
            action_class: ActionClass::Github,
            source_kind: "api_observation",
            semantic_surface: "github.actions",
            method: "PUT",
            host: "api.github.com",
            path_template: "/repos/{owner}/{repo}/actions/secrets/{secret_name}",
            query_class: "none",
            primary_scope: "github.permission:secrets:write",
            documented_scopes: &["github.permission:secrets:write", "github.oauth:repo"],
            side_effect: "creates or updates an encrypted repository Actions secret",
            privilege_class: "admin_write",
        }));

        let decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .expect("generic REST secret-write rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("generic_rest.secret_write.denied")
        );
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Generic REST secret write is denied")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec![
                "generic_rest".to_owned(),
                "secret".to_owned(),
                "deny".to_owned()
            ]
        );
    }

    #[test]
    fn generic_rest_action_rego_requires_approval_for_outbound_send() {
        let input = PolicyInput::from_event(&generic_rest_event(GenericRestEventFixture {
            event_id: "evt_rest_gmail_send",
            provider_id: "gws",
            action_key: "gmail.users.messages.send",
            target: "gmail.users/me",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            source_kind: "api_observation",
            semantic_surface: "gws.gmail",
            method: "POST",
            host: "gmail.googleapis.com",
            path_template: "/gmail/v1/users/{userId}/messages/send",
            query_class: "action_arguments",
            primary_scope: "https://www.googleapis.com/auth/gmail.send",
            documented_scopes: &["https://www.googleapis.com/auth/gmail.send"],
            side_effect: "sends a Gmail message to one or more recipients",
            privilege_class: "outbound_send",
        }));

        let decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .expect("generic REST outbound-send rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("generic_rest.outbound_send.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Outbound REST actions require approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(
            decision.tags,
            vec![
                "generic_rest".to_owned(),
                "outbound_send".to_owned(),
                "approval".to_owned()
            ]
        );
    }

    #[test]
    fn generic_rest_action_rego_allows_read_only_audit_listing() {
        let input = PolicyInput::from_event(&generic_rest_event(GenericRestEventFixture {
            event_id: "evt_rest_admin_reports",
            provider_id: "gws",
            action_key: "admin.reports.activities.list",
            target: "admin.reports/users/all/applications/drive",
            event_type: EventType::GwsAction,
            action_class: ActionClass::Gws,
            source_kind: "api_observation",
            semantic_surface: "gws.admin",
            method: "GET",
            host: "admin.googleapis.com",
            path_template: "/admin/reports/v1/activity/users/all/applications/{applicationName}",
            query_class: "filter",
            primary_scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            documented_scopes: &["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
            side_effect: "lists admin activity reports without mutating tenant state",
            privilege_class: "admin_read",
        }));

        let decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .expect("generic REST read-only rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("generic_rest.read_only.allow")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Read-only generic REST audit retrieval is allowed")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec![
                "generic_rest".to_owned(),
                "read_only".to_owned(),
                "allow".to_owned()
            ]
        );
    }

    #[test]
    fn messaging_action_rego_allows_public_channel_message_send() {
        let input = PolicyInput::from_event(&messaging_event(MessagingEventFixture {
            event_id: "evt_msg_slack_send_allow",
            provider_id: "slack",
            action_key: "chat.post_message",
            target: "slack.channels/C12345678",
            event_type: EventType::NetworkConnect,
            action_class: ActionClass::Browser,
            source_kind: "api_observation",
            semantic_surface: "slack.chat",
            method: "POST",
            host: "slack.com",
            path_template: "/api/chat.postMessage",
            query_class: "action_arguments",
            primary_scope: "slack.scope:chat:write",
            documented_scopes: &["slack.scope:chat:write"],
            side_effect: "sends a message into a Slack conversation",
            privilege_class: "outbound_send",
            action_family: "message.send",
            channel_hint: Some("slack.channels/C12345678"),
            conversation_hint: None,
            delivery_scope: Some("public_channel"),
            membership_target_kind: None,
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        }));

        let decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&input)
            .expect("messaging send rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("messaging.message_send.allow")
        );
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Public-channel messaging sends are allowed by the preview policy")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec![
                "messaging".to_owned(),
                "message_send".to_owned(),
                "allow".to_owned()
            ]
        );
    }

    #[test]
    fn messaging_action_rego_requires_approval_for_channel_invites() {
        let input = PolicyInput::from_event(&messaging_event(MessagingEventFixture {
            event_id: "evt_msg_discord_thread_invite",
            provider_id: "discord",
            action_key: "channels.thread_members.put",
            target: "discord.threads/123456789012345678/members/234567890123456789",
            event_type: EventType::NetworkConnect,
            action_class: ActionClass::Browser,
            source_kind: "browser_observation",
            semantic_surface: "discord.threads",
            method: "PUT",
            host: "discord.com",
            path_template: "/api/v10/channels/{thread_id}/thread-members/{user_id}",
            query_class: "none",
            primary_scope: "discord.permission:create_public_threads",
            documented_scopes: &[
                "discord.permission:create_public_threads",
                "discord.permission:send_messages_in_threads",
            ],
            side_effect: "adds a member into a Discord thread",
            privilege_class: "sharing_write",
            action_family: "channel.invite",
            channel_hint: None,
            conversation_hint: Some("discord.threads/123456789012345678"),
            delivery_scope: Some("thread"),
            membership_target_kind: Some("thread_member"),
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        }));

        let decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&input)
            .expect("messaging invite rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("messaging.channel_invite.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Messaging membership expansion requires approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(
            decision.tags,
            vec![
                "messaging".to_owned(),
                "channel_invite".to_owned(),
                "approval".to_owned()
            ]
        );
    }

    #[test]
    fn messaging_action_rego_denies_permission_updates() {
        let input = PolicyInput::from_event(&messaging_event(MessagingEventFixture {
            event_id: "evt_msg_discord_permission_update",
            provider_id: "discord",
            action_key: "channels.permissions.put",
            target: "discord.channels/123456789012345678/permissions/role:345678901234567890",
            event_type: EventType::NetworkConnect,
            action_class: ActionClass::Browser,
            source_kind: "api_observation",
            semantic_surface: "discord.permissions",
            method: "PUT",
            host: "discord.com",
            path_template: "/api/v10/channels/{channel_id}/permissions/{overwrite_id}",
            query_class: "none",
            primary_scope: "discord.permission:manage_roles",
            documented_scopes: &["discord.permission:manage_channels"],
            side_effect: "updates a Discord channel permission overwrite",
            privilege_class: "sharing_write",
            action_family: "permission.update",
            channel_hint: Some("discord.channels/123456789012345678"),
            conversation_hint: None,
            delivery_scope: None,
            membership_target_kind: None,
            permission_target_kind: Some("channel_permission_overwrite"),
            file_target_kind: None,
            attachment_count_hint: None,
        }));

        let decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&input)
            .expect("messaging permission rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("messaging.permission_update.denied")
        );
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Messaging permission updates are denied by the preview policy")
        );
        assert!(decision.approval.is_none());
        assert_eq!(
            decision.tags,
            vec![
                "messaging".to_owned(),
                "permission_update".to_owned(),
                "deny".to_owned()
            ]
        );
    }

    #[test]
    fn messaging_action_rego_requires_approval_for_file_uploads() {
        let input = PolicyInput::from_event(&messaging_event(MessagingEventFixture {
            event_id: "evt_msg_slack_file_upload",
            provider_id: "slack",
            action_key: "files.upload_v2",
            target: "slack.channels/C12345678/files/F12345678",
            event_type: EventType::NetworkConnect,
            action_class: ActionClass::Browser,
            source_kind: "api_observation",
            semantic_surface: "slack.files",
            method: "POST",
            host: "slack.com",
            path_template: "/api/files.uploadV2",
            query_class: "action_arguments",
            primary_scope: "slack.scope:files:write",
            documented_scopes: &["slack.scope:files:write"],
            side_effect: "uploads a file into a Slack conversation",
            privilege_class: "content_write",
            action_family: "file.upload",
            channel_hint: Some("slack.channels/C12345678"),
            conversation_hint: None,
            delivery_scope: Some("public_channel"),
            membership_target_kind: None,
            permission_target_kind: None,
            file_target_kind: Some("channel_attachment"),
            attachment_count_hint: Some(1),
        }));

        let decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&input)
            .expect("messaging file upload rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("messaging.file_upload.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("Messaging file uploads require approval")
        );
        assert_eq!(
            decision.approval,
            Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            })
        );
        assert_eq!(
            decision.tags,
            vec![
                "messaging".to_owned(),
                "file_upload".to_owned(),
                "approval".to_owned()
            ]
        );
    }

    fn require_approval_decision() -> PolicyDecision {
        PolicyDecision {
            decision: PolicyDecisionKind::RequireApproval,
            rule_id: Some("fs.sensitive.read".to_owned()),
            severity: Some(Severity::High),
            reason: Some("sensitive path access requires approval".to_owned()),
            approval: Some(ApprovalConstraint {
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            }),
            tags: vec!["filesystem".to_owned(), "approval".to_owned()],
        }
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

    fn process_event(event_id: &str, pid: u32, command: &str, filename: &str) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("pid".to_owned(), json!(pid));
        attributes.insert("ppid".to_owned(), json!(1337));
        attributes.insert("uid".to_owned(), json!(1000));
        attributes.insert("gid".to_owned(), json!(1000));
        attributes.insert("command".to_owned(), json!(command));
        attributes.insert("filename".to_owned(), json!(filename));

        EventEnvelope::new(
            event_id,
            EventType::ProcessExec,
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
                class: ActionClass::Process,
                verb: Some("exec".to_owned()),
                target: Some(filename.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd exec/exit PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Ebpf,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(pid as i32),
                ppid: Some(1337),
            },
        )
    }

    fn network_event(
        destination_ip: &str,
        destination_port: u16,
        transport: &str,
        domain_candidate: Option<&str>,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("pid".to_owned(), json!(4242));
        attributes.insert("sock_fd".to_owned(), json!(7));
        attributes.insert("destination_ip".to_owned(), json!(destination_ip));
        attributes.insert("destination_port".to_owned(), json!(destination_port));
        attributes.insert("transport".to_owned(), json!(transport));
        attributes.insert("address_family".to_owned(), json!("inet"));
        attributes.insert("destination_scope".to_owned(), json!("public"));
        attributes.insert("domain_candidate".to_owned(), json!(domain_candidate));
        attributes.insert(
            "domain_attribution_source".to_owned(),
            json!(domain_candidate.map(|_| "dns_answer_cache_exact_ip")),
        );

        EventEnvelope::new(
            "evt_net_1",
            EventType::NetworkConnect,
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
                class: ActionClass::Network,
                verb: Some("connect".to_owned()),
                target: Some(format!("{destination_ip}:{destination_port}")),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd network PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Ebpf,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4242),
                ppid: None,
            },
        )
    }

    fn github_event(
        event_id: &str,
        action_key: &str,
        target: &str,
        source_kind: &str,
        semantic_surface: &str,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(source_kind));
        attributes.insert("request_id".to_owned(), json!(format!("req_{event_id}")));
        attributes.insert(
            "transport".to_owned(),
            json!(if source_kind == "browser_observation" {
                "browser"
            } else {
                "https"
            }),
        );
        attributes.insert("semantic_surface".to_owned(), json!(semantic_surface));
        attributes.insert("provider_id".to_owned(), json!("github"));
        attributes.insert("action_key".to_owned(), json!(action_key));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(format!("github:{action_key}")),
        );
        attributes.insert("semantic_action_label".to_owned(), json!(action_key));
        attributes.insert("target_hint".to_owned(), json!(target));
        attributes.insert(
            "classifier_labels".to_owned(),
            json!([semantic_surface, action_key]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["classified for GitHub policy test"]),
        );
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope::new(
            event_id,
            EventType::GithubAction,
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
                class: ActionClass::Github,
                verb: Some(action_key.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd GitHub semantic-governance PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        )
    }

    struct GenericRestEventFixture<'a> {
        event_id: &'a str,
        provider_id: &'a str,
        action_key: &'a str,
        target: &'a str,
        event_type: EventType,
        action_class: ActionClass,
        source_kind: &'a str,
        semantic_surface: &'a str,
        method: &'a str,
        host: &'a str,
        path_template: &'a str,
        query_class: &'a str,
        primary_scope: &'a str,
        documented_scopes: &'a [&'a str],
        side_effect: &'a str,
        privilege_class: &'a str,
    }

    fn generic_rest_event(fixture: GenericRestEventFixture<'_>) -> EventEnvelope {
        let GenericRestEventFixture {
            event_id,
            provider_id,
            action_key,
            target,
            event_type,
            action_class,
            source_kind,
            semantic_surface,
            method,
            host,
            path_template,
            query_class,
            primary_scope,
            documented_scopes,
            side_effect,
            privilege_class,
        } = fixture;

        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(source_kind));
        attributes.insert("request_id".to_owned(), json!(format!("req_{event_id}")));
        attributes.insert(
            "transport".to_owned(),
            json!(if source_kind == "browser_observation" {
                "browser"
            } else {
                "https"
            }),
        );
        attributes.insert("semantic_surface".to_owned(), json!(semantic_surface));
        attributes.insert("provider_id".to_owned(), json!(provider_id));
        attributes.insert("action_key".to_owned(), json!(action_key));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(format!("{provider_id}:{action_key}")),
        );
        attributes.insert("target_hint".to_owned(), json!(target));
        attributes.insert("method".to_owned(), json!(method));
        attributes.insert("host".to_owned(), json!(host));
        attributes.insert("path_template".to_owned(), json!(path_template));
        attributes.insert("query_class".to_owned(), json!(query_class));
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": primary_scope,
                "documented": documented_scopes,
            }),
        );
        attributes.insert("side_effect".to_owned(), json!(side_effect));
        attributes.insert("privilege_class".to_owned(), json!(privilege_class));

        EventEnvelope::new(
            event_id,
            event_type,
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
                class: action_class,
                verb: Some(action_key.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd generic REST policy fixture".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        )
    }

    struct MessagingEventFixture<'a> {
        event_id: &'a str,
        provider_id: &'a str,
        action_key: &'a str,
        target: &'a str,
        event_type: EventType,
        action_class: ActionClass,
        source_kind: &'a str,
        semantic_surface: &'a str,
        method: &'a str,
        host: &'a str,
        path_template: &'a str,
        query_class: &'a str,
        primary_scope: &'a str,
        documented_scopes: &'a [&'a str],
        side_effect: &'a str,
        privilege_class: &'a str,
        action_family: &'a str,
        channel_hint: Option<&'a str>,
        conversation_hint: Option<&'a str>,
        delivery_scope: Option<&'a str>,
        membership_target_kind: Option<&'a str>,
        permission_target_kind: Option<&'a str>,
        file_target_kind: Option<&'a str>,
        attachment_count_hint: Option<u16>,
    }

    fn messaging_event(fixture: MessagingEventFixture<'_>) -> EventEnvelope {
        let MessagingEventFixture {
            event_id,
            provider_id,
            action_key,
            target,
            event_type,
            action_class,
            source_kind,
            semantic_surface,
            method,
            host,
            path_template,
            query_class,
            primary_scope,
            documented_scopes,
            side_effect,
            privilege_class,
            action_family,
            channel_hint,
            conversation_hint,
            delivery_scope,
            membership_target_kind,
            permission_target_kind,
            file_target_kind,
            attachment_count_hint,
        } = fixture;

        let mut event = generic_rest_event(GenericRestEventFixture {
            event_id,
            provider_id,
            action_key,
            target,
            event_type,
            action_class,
            source_kind,
            semantic_surface,
            method,
            host,
            path_template,
            query_class,
            primary_scope,
            documented_scopes,
            side_effect,
            privilege_class,
        });
        event
            .action
            .attributes
            .insert("action_family".to_owned(), json!(action_family));
        if let Some(channel_hint) = channel_hint {
            event
                .action
                .attributes
                .insert("channel_hint".to_owned(), json!(channel_hint));
        }
        if let Some(conversation_hint) = conversation_hint {
            event
                .action
                .attributes
                .insert("conversation_hint".to_owned(), json!(conversation_hint));
        }
        if let Some(delivery_scope) = delivery_scope {
            event
                .action
                .attributes
                .insert("delivery_scope".to_owned(), json!(delivery_scope));
        }
        if let Some(membership_target_kind) = membership_target_kind {
            event.action.attributes.insert(
                "membership_target_kind".to_owned(),
                json!(membership_target_kind),
            );
        }
        if let Some(permission_target_kind) = permission_target_kind {
            event.action.attributes.insert(
                "permission_target_kind".to_owned(),
                json!(permission_target_kind),
            );
        }
        if let Some(file_target_kind) = file_target_kind {
            event
                .action
                .attributes
                .insert("file_target_kind".to_owned(), json!(file_target_kind));
        }
        if let Some(attachment_count_hint) = attachment_count_hint {
            event.action.attributes.insert(
                "attachment_count_hint".to_owned(),
                json!(attachment_count_hint),
            );
        }
        event
    }

    fn gws_event(
        event_id: &str,
        action_key: &str,
        target: &str,
        source_kind: &str,
        semantic_surface: &str,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(source_kind));
        attributes.insert("request_id".to_owned(), json!(format!("req_{event_id}")));
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!(semantic_surface));
        attributes.insert("provider_id".to_owned(), json!("gws"));
        attributes.insert("action_key".to_owned(), json!(action_key));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(format!("gws:{action_key}")),
        );
        attributes.insert("semantic_action_label".to_owned(), json!(action_key));
        attributes.insert("target_hint".to_owned(), json!(target));
        attributes.insert(
            "classifier_labels".to_owned(),
            json!([semantic_surface, action_key]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["classified for policy test"]),
        );
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope::new(
            event_id,
            EventType::GwsAction,
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
                class: ActionClass::Gws,
                verb: Some(action_key.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd API/network GWS PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: match source_kind {
                    "api_observation" => CollectorKind::RuntimeHint,
                    _ => CollectorKind::Ebpf,
                },
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        )
    }

    struct SecretEventFixture<'a> {
        event_id: &'a str,
        verb: &'a str,
        target: &'a str,
        source_kind: &'a str,
        taxonomy_kind: &'a str,
        taxonomy_variant: &'a str,
        path: Option<&'a str>,
        broker_id: Option<&'a str>,
        broker_action: Option<&'a str>,
    }

    fn secret_event(fixture: SecretEventFixture<'_>) -> EventEnvelope {
        let SecretEventFixture {
            event_id,
            verb,
            target,
            source_kind,
            taxonomy_kind,
            taxonomy_variant,
            path,
            broker_id,
            broker_action,
        } = fixture;

        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(source_kind));
        attributes.insert("taxonomy_kind".to_owned(), json!(taxonomy_kind));
        attributes.insert("taxonomy_variant".to_owned(), json!(taxonomy_variant));
        attributes.insert("locator_hint".to_owned(), json!(target));
        attributes.insert(
            "classifier_labels".to_owned(),
            json!([taxonomy_kind, taxonomy_variant]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["classified for test"]),
        );
        attributes.insert("plaintext_retained".to_owned(), json!(false));
        if let Some(path) = path {
            attributes.insert("path".to_owned(), json!(path));
        }
        if let Some(broker_id) = broker_id {
            attributes.insert("broker_id".to_owned(), json!(broker_id));
        }
        if let Some(broker_action) = broker_action {
            attributes.insert("broker_action".to_owned(), json!(broker_action));
        }

        EventEnvelope::new(
            event_id,
            EventType::SecretAccess,
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
                class: ActionClass::Secret,
                verb: Some(verb.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd secret access PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: match source_kind {
                    "fanotify" => CollectorKind::Fanotify,
                    _ => CollectorKind::ControlPlane,
                },
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        )
    }
}
