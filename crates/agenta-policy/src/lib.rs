use std::collections::BTreeMap;

use agenta_core::{Action, Actor, PolicyDecision, SessionRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub type JsonMap = BTreeMap<String, Value>;

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
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy evaluation is not implemented yet")]
    NotImplemented,
}

pub trait PolicyEvaluator {
    fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, PolicyError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenta_core::{ActionClass, ActorKind};
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
}
