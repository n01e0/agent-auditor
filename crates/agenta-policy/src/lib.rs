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
