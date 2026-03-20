use std::fmt;

use agenta_core::{
    ActionClass, ApprovalRequest, EventEnvelope, PolicyDecision, PolicyDecisionKind, ResultStatus,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementScope {
    Filesystem,
    Process,
}

impl EnforcementScope {
    pub fn action_class(self) -> ActionClass {
        match self {
            Self::Filesystem => ActionClass::Filesystem,
            Self::Process => ActionClass::Process,
        }
    }
}

impl fmt::Display for EnforcementScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Filesystem => "filesystem",
            Self::Process => "process",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDirective {
    Allow,
    Hold,
    Deny,
}

impl EnforcementDirective {
    pub fn from_policy_decision(decision: PolicyDecisionKind) -> Self {
        match decision {
            PolicyDecisionKind::Allow => Self::Allow,
            PolicyDecisionKind::RequireApproval => Self::Hold,
            PolicyDecisionKind::Deny => Self::Deny,
        }
    }

    pub fn result_status(self) -> ResultStatus {
        match self {
            Self::Allow => ResultStatus::Allowed,
            Self::Hold => ResultStatus::ApprovalRequired,
            Self::Deny => ResultStatus::Denied,
        }
    }
}

impl fmt::Display for EnforcementDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Allow => "allow",
            Self::Hold => "hold",
            Self::Deny => "deny",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Allowed,
    Held,
    Denied,
    ObserveOnlyFallback,
}

impl fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Allowed => "allowed",
            Self::Held => "held",
            Self::Denied => "denied",
            Self::ObserveOnlyFallback => "observe_only_fallback",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementOutcome {
    pub event_id: String,
    pub scope: EnforcementScope,
    pub target: Option<String>,
    pub action_verb: Option<String>,
    pub policy_decision: PolicyDecisionKind,
    pub directive: EnforcementDirective,
    pub status: EnforcementStatus,
    pub status_reason: String,
    pub enforced: bool,
    pub coverage_gap: Option<String>,
    pub approval_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl EnforcementOutcome {
    pub fn from_allowed_event(
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Self {
        Self {
            event_id: event.event_id.clone(),
            scope,
            target: event.action.target.clone(),
            action_verb: event.action.verb.clone(),
            policy_decision: decision.decision,
            directive: EnforcementDirective::Allow,
            status: EnforcementStatus::Allowed,
            status_reason: decision
                .reason
                .clone()
                .unwrap_or_else(|| "action allowed by policy".to_owned()),
            enforced: true,
            coverage_gap: None,
            approval_id: None,
            expires_at: None,
        }
    }

    pub fn held_for_approval(
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        request: &ApprovalRequest,
    ) -> Self {
        Self {
            event_id: event.event_id.clone(),
            scope,
            target: event.action.target.clone(),
            action_verb: event.action.verb.clone(),
            policy_decision: decision.decision,
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: decision
                .reason
                .clone()
                .unwrap_or_else(|| "action held pending approval".to_owned()),
            enforced: true,
            coverage_gap: None,
            approval_id: Some(request.approval_id.clone()),
            expires_at: request.expires_at,
        }
    }

    pub fn denied(
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Self {
        Self {
            event_id: event.event_id.clone(),
            scope,
            target: event.action.target.clone(),
            action_verb: event.action.verb.clone(),
            policy_decision: decision.decision,
            directive: EnforcementDirective::Deny,
            status: EnforcementStatus::Denied,
            status_reason: decision
                .reason
                .clone()
                .unwrap_or_else(|| "action denied by policy".to_owned()),
            enforced: true,
            coverage_gap: None,
            approval_id: None,
            expires_at: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("approval-hold enforcement requires an approval request for event `{event_id}`")]
    MissingApprovalRequest { event_id: String },
    #[error(
        "{stage} stage cannot apply directive `{directive}` for scope `{scope}` on event `{event_id}`"
    )]
    UnsupportedDirective {
        stage: &'static str,
        directive: EnforcementDirective,
        scope: EnforcementScope,
        event_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionBoundary {
    pub scopes: Vec<EnforcementScope>,
    pub input_fields: Vec<&'static str>,
    pub directive_fields: Vec<&'static str>,
}

impl DecisionBoundary {
    pub fn foundation_poc() -> Self {
        Self {
            scopes: vec![EnforcementScope::Filesystem, EnforcementScope::Process],
            input_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "coverage_context",
                "enforcement_capability",
            ],
            directive_fields: vec![
                "directive",
                "coverage_gap",
                "status_reason",
                "audit_context",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBoundary {
    pub scopes: Vec<EnforcementScope>,
    pub record_fields: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
}
