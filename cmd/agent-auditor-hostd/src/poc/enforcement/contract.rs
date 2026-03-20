use std::fmt;

use agenta_core::{ActionClass, PolicyDecisionKind, ResultStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
