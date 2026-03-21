use super::contract::{PolicyBoundary, RecordBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(policy: PolicyBoundary) -> Self {
        Self {
            providers: policy.providers,
            action_families: policy.action_families,
            input_fields: policy.decision_fields,
            record_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "append redaction-safe messaging audit records and approval requests without replaying provider taxonomy, generic REST normalization, or messaging-family inference",
                "reflect allow, hold, and deny outcomes into append-only storage and later publish fanout using the checked-in messaging contract",
                "avoid storing raw message bodies, participant rosters, uploaded bytes, invite links, and provider-specific opaque payloads in the shared messaging record seam",
            ],
            stages: vec!["persist", "publish"],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            redaction_contract: policy.redaction_contract,
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        RecordBoundary {
            providers: self.providers.clone(),
            action_families: self.action_families.clone(),
            input_fields: self.input_fields.clone(),
            record_fields: self.record_fields.clone(),
            redaction_contract: self.redaction_contract,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} action_families={} input_fields={} record_fields={} stages={} sinks={}",
            self.providers.join(","),
            self.action_families.join(","),
            self.input_fields.join(","),
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}
