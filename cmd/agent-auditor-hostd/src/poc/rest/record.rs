use super::contract::{PolicyBoundary, RecordBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(policy: PolicyBoundary) -> Self {
        Self {
            providers: policy.providers,
            input_fields: policy.decision_fields,
            record_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "append redaction-safe generic REST audit records and approval requests without replaying provider-specific taxonomy or metadata joins",
                "reflect allow, hold, and deny outcomes into append-only storage and later publish fanout using the checked-in generic REST contract",
                "avoid storing raw request or response payloads, token values, signed URLs, full query strings, message bodies, or file bytes",
            ],
            stages: vec!["persist", "publish"],
            redaction_contract: policy.redaction_contract,
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        RecordBoundary {
            providers: self.providers.clone(),
            input_fields: self.input_fields.clone(),
            record_fields: self.record_fields.clone(),
            redaction_contract: self.redaction_contract,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} input_fields={} record_fields={} stages={}",
            self.providers.join(","),
            self.input_fields.join(","),
            self.record_fields.join(","),
            self.stages.join("->")
        )
    }
}
