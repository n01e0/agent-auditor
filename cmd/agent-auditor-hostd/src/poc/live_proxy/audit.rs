use super::contract::{
    ApprovalBoundary, AuditBoundary, LIVE_PROXY_INTERCEPTION_REDACTION_RULE, PolicyBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPlan {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: AuditBoundary,
}

impl AuditPlan {
    pub fn from_policy_and_approval_boundaries(
        policy: PolicyBoundary,
        approval: ApprovalBoundary,
    ) -> Self {
        let modes = approval.modes;
        let input_fields = vec![
            "normalized_event",
            "policy_decision",
            "coverage_posture",
            "mode_status",
            "approval_eligibility",
            "approval_request",
            "approval_hold_allowed",
            "hold_reason",
            "expiry_hint",
            "resume_token_hint",
            "wait_state",
        ];
        let record_fields = vec![
            "live_request_summary",
            "normalized_event",
            "policy_decision",
            "approval_request",
            "mode_status",
            "coverage_gap",
            "realized_enforcement",
            "redaction_status",
        ];

        debug_assert!(
            policy
                .decision_fields
                .iter()
                .all(|field| input_fields.contains(field))
        );

        Self {
            modes: modes.clone(),
            input_fields: input_fields.clone(),
            record_fields: record_fields.clone(),
            responsibilities: vec![
                "append live preview, enforce-preview, or unsupported audit records without replaying proxy capture, session correlation, semantic conversion, or policy evaluation",
                "record the exact realized interception status, coverage gap, and approval linkage so operators can tell modeled intent from real runtime effect",
                "preserve correlation ids and redaction-safe live request summaries for later control-plane reconciliation",
                "stay append-only and avoid becoming the owner of approval queue state, policy decisions, or provider-specific taxonomy",
            ],
            stages: vec!["reflect", "annotate_mode", "append", "publish"],
            handoff: AuditBoundary {
                modes,
                input_fields,
                record_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> AuditBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "modes={} record_fields={} stages={}",
            self.modes.join(","),
            self.record_fields.join(","),
            self.stages.join("->")
        )
    }
}
