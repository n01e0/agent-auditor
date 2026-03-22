use super::contract::{ApprovalBoundary, LIVE_PROXY_INTERCEPTION_REDACTION_RULE, PolicyBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPlan {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub approval_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ApprovalBoundary,
}

impl ApprovalPlan {
    pub fn from_policy_boundary(boundary: PolicyBoundary) -> Self {
        let modes = vec!["shadow", "enforce_preview", "unsupported"];
        let input_fields = boundary.decision_fields;
        let approval_fields = vec![
            "approval_request",
            "approval_hold_allowed",
            "hold_reason",
            "expiry_hint",
            "resume_token_hint",
            "wait_state",
        ];

        Self {
            modes: modes.clone(),
            input_fields: input_fields.clone(),
            approval_fields: approval_fields.clone(),
            responsibilities: vec![
                "decide whether a live require_approval result can be represented as a real hold, an enforce-preview hold, or an unsupported fallback for the intercepted request class",
                "materialize approval-request state and release or cancel handles without re-running policy evaluation or semantic conversion",
                "keep pause or resume feasibility separate from durable audit persistence so later reviewers can see what the runtime actually could hold",
                "handoff approval state for append-only audit reflection without owning the long-term operator UX or reconciliation loop",
            ],
            stages: vec![
                "eligibility",
                "hold_projection",
                "approval_request",
                "handoff",
            ],
            handoff: ApprovalBoundary {
                modes,
                input_fields,
                approval_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> ApprovalBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "modes={} approval_fields={} stages={}",
            self.modes.join(","),
            self.approval_fields.join(","),
            self.stages.join("->")
        )
    }
}
