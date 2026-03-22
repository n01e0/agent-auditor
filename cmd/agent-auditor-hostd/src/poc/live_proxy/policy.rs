use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, PolicyBoundary, SemanticConversionBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: PolicyBoundary,
}

impl PolicyPlan {
    pub fn from_semantic_conversion_boundary(boundary: SemanticConversionBoundary) -> Self {
        let consumers = boundary.consumers.clone();
        let input_fields = boundary.semantic_fields;
        let decision_fields = vec![
            "normalized_event",
            "policy_decision",
            "coverage_posture",
            "mode_status",
            "approval_eligibility",
        ];

        Self {
            consumers: consumers.clone(),
            input_fields: input_fields.clone(),
            decision_fields: decision_fields.clone(),
            responsibilities: vec![
                "bridge generic live semantic envelopes into agenta-policy without re-running proxy capture or session ownership logic",
                "evaluate live requests against existing generic REST, GWS, GitHub, and messaging policy surfaces using only redaction-safe semantic fields",
                "project live coverage posture and mode status alongside allow, deny, or require_approval decisions so downstream code can tell preview from validated enforcement",
                "handoff policy outputs to approval and audit stages without owning request pause/resume mechanics or durable record persistence",
            ],
            stages: vec!["normalize", "policy_input", "evaluate", "handoff"],
            handoff: PolicyBoundary {
                consumers,
                input_fields,
                decision_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> PolicyBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "consumers={} decision_fields={} stages={}",
            self.consumers.join(","),
            self.decision_fields.join(","),
            self.stages.join("->")
        )
    }
}
