use super::contract::{GenericRestContractBoundary, PolicyBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: PolicyBoundary,
}

impl PolicyPlan {
    pub fn from_contract_boundary(contract: GenericRestContractBoundary) -> Self {
        Self {
            providers: contract.providers.clone(),
            input_fields: contract.contract_fields.clone(),
            decision_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "bridge the generic REST / OAuth governance contract into agenta-policy without re-running provider-specific taxonomy",
                "evaluate provider-neutral method, host, path template, query class, scope labels, side effect, and privilege class descriptors",
                "project allow, deny, and require_approval outcomes plus approval-request candidates while carrying redaction-safe provider lineage forward",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: PolicyBoundary {
                providers: contract.providers,
                input_fields: contract.contract_fields,
                decision_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: contract.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> PolicyBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} input_fields={} decision_fields={} stages={}",
            self.providers.join(","),
            self.input_fields.join(","),
            self.decision_fields.join(","),
            self.stages.join("->")
        )
    }
}
