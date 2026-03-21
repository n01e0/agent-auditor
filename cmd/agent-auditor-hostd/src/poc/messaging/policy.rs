use super::contract::{MessagingContractBoundary, PolicyBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: PolicyBoundary,
}

impl PolicyPlan {
    pub fn from_contract_boundary(contract: MessagingContractBoundary) -> Self {
        Self {
            providers: contract.providers.clone(),
            action_families: contract.action_families.clone(),
            input_fields: contract.contract_fields.clone(),
            decision_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "bridge the messaging / collaboration contract into agenta-policy without re-running provider-specific route heuristics",
                "evaluate shared collaboration action families such as message.send, channel.invite, permission.update, and file.upload using redaction-safe collaboration hints and preserved lineage",
                "project allow, deny, and require_approval outcomes plus approval-request candidates while carrying the messaging redaction contract forward",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: PolicyBoundary {
                providers: contract.providers,
                action_families: contract.action_families,
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
            "providers={} action_families={} input_fields={} decision_fields={} stages={}",
            self.providers.join(","),
            self.action_families.join(","),
            self.input_fields.join(","),
            self.decision_fields.join(","),
            self.stages.join("->")
        )
    }
}
