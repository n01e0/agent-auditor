use agenta_core::PolicyDecisionKind;

use super::contract::{DecisionBoundary, EnforcementDirective, EnforcementScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPlan {
    pub scopes: Vec<EnforcementScope>,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: DecisionBoundary,
}

impl Default for DecisionPlan {
    fn default() -> Self {
        let boundary = DecisionBoundary::foundation_poc();

        Self {
            scopes: boundary.scopes.clone(),
            input_fields: boundary.input_fields.clone(),
            responsibilities: vec![
                "accept normalized action candidates plus the exact policy decision output without re-evaluating policy",
                "route allow / require_approval / deny outcomes into explicit enforcement directives for filesystem and process scopes",
                "surface coverage gaps and status reasons before any hold or deny implementation mutates runtime state",
                "handoff directive context to hold, deny, and audit stages without writing durable records",
            ],
            stages: vec!["accept", "route", "handoff"],
            handoff: boundary,
        }
    }
}

impl DecisionPlan {
    pub fn handoff(&self) -> DecisionBoundary {
        self.handoff.clone()
    }

    pub fn directive_for(&self, decision: PolicyDecisionKind) -> EnforcementDirective {
        EnforcementDirective::from_policy_decision(decision)
    }

    pub fn summary(&self) -> String {
        let scopes = self
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "scopes={} input_fields={} stages={} directive_fields={}",
            scopes,
            self.input_fields.join(","),
            self.stages.join("->"),
            self.handoff.directive_fields.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::PolicyDecisionKind;

    use super::DecisionPlan;
    use crate::poc::enforcement::contract::{EnforcementDirective, EnforcementScope};

    #[test]
    fn decision_plan_covers_filesystem_and_process_inputs() {
        let plan = DecisionPlan::default();

        assert_eq!(
            plan.scopes,
            vec![EnforcementScope::Filesystem, EnforcementScope::Process]
        );
        assert_eq!(
            plan.input_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "coverage_context",
                "enforcement_capability",
            ]
        );
        assert_eq!(plan.stages, vec!["accept", "route", "handoff"]);
    }

    #[test]
    fn decision_plan_maps_policy_outcomes_into_enforcement_directives() {
        let plan = DecisionPlan::default();

        assert_eq!(
            plan.directive_for(PolicyDecisionKind::Allow),
            EnforcementDirective::Allow
        );
        assert_eq!(
            plan.directive_for(PolicyDecisionKind::RequireApproval),
            EnforcementDirective::Hold
        );
        assert_eq!(
            plan.directive_for(PolicyDecisionKind::Deny),
            EnforcementDirective::Deny
        );
    }
}
