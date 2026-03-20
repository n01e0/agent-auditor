use super::contract::{AuditBoundary, DecisionBoundary, EnforcementDirective, EnforcementScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPlan {
    pub scopes: Vec<EnforcementScope>,
    pub directive_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub directives: Vec<EnforcementDirective>,
    handoff: AuditBoundary,
}

impl DenyPlan {
    pub fn from_decision_boundary(boundary: DecisionBoundary) -> Self {
        Self {
            scopes: boundary.scopes.clone(),
            directive_fields: boundary.directive_fields,
            responsibilities: vec![
                "own the technical block path for deny directives after policy routing has already happened",
                "report whether the runtime applied a hard deny or had to fall back because enforcement coverage was missing",
                "preserve the exact policy decision and runtime status reason for downstream audit",
                "handoff deny outcomes to audit without taking ownership of approval lifecycle or durable records",
            ],
            stages: vec!["attempt_block", "report_outcome"],
            directives: vec![EnforcementDirective::Deny],
            handoff: AuditBoundary {
                scopes: boundary.scopes,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "directive",
                    "enforcement_status",
                    "status_reason",
                    "coverage_gap",
                ],
                sinks: vec!["structured_log", "audit_store"],
            },
        }
    }

    pub fn handoff(&self) -> AuditBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        let scopes = self
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let directives = self
            .directives
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "scopes={} directive_fields={} stages={} directives={}",
            scopes,
            self.directive_fields.join(","),
            self.stages.join("->"),
            directives,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::DenyPlan;
    use crate::poc::enforcement::{
        contract::{EnforcementDirective, EnforcementScope},
        decision::DecisionPlan,
    };

    #[test]
    fn deny_plan_only_accepts_deny_directives() {
        let plan = DenyPlan::from_decision_boundary(DecisionPlan::default().handoff());

        assert_eq!(plan.directives, vec![EnforcementDirective::Deny]);
        assert_eq!(
            plan.scopes,
            vec![EnforcementScope::Filesystem, EnforcementScope::Process]
        );
        assert_eq!(plan.stages, vec!["attempt_block", "report_outcome"]);
    }

    #[test]
    fn deny_plan_handoff_keeps_audit_fields_smaller_than_hold() {
        let plan = DenyPlan::from_decision_boundary(DecisionPlan::default().handoff());
        let handoff = plan.handoff();

        assert_eq!(
            handoff.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "directive",
                "enforcement_status",
                "status_reason",
                "coverage_gap",
            ]
        );
        assert_eq!(handoff.sinks, vec!["structured_log", "audit_store"]);
    }
}
