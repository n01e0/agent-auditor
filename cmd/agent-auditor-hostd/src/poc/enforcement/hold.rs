use super::contract::{AuditBoundary, DecisionBoundary, EnforcementDirective, EnforcementScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldPlan {
    pub scopes: Vec<EnforcementScope>,
    pub directive_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub directives: Vec<EnforcementDirective>,
    handoff: AuditBoundary,
}

impl HoldPlan {
    pub fn from_decision_boundary(boundary: DecisionBoundary) -> Self {
        Self {
            scopes: boundary.scopes.clone(),
            directive_fields: boundary.directive_fields,
            responsibilities: vec![
                "own the approval-required pause between decision routing and action completion",
                "surface hold handles, timeout state, and resume-or-expire outcomes without re-evaluating policy",
                "preserve the exact policy decision and approval-request context for downstream audit",
                "handoff hold outcomes to audit without performing durable persistence itself",
            ],
            stages: vec!["queue", "await_decision", "release_or_expire"],
            directives: vec![EnforcementDirective::Hold],
            handoff: AuditBoundary {
                scopes: boundary.scopes,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "directive",
                    "enforcement_status",
                    "status_reason",
                    "coverage_gap",
                ],
                sinks: vec!["structured_log", "audit_store", "approval_store"],
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
    use super::HoldPlan;
    use crate::poc::enforcement::{
        contract::{EnforcementDirective, EnforcementScope},
        decision::DecisionPlan,
    };

    #[test]
    fn hold_plan_only_accepts_hold_directives() {
        let plan = HoldPlan::from_decision_boundary(DecisionPlan::default().handoff());

        assert_eq!(plan.directives, vec![EnforcementDirective::Hold]);
        assert_eq!(
            plan.scopes,
            vec![EnforcementScope::Filesystem, EnforcementScope::Process]
        );
        assert_eq!(
            plan.stages,
            vec!["queue", "await_decision", "release_or_expire"]
        );
    }

    #[test]
    fn hold_plan_handoff_prepares_audit_and_approval_records() {
        let plan = HoldPlan::from_decision_boundary(DecisionPlan::default().handoff());
        let handoff = plan.handoff();

        assert_eq!(
            handoff.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "directive",
                "enforcement_status",
                "status_reason",
                "coverage_gap",
            ]
        );
        assert_eq!(
            handoff.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
    }
}
