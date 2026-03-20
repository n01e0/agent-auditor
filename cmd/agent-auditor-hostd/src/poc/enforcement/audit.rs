use super::contract::{AuditBoundary, EnforcementScope, EnforcementStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPlan {
    pub scopes: Vec<EnforcementScope>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub statuses: Vec<EnforcementStatus>,
    pub stages: Vec<&'static str>,
}

impl AuditPlan {
    pub fn from_execution_boundaries(boundaries: &[AuditBoundary]) -> Self {
        let first = boundaries
            .first()
            .expect("audit plan requires at least one execution boundary");

        Self {
            scopes: first.scopes.clone(),
            record_fields: union_fields(boundaries, |boundary| &boundary.record_fields),
            responsibilities: vec![
                "append the exact policy decision plus the realized enforcement outcome to the durable audit path",
                "record whether a directive was held, denied, allowed, or downgraded because coverage was missing",
                "fan out enforcement records to logs and later control-plane sinks without re-running runtime enforcement steps",
                "keep decision-time and runtime-time status aligned so operators can compare what should have happened with what did happen",
            ],
            sinks: union_fields(boundaries, |boundary| &boundary.sinks),
            statuses: vec![
                EnforcementStatus::Allowed,
                EnforcementStatus::Held,
                EnforcementStatus::Denied,
                EnforcementStatus::ObserveOnlyFallback,
            ],
            stages: vec!["append", "publish"],
        }
    }

    pub fn summary(&self) -> String {
        let scopes = self
            .scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let statuses = self
            .statuses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "scopes={} record_fields={} stages={} sinks={} statuses={}",
            scopes,
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(","),
            statuses,
        )
    }
}

fn union_fields(
    boundaries: &[AuditBoundary],
    project: impl Fn(&AuditBoundary) -> &[&'static str],
) -> Vec<&'static str> {
    let mut fields = Vec::new();

    for boundary in boundaries {
        for field in project(boundary) {
            if !fields.contains(field) {
                fields.push(*field);
            }
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::AuditPlan;
    use crate::poc::enforcement::{decision::DecisionPlan, deny::DenyPlan, hold::HoldPlan};

    #[test]
    fn audit_plan_unions_hold_and_deny_handoffs() {
        let decision = DecisionPlan::default();
        let hold = HoldPlan::from_decision_boundary(decision.handoff());
        let deny = DenyPlan::from_decision_boundary(decision.handoff());
        let audit = AuditPlan::from_execution_boundaries(&[hold.handoff(), deny.handoff()]);

        assert_eq!(
            audit.record_fields,
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
            audit.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
    }

    #[test]
    fn audit_plan_tracks_runtime_status_variants() {
        let decision = DecisionPlan::default();
        let hold = HoldPlan::from_decision_boundary(decision.handoff());
        let deny = DenyPlan::from_decision_boundary(decision.handoff());
        let audit = AuditPlan::from_execution_boundaries(&[hold.handoff(), deny.handoff()]);

        assert_eq!(
            audit
                .statuses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["allowed", "held", "denied", "observe_only_fallback"]
        );
        assert_eq!(audit.stages, vec!["append", "publish"]);
    }
}
