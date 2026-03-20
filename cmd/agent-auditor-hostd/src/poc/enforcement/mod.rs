pub mod audit;
pub mod contract;
pub mod decision;
pub mod deny;
pub mod hold;

use self::{audit::AuditPlan, decision::DecisionPlan, deny::DenyPlan, hold::HoldPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPocPlan {
    pub decision: DecisionPlan,
    pub hold: HoldPlan,
    pub deny: DenyPlan,
    pub audit: AuditPlan,
}

impl EnforcementPocPlan {
    pub fn bootstrap() -> Self {
        let decision = DecisionPlan::default();
        let hold = HoldPlan::from_decision_boundary(decision.handoff());
        let deny = DenyPlan::from_decision_boundary(decision.handoff());
        let audit = AuditPlan::from_execution_boundaries(&[hold.handoff(), deny.handoff()]);

        Self {
            decision,
            hold,
            deny,
            audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{ActionClass, PolicyDecisionKind, ResultStatus};

    use super::EnforcementPocPlan;
    use crate::poc::enforcement::contract::{EnforcementDirective, EnforcementScope};

    #[test]
    fn bootstrap_plan_keeps_decision_hold_deny_and_audit_responsibilities_separate() {
        let plan = EnforcementPocPlan::bootstrap();

        assert!(
            plan.decision
                .responsibilities
                .iter()
                .any(|item| item.contains("exact policy decision output"))
        );
        assert!(
            plan.decision
                .responsibilities
                .iter()
                .all(|item| !item.contains("durable audit"))
        );
        assert!(
            plan.hold
                .responsibilities
                .iter()
                .any(|item| item.contains("approval-required pause"))
        );
        assert!(
            plan.hold
                .responsibilities
                .iter()
                .all(|item| !item.contains("technical block"))
        );
        assert!(
            plan.deny
                .responsibilities
                .iter()
                .any(|item| item.contains("technical block path"))
        );
        assert!(
            plan.deny
                .responsibilities
                .iter()
                .all(|item| !item.contains("approval waits"))
        );
        assert!(
            plan.audit
                .responsibilities
                .iter()
                .any(|item| item.contains("durable audit path"))
        );
        assert!(
            plan.audit
                .responsibilities
                .iter()
                .all(|item| !item.contains("hold or deny mechanics"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_filesystem_and_process_scopes_across_stages() {
        let plan = EnforcementPocPlan::bootstrap();

        assert_eq!(
            plan.decision.scopes,
            vec![EnforcementScope::Filesystem, EnforcementScope::Process]
        );
        assert_eq!(plan.hold.scopes, plan.decision.scopes);
        assert_eq!(plan.deny.scopes, plan.decision.scopes);
        assert_eq!(plan.audit.scopes, plan.decision.scopes);
        assert_eq!(
            plan.decision
                .scopes
                .iter()
                .map(|scope| scope.action_class())
                .collect::<Vec<_>>(),
            vec![ActionClass::Filesystem, ActionClass::Process]
        );
    }

    #[test]
    fn decision_to_runtime_contract_maps_policy_outcomes_consistently() {
        let plan = EnforcementPocPlan::bootstrap();

        assert_eq!(
            plan.decision.directive_for(PolicyDecisionKind::Allow),
            EnforcementDirective::Allow
        );
        assert_eq!(
            plan.decision
                .directive_for(PolicyDecisionKind::RequireApproval),
            EnforcementDirective::Hold
        );
        assert_eq!(
            plan.decision.directive_for(PolicyDecisionKind::Deny),
            EnforcementDirective::Deny
        );
        assert_eq!(
            EnforcementDirective::Allow.result_status(),
            ResultStatus::Allowed
        );
        assert_eq!(
            EnforcementDirective::Hold.result_status(),
            ResultStatus::ApprovalRequired
        );
        assert_eq!(
            EnforcementDirective::Deny.result_status(),
            ResultStatus::Denied
        );
    }
}
