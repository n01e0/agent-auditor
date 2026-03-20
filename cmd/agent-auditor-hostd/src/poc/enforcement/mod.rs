pub mod audit;
pub mod contract;
pub mod decision;
pub mod deny;
pub mod hold;

use agenta_core::{ApprovalRequest, EventEnvelope, PolicyDecision};

use self::{audit::AuditPlan, decision::DecisionPlan, deny::DenyPlan, hold::HoldPlan};
use crate::poc::enforcement::contract::{
    EnforcementDirective, EnforcementError, EnforcementOutcome, EnforcementScope,
};

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

    pub fn preview_filesystem_outcome(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: Option<&ApprovalRequest>,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        self.preview_outcome(
            EnforcementScope::Filesystem,
            event,
            decision,
            approval_request,
        )
    }

    pub fn preview_process_outcome(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: Option<&ApprovalRequest>,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        self.preview_outcome(EnforcementScope::Process, event, decision, approval_request)
    }

    fn preview_outcome(
        &self,
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: Option<&ApprovalRequest>,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        match self.decision.directive_for(decision.decision) {
            EnforcementDirective::Allow => Ok(self.decision.allow_outcome(scope, event, decision)),
            EnforcementDirective::Hold => self.hold.apply(scope, event, decision, approval_request),
            EnforcementDirective::Deny => self.deny.apply(scope, event, decision),
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, EventEnvelope, PolicyDecisionKind, ResultStatus, SessionRecord,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };

    use super::EnforcementPocPlan;
    use crate::poc::{
        enforcement::contract::{EnforcementDirective, EnforcementScope, EnforcementStatus},
        event_path::{EventPathPlan, ExecEvent},
        filesystem::FilesystemPocPlan,
    };

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

    #[test]
    fn filesystem_preview_path_holds_sensitive_reads_until_approval() {
        let plan = EnforcementPocPlan::bootstrap();
        let event = normalized_filesystem_event("/home/agent/.ssh/id_ed25519", "read");
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("filesystem rego should evaluate");
        let request = approval_request_from_decision(&event, &decision)
            .expect("sensitive read should create approval request");

        let outcome = plan
            .preview_filesystem_outcome(&event, &decision, Some(&request))
            .expect("filesystem preview should create hold outcome");

        assert_eq!(outcome.directive, EnforcementDirective::Hold);
        assert_eq!(outcome.status, EnforcementStatus::Held);
        assert_eq!(outcome.policy_decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            outcome.approval_id.as_deref(),
            Some("apr_poc_filesystem_access_4242_17_read")
        );
    }

    #[test]
    fn filesystem_preview_path_denies_sensitive_writes() {
        let plan = EnforcementPocPlan::bootstrap();
        let event = normalized_filesystem_event("/home/agent/.ssh/config", "write");
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("filesystem rego should evaluate");

        let outcome = plan
            .preview_filesystem_outcome(&event, &decision, None)
            .expect("filesystem preview should create deny outcome");

        assert_eq!(outcome.directive, EnforcementDirective::Deny);
        assert_eq!(outcome.status, EnforcementStatus::Denied);
        assert_eq!(outcome.policy_decision, PolicyDecisionKind::Deny);
        assert_eq!(outcome.status_reason, "sensitive path write is denied");
    }

    #[test]
    fn process_preview_path_holds_remote_shell_exec_until_approval() {
        let plan = EnforcementPocPlan::bootstrap();
        let event = normalized_process_event(4545, "ssh", "/usr/bin/ssh");
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .expect("process exec rego should evaluate");
        let request = approval_request_from_decision(&event, &decision)
            .expect("ssh exec should create approval request");

        let outcome = plan
            .preview_process_outcome(&event, &decision, Some(&request))
            .expect("process preview should create hold outcome");

        assert_eq!(outcome.directive, EnforcementDirective::Hold);
        assert_eq!(outcome.status, EnforcementStatus::Held);
        assert_eq!(outcome.policy_decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            outcome.approval_id.as_deref(),
            Some("apr_poc_process_exec_4545_1337")
        );
        assert_eq!(outcome.target.as_deref(), Some("/usr/bin/ssh"));
    }

    #[test]
    fn process_preview_path_denies_destructive_rm_exec() {
        let plan = EnforcementPocPlan::bootstrap();
        let event = normalized_process_event(4646, "rm", "/usr/bin/rm");
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .expect("process exec rego should evaluate");

        let outcome = plan
            .preview_process_outcome(&event, &decision, None)
            .expect("process preview should create deny outcome");

        assert_eq!(outcome.directive, EnforcementDirective::Deny);
        assert_eq!(outcome.status, EnforcementStatus::Denied);
        assert_eq!(outcome.policy_decision, PolicyDecisionKind::Deny);
        assert_eq!(outcome.status_reason, "destructive rm execution is denied");
        assert_eq!(outcome.target.as_deref(), Some("/usr/bin/rm"));
    }

    fn normalized_filesystem_event(path: &str, verb: &str) -> EventEnvelope {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = FilesystemPocPlan::bootstrap();
        let access = plan.classify.classify_access(4242, 17, verb, path);
        let observed = plan.emit.normalize_classified_access(&access, &session);
        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("filesystem rego should evaluate");

        agenta_policy::apply_decision_to_event(&observed, &decision)
    }

    fn normalized_process_event(pid: u32, command: &str, filename: &str) -> EventEnvelope {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = EventPathPlan::from_loader_boundary(
            crate::poc::contract::LoaderBoundary::exec_exit_ring_buffer(),
        );
        let observed = plan.normalize_exec_event(
            &ExecEvent {
                pid,
                ppid: 1337,
                uid: 1000,
                gid: 1000,
                command: command.to_owned(),
                filename: filename.to_owned(),
            },
            &session,
        );
        let decision = RegoPolicyEvaluator::process_exec_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("process exec rego should evaluate");

        agenta_policy::apply_decision_to_event(&observed, &decision)
    }
}
