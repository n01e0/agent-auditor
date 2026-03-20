use agenta_core::{EventEnvelope, PolicyDecision, PolicyDecisionKind};

use super::contract::{
    DecisionBoundary, EnforcementDirective, EnforcementOutcome, EnforcementScope,
};

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

    pub fn allow_outcome(
        &self,
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> EnforcementOutcome {
        EnforcementOutcome::from_allowed_event(scope, event, decision)
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
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, EventEnvelope, EventType, PolicyDecision,
        PolicyDecisionKind, ResultInfo, ResultStatus, SessionRef, Severity, SourceInfo,
    };

    use super::DecisionPlan;
    use crate::poc::enforcement::contract::{
        EnforcementDirective, EnforcementScope, EnforcementStatus,
    };

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

    #[test]
    fn decision_plan_can_finalize_allow_outcomes_without_runtime_stages() {
        let plan = DecisionPlan::default();
        let event = fixture_event();
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::Allow,
            rule_id: Some("default.allow".to_owned()),
            severity: Some(Severity::Low),
            reason: Some("no matching rule".to_owned()),
            approval: None,
            tags: vec![],
        };

        let outcome = plan.allow_outcome(EnforcementScope::Filesystem, &event, &decision);

        assert_eq!(outcome.event_id, "evt_fs_allow");
        assert_eq!(outcome.directive, EnforcementDirective::Allow);
        assert_eq!(outcome.status, EnforcementStatus::Allowed);
        assert_eq!(outcome.status_reason, "no matching rule");
        assert!(outcome.enforced);
        assert!(outcome.approval_id.is_none());
    }

    fn fixture_event() -> EventEnvelope {
        EventEnvelope::new(
            "evt_fs_allow",
            EventType::FilesystemAccess,
            SessionRef {
                session_id: "sess_bootstrap_hostd".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: None,
                environment: None,
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Filesystem,
                verb: Some("read".to_owned()),
                target: Some("/workspace/src/main.rs".to_owned()),
                attributes: Default::default(),
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd filesystem PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: agenta_core::CollectorKind::Fanotify,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4343),
                ppid: None,
            },
        )
    }
}
