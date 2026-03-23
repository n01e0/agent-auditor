use agenta_core::{EventEnvelope, PolicyDecision};

use super::contract::{
    AuditBoundary, DecisionBoundary, EnforcementDirective, EnforcementError, EnforcementOutcome,
    EnforcementScope,
};

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

    pub fn apply(
        &self,
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        if !self.directives.contains(&EnforcementDirective::Deny) {
            return Err(EnforcementError::UnsupportedDirective {
                stage: "deny",
                directive: EnforcementDirective::Deny,
                scope,
                event_id: event.event_id.clone(),
            });
        }

        Ok(EnforcementOutcome::denied(scope, event, decision))
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
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType,
        PolicyDecision, PolicyDecisionKind, ResultInfo, ResultStatus, SessionRef, Severity,
        SourceInfo,
    };

    use super::DenyPlan;
    use crate::poc::enforcement::{
        contract::{EnforcementDirective, EnforcementScope, EnforcementStatus},
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

    #[test]
    fn deny_plan_turns_sensitive_writes_into_denied_outcomes() {
        let plan = DenyPlan::from_decision_boundary(DecisionPlan::default().handoff());
        let event = fixture_event();
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::Deny,
            rule_id: Some("fs.sensitive.write".to_owned()),
            severity: Some(Severity::Critical),
            reason: Some("sensitive path write is denied".to_owned()),
            explanation: None,
            rationale: None,
            reviewer_hint: None,
            approval: None,
            tags: vec!["filesystem".to_owned(), "deny".to_owned()],
        };

        let outcome = plan
            .apply(EnforcementScope::Filesystem, &event, &decision)
            .expect("deny plan should apply to deny decisions");

        assert_eq!(outcome.directive, EnforcementDirective::Deny);
        assert_eq!(outcome.status, EnforcementStatus::Denied);
        assert_eq!(outcome.status_reason, "sensitive path write is denied");
        assert!(outcome.enforced);
        assert!(outcome.approval_id.is_none());
    }

    fn fixture_event() -> EventEnvelope {
        EventEnvelope::new(
            "evt_fs_deny",
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
                verb: Some("write".to_owned()),
                target: Some("/home/agent/.ssh/config".to_owned()),
                attributes: Default::default(),
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd filesystem PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Fanotify,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4444),
                ppid: None,
            },
        )
    }
}
