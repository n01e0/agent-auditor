use agenta_core::{ApprovalRequest, EventEnvelope, PolicyDecision};

use super::contract::{
    AuditBoundary, DecisionBoundary, EnforcementDirective, EnforcementError, EnforcementOutcome,
    EnforcementScope,
};

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

    pub fn apply(
        &self,
        scope: EnforcementScope,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        request: Option<&ApprovalRequest>,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        if !self.directives.contains(&EnforcementDirective::Hold) {
            return Err(EnforcementError::UnsupportedDirective {
                stage: "hold",
                directive: EnforcementDirective::Hold,
                scope,
                event_id: event.event_id.clone(),
            });
        }

        let request = request.ok_or_else(|| EnforcementError::MissingApprovalRequest {
            event_id: event.event_id.clone(),
        })?;

        Ok(EnforcementOutcome::held_for_approval(
            scope, event, decision, request,
        ))
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
        Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest,
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EventEnvelope, EventType,
        PolicyDecision, PolicyDecisionKind, ResultInfo, ResultStatus, SessionRef, Severity,
        SourceInfo,
    };

    use super::HoldPlan;
    use crate::poc::enforcement::{
        contract::{EnforcementDirective, EnforcementScope, EnforcementStatus},
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

    #[test]
    fn hold_plan_turns_require_approval_into_a_held_outcome() {
        let plan = HoldPlan::from_decision_boundary(DecisionPlan::default().handoff());
        let event = fixture_event();
        let decision = PolicyDecision {
            decision: PolicyDecisionKind::RequireApproval,
            rule_id: Some("fs.sensitive.read".to_owned()),
            severity: Some(Severity::High),
            reason: Some("sensitive path access requires approval".to_owned()),
            approval: None,
            tags: vec!["filesystem".to_owned(), "approval".to_owned()],
        };
        let request = fixture_request();

        let outcome = plan
            .apply(
                EnforcementScope::Filesystem,
                &event,
                &decision,
                Some(&request),
            )
            .expect("hold plan should apply with approval request");

        assert_eq!(outcome.directive, EnforcementDirective::Hold);
        assert_eq!(outcome.status, EnforcementStatus::Held);
        assert_eq!(outcome.approval_id.as_deref(), Some("apr_evt_fs_hold"));
        assert_eq!(outcome.expires_at, request.expires_at);
        assert_eq!(
            outcome.status_reason,
            "sensitive path access requires approval"
        );
    }

    fn fixture_event() -> EventEnvelope {
        EventEnvelope::new(
            "evt_fs_hold",
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
                target: Some("/home/agent/.ssh/id_ed25519".to_owned()),
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
                pid: Some(4242),
                ppid: None,
            },
        )
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_evt_fs_hold".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(30)),
            session_id: "sess_bootstrap_hostd".to_owned(),
            event_id: Some("evt_fs_hold".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Filesystem,
                action_verb: "read".to_owned(),
                target: Some("/home/agent/.ssh/id_ed25519".to_owned()),
                summary: Some("sensitive path access requires approval".to_owned()),
                attributes: Default::default(),
            },
            policy: ApprovalPolicy {
                rule_id: "fs.sensitive.read".to_owned(),
                severity: Some(Severity::High),
                reason: Some("sensitive path access requires approval".to_owned()),
                scope: None,
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            requester_context: Some(agenta_core::RequesterContext {
                agent_reason: Some("sensitive path access requires approval".to_owned()),
                human_request: None,
            }),
            decision: None,
            enforcement: None,
        }
    }
}
