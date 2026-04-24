use agenta_core::{
    ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus, EventEnvelope,
    PolicyDecision, PolicyDecisionKind,
};
use agenta_policy::{
    apply_decision_to_event, apply_enforcement_to_approval_request, apply_enforcement_to_event,
};
use thiserror::Error;

use super::contract::{
    GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource, RecordBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(boundary: RecordBoundary) -> Self {
        Self {
            sources: boundary.sources,
            semantic_surfaces: boundary.semantic_surfaces,
            semantic_actions: boundary.semantic_actions,
            record_fields: boundary.record_fields,
            responsibilities: vec![
                "persist redaction-safe GitHub governance audit records",
                "persist approval requests created by approval-gated GitHub governance actions",
                "reflect held and denied GitHub outcomes into audit and approval records without re-evaluating policy",
                "fan out recorded artifacts to structured logs and later control-plane sinks",
                "avoid re-classifying GitHub actions, mutating docs-backed metadata, or re-evaluating policy while recording results",
            ],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            stages: vec!["persist", "publish"],
            redaction_contract: boundary.redaction_contract,
        }
    }

    pub fn reflect_allow(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Allow {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Allow,
                actual: decision.decision,
            });
        }

        Ok(apply_decision_to_event(event, decision))
    }

    pub fn reflect_hold(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: &ApprovalRequest,
    ) -> Result<(EventEnvelope, ApprovalRequest), RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::RequireApproval {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::RequireApproval,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: Some(approval_request.approval_id.clone()),
            expires_at: approval_request.expires_at,
        };

        Ok((
            apply_enforcement_to_event(&decision_applied, &enforcement),
            apply_enforcement_to_approval_request(approval_request, &enforcement),
        ))
    }

    pub fn reflect_deny(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Deny {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Deny,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Deny,
            status: EnforcementStatus::Denied,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: None,
            expires_at: None,
        };

        Ok(apply_enforcement_to_event(&decision_applied, &enforcement))
    }

    pub fn summary(&self) -> String {
        let sources = self
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let surfaces = self
            .semantic_surfaces
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} surfaces={} record_fields={} stages={} sinks={}",
            sources,
            surfaces,
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordReflectionError {
    #[error(
        "github record reflection expected `{expected:?}` for event `{event_id}`, got `{actual:?}`"
    )]
    UnexpectedDecision {
        event_id: String,
        expected: PolicyDecisionKind,
        actual: PolicyDecisionKind,
    },
}

#[cfg(test)]
mod tests {
    use agenta_core::{ApprovalStatus, PolicyDecisionKind, ResultStatus};
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };

    use super::{RecordPlan, RecordReflectionError};
    use crate::poc::github::{metadata::MetadataPlan, policy::PolicyPlan, taxonomy::TaxonomyPlan};

    #[test]
    fn record_plan_preserves_redaction_contract_and_storage_sinks() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        assert_eq!(plan.stages, vec!["persist", "publish"]);
        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
        assert_eq!(
            plan.redaction_contract,
            "raw GitHub request or response payloads, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, and secret values must not cross the GitHub governance seams"
        );
    }

    #[test]
    fn record_plan_reflects_allow_hold_and_deny_without_re_evaluating_policy() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());
        let session = fixture_session();

        let allow_observed = policy.normalize_classified_action(
            &taxonomy
                .classify_signal(
                    &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
                )
                .expect("rerun preview should classify"),
            &session,
        );
        let allow_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&allow_observed))
            .expect("allow decision should evaluate");
        let allow_enriched = plan
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");

        let hold_observed = policy.normalize_classified_action(
            &taxonomy
                .classify_signal(
                    &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility(),
                )
                .expect("visibility preview should classify"),
            &session,
        );
        let hold_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&hold_observed))
            .expect("hold decision should evaluate");
        let hold_request = approval_request_from_decision(
            &agenta_policy::apply_decision_to_event(&hold_observed, &hold_decision),
            &hold_decision,
        )
        .expect("hold decision should yield approval request");
        let (hold_enriched, hold_request) = plan
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");

        let deny_observed = policy.normalize_classified_action(
            &taxonomy
                .classify_signal(
                    &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
                )
                .expect("secret write preview should classify"),
            &session,
        );
        let deny_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(&deny_observed))
            .expect("deny decision should evaluate");
        let deny_enriched = plan
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");

        assert_eq!(allow_enriched.result.status, ResultStatus::Allowed);
        assert!(allow_enriched.enforcement.is_none());
        assert_eq!(hold_enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            hold_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(hold_request.status, ApprovalStatus::Pending);
        assert_eq!(
            hold_request.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(deny_enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            deny_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );
    }

    #[test]
    fn record_plan_rejects_mismatched_decision_kinds() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());
        let session = fixture_session();
        let observed = policy.normalize_classified_action(
            &taxonomy
                .classify_signal(
                    &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
                )
                .expect("rerun preview should classify"),
            &session,
        );
        let deny_decision = agenta_core::PolicyDecision {
            decision: PolicyDecisionKind::Deny,
            rule_id: Some("github.actions.runs_rerun.denied".to_owned()),
            severity: Some(agenta_core::Severity::High),
            reason: Some("workflow rerun denied for mismatch test".to_owned()),
            explanation: None,
            rationale: None,
            reviewer_hint: None,
            approval: None,
            tags: vec!["github".to_owned(), "actions".to_owned(), "deny".to_owned()],
        };

        let approval_request = agenta_core::ApprovalRequest {
            approval_id: "apr_mismatch_github_hold".to_owned(),
            status: agenta_core::ApprovalStatus::Pending,
            requested_at: observed.timestamp,
            resolved_at: None,
            expires_at: None,
            session_id: observed.session.session_id.clone(),
            event_id: Some(observed.event_id.clone()),
            request: agenta_core::ApprovalRequestAction {
                action_class: observed.action.class,
                action_verb: observed
                    .action
                    .verb
                    .clone()
                    .expect("normalized GitHub event should have action verb"),
                target: observed.action.target.clone(),
                summary: deny_decision.reason.clone(),
                attributes: observed.action.attributes.clone(),
            },
            policy: agenta_core::ApprovalPolicy {
                rule_id: "github.mismatch.requires_approval".to_owned(),
                severity: Some(agenta_core::Severity::High),
                reason: deny_decision.reason.clone(),
                scope: Some(agenta_core::ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            presentation: None,
            requester_context: None,
            decision: None,
            enforcement: None,
            integrity: None,
        };

        let error = plan
            .reflect_hold(&observed, &deny_decision, &approval_request)
            .expect_err("hold reflection should reject deny decisions");

        assert_eq!(
            error,
            RecordReflectionError::UnexpectedDecision {
                event_id: observed.event_id.clone(),
                expected: PolicyDecisionKind::RequireApproval,
                actual: PolicyDecisionKind::Deny,
            }
        );
    }

    #[test]
    fn record_summary_mentions_record_fields_and_sinks() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let summary = RecordPlan::from_policy_boundary(policy.handoff()).summary();

        assert!(summary.contains(
            "record_fields=normalized_event,policy_decision,approval_request,redaction_status"
        ));
        assert!(summary.contains("sinks=structured_log,audit_store,approval_store"));
    }

    pub(super) fn fixture_session() -> agenta_core::SessionRecord {
        let mut session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_github_record");
        session.workspace = Some(agenta_core::SessionWorkspace {
            workspace_id: Some("ws_github_record".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
