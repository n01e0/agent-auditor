pub mod contract;
pub mod metadata;
pub mod policy;
pub mod record;
pub mod taxonomy;

use self::{
    metadata::MetadataPlan, policy::PolicyPlan, record::RecordPlan, taxonomy::TaxonomyPlan,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubSemanticGovernancePocPlan {
    pub taxonomy: TaxonomyPlan,
    pub metadata: MetadataPlan,
    pub policy: PolicyPlan,
    pub record: RecordPlan,
}

impl GitHubSemanticGovernancePocPlan {
    pub fn bootstrap() -> Self {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let record = RecordPlan::from_policy_boundary(policy.handoff());

        Self {
            taxonomy,
            metadata,
            policy,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, ApprovalScope, ApprovalStatus, EventType, PolicyDecisionKind, ResultStatus,
        SessionRecord, SessionWorkspace, Severity,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
        approval_request_from_decision,
    };

    use super::GitHubSemanticGovernancePocPlan;
    use crate::poc::github::contract::{
        GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource,
    };

    #[test]
    fn bootstrap_plan_keeps_taxonomy_metadata_policy_and_record_separate() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();

        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("semantic action candidates"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("docs-backed GitHub method"))
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .all(|item| !item.contains("structured logs"))
        );
        assert!(
            plan.policy
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-policy"))
        );
        assert!(
            plan.policy
                .responsibilities
                .iter()
                .all(|item| !item.contains("structured logs"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("avoid re-classifying GitHub actions"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_github_boundary_labels_across_the_pipeline() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();

        assert_eq!(
            plan.taxonomy.sources,
            vec![
                GitHubSignalSource::ApiObservation,
                GitHubSignalSource::BrowserObservation,
            ]
        );
        assert_eq!(plan.taxonomy.sources, plan.policy.sources);
        assert_eq!(plan.policy.sources, plan.record.sources);
        assert_eq!(
            plan.taxonomy.semantic_surfaces,
            vec![
                GitHubSemanticSurface::GitHub,
                GitHubSemanticSurface::GitHubRepos,
                GitHubSemanticSurface::GitHubBranches,
                GitHubSemanticSurface::GitHubActions,
                GitHubSemanticSurface::GitHubPulls,
            ]
        );
        assert_eq!(
            plan.taxonomy.semantic_surfaces,
            plan.policy.semantic_surfaces
        );
        assert_eq!(plan.policy.semantic_surfaces, plan.record.semantic_surfaces);
        assert_eq!(
            plan.metadata.contract_fields,
            vec!["provider_id", "action_key"]
        );
        assert_eq!(
            plan.metadata.metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.record.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
    }

    #[test]
    fn bootstrap_plan_normalizes_preview_github_action_into_agenta_core() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let classified = plan
            .taxonomy
            .classify_signal(
                &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_pulls_merge(
                ),
            )
            .expect("preview pull merge should classify");
        let normalized = plan
            .policy
            .normalize_classified_action(&classified, &fixture_session());
        let provider_action = PolicyInput::from_event(&normalized)
            .provider_action
            .expect("normalized GitHub event should derive shared provider action");

        assert_eq!(normalized.event_type, EventType::GithubAction);
        assert_eq!(normalized.action.class, ActionClass::Github);
        assert_eq!(normalized.action.verb.as_deref(), Some("pulls.merge"));
        assert_eq!(
            normalized.action.target.as_deref(),
            Some("repos/n01e0/agent-auditor/pulls/69")
        );
        assert_eq!(provider_action.provider_id.to_string(), "github");
        assert_eq!(provider_action.action_key.to_string(), "pulls.merge");
    }

    #[test]
    fn bootstrap_plan_carries_initial_high_risk_github_actions_without_runtime_logic() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();

        assert_eq!(
            plan.taxonomy.semantic_actions,
            vec![
                GitHubGovernanceActionKind::ReposUpdateVisibility,
                GitHubGovernanceActionKind::BranchesUpdateProtection,
                GitHubGovernanceActionKind::ActionsWorkflowDispatch,
                GitHubGovernanceActionKind::ActionsRunsRerun,
                GitHubGovernanceActionKind::PullsMerge,
                GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate,
            ]
        );
        assert_eq!(
            plan.taxonomy.semantic_actions,
            plan.metadata.semantic_actions
        );
        assert_eq!(plan.metadata.semantic_actions, plan.policy.semantic_actions);
        assert_eq!(plan.policy.semantic_actions, plan.record.semantic_actions);
        assert_eq!(
            plan.record.redaction_contract,
            "raw GitHub request or response payloads, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, and secret values must not cross the GitHub governance seams"
        );
    }

    #[test]
    fn github_pipeline_can_require_approval_for_visibility_dispatch_and_merge() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let session = fixture_session();
        let previews = [
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_workflow_dispatch(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_pulls_merge(),
        ];
        let expected_rule_ids = [
            "github.repos.update_visibility.requires_approval",
            "github.actions.workflow_dispatch.requires_approval",
            "github.pulls.merge.requires_approval",
        ];

        for (preview, expected_rule_id) in previews.iter().zip(expected_rule_ids) {
            let classified = plan
                .taxonomy
                .classify_signal(preview)
                .expect("preview should classify");
            let normalized = plan
                .policy
                .normalize_classified_action(&classified, &session);
            let decision = RegoPolicyEvaluator::github_action_example()
                .evaluate(&PolicyInput::from_event(&normalized))
                .expect("github rego should evaluate");
            let enriched = apply_decision_to_event(&normalized, &decision);
            let approval_request = approval_request_from_decision(&enriched, &decision)
                .expect("require_approval should yield approval request");

            assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
            assert_eq!(decision.rule_id.as_deref(), Some(expected_rule_id));
            assert!(matches!(
                decision.severity,
                Some(Severity::High | Severity::Medium)
            ));
            assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
            assert_eq!(approval_request.status, ApprovalStatus::Pending);
            assert_eq!(
                approval_request.policy.scope,
                Some(ApprovalScope::SingleAction)
            );
            assert!(approval_request.policy.ttl_seconds.is_some());
            assert_eq!(
                approval_request.policy.reviewer_hint.as_deref(),
                Some("security-oncall")
            );
        }
    }

    #[test]
    fn github_pipeline_can_allow_workflow_reruns_and_deny_secret_writes() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let session = fixture_session();
        let rerun = plan
            .taxonomy
            .classify_signal(
                &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
            )
            .expect("rerun preview should classify");
        let secret_write = plan
            .taxonomy
            .classify_signal(
                &crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
            )
            .expect("secret write preview should classify");

        let rerun_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan.policy.normalize_classified_action(&rerun, &session),
            ))
            .expect("github rerun policy should evaluate");
        let secret_write_decision = RegoPolicyEvaluator::github_action_example()
            .evaluate(&PolicyInput::from_event(
                &plan
                    .policy
                    .normalize_classified_action(&secret_write, &session),
            ))
            .expect("github secret write policy should evaluate");

        assert_eq!(rerun_decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(
            rerun_decision.rule_id.as_deref(),
            Some("github.actions.runs_rerun.allow")
        );
        assert_eq!(rerun_decision.severity, Some(Severity::Low));
        assert_eq!(secret_write_decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            secret_write_decision.rule_id.as_deref(),
            Some("github.actions.secrets_create_or_update.denied")
        );
        assert_eq!(secret_write_decision.severity, Some(Severity::Critical));
    }

    #[test]
    fn github_all_supported_actions_round_trip_through_policy() {
        let plan = GitHubSemanticGovernancePocPlan::bootstrap();
        let session = fixture_session();
        let previews = [
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_branches_update_protection(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_workflow_dispatch(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_pulls_merge(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
        ];

        let decisions = previews
            .iter()
            .map(|preview| {
                plan.taxonomy
                    .classify_signal(preview)
                    .expect("preview should classify")
            })
            .map(|classified| {
                plan.policy
                    .normalize_classified_action(&classified, &session)
            })
            .map(|event| {
                RegoPolicyEvaluator::github_action_example()
                    .evaluate(&PolicyInput::from_event(&event))
                    .expect("github policy should evaluate")
                    .decision
            })
            .collect::<Vec<_>>();

        assert_eq!(
            decisions,
            vec![
                PolicyDecisionKind::RequireApproval,
                PolicyDecisionKind::RequireApproval,
                PolicyDecisionKind::RequireApproval,
                PolicyDecisionKind::Allow,
                PolicyDecisionKind::RequireApproval,
                PolicyDecisionKind::Deny,
            ]
        );
    }

    fn fixture_session() -> SessionRecord {
        let mut session = SessionRecord::placeholder("openclaw-main", "sess_github_mod");
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("ws_github_mod".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
