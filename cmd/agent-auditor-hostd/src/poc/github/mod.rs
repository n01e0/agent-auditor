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
}
