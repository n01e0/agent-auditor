use super::contract::{
    GITHUB_GOVERNANCE_REDACTION_RULE, GitHubGovernanceActionKind, GitHubSemanticSurface,
    GitHubSignalSource, TaxonomyBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyPlan {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub input_fields: Vec<&'static str>,
    pub taxonomy_fields: Vec<&'static str>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: TaxonomyBoundary,
}

impl Default for TaxonomyPlan {
    fn default() -> Self {
        Self {
            sources: vec![
                GitHubSignalSource::ApiObservation,
                GitHubSignalSource::BrowserObservation,
            ],
            semantic_surfaces: vec![
                GitHubSemanticSurface::GitHub,
                GitHubSemanticSurface::GitHubRepos,
                GitHubSemanticSurface::GitHubBranches,
                GitHubSemanticSurface::GitHubActions,
                GitHubSemanticSurface::GitHubPulls,
            ],
            input_fields: vec![
                "source_kind",
                "transport",
                "authority_hint",
                "method_hint",
                "route_template_hint",
                "path_hint",
                "target_hint",
                "provider_hint",
                "classifier_labels",
                "classifier_reasons",
            ],
            taxonomy_fields: vec![
                "semantic_surface",
                "provider_id",
                "action_key",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ],
            semantic_actions: vec![
                GitHubGovernanceActionKind::ReposUpdateVisibility,
                GitHubGovernanceActionKind::BranchesUpdateProtection,
                GitHubGovernanceActionKind::ActionsWorkflowDispatch,
                GitHubGovernanceActionKind::ActionsRunsRerun,
                GitHubGovernanceActionKind::PullsMerge,
                GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate,
            ],
            responsibilities: vec![
                "accept GitHub API- and browser-origin governance hints after upstream session attribution already exists",
                "classify GitHub governance observations into semantic action candidates without retaining bodies, diff hunks, workflow YAML, or secret values",
                "attach provider_id plus action_key, target hints, and classifier-owned rationale without joining docs-backed metadata",
                "handoff redaction-safe GitHub governance candidates downstream without normalizing agenta-core events or deciding policy outcomes",
            ],
            stages: vec!["ingest", "match", "label", "handoff"],
            handoff: TaxonomyBoundary {
                sources: vec![
                    GitHubSignalSource::ApiObservation,
                    GitHubSignalSource::BrowserObservation,
                ],
                semantic_surfaces: vec![
                    GitHubSemanticSurface::GitHub,
                    GitHubSemanticSurface::GitHubRepos,
                    GitHubSemanticSurface::GitHubBranches,
                    GitHubSemanticSurface::GitHubActions,
                    GitHubSemanticSurface::GitHubPulls,
                ],
                taxonomy_fields: vec![
                    "semantic_surface",
                    "provider_id",
                    "action_key",
                    "target_hint",
                    "classifier_labels",
                    "classifier_reasons",
                    "content_retained",
                ],
                redaction_contract: GITHUB_GOVERNANCE_REDACTION_RULE,
            },
        }
    }
}

impl TaxonomyPlan {
    pub fn handoff(&self) -> TaxonomyBoundary {
        self.handoff.clone()
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
        let actions = self
            .semantic_actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} surfaces={} input_fields={} semantic_actions={} stages={}",
            sources,
            surfaces,
            self.input_fields.join(","),
            actions,
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::TaxonomyPlan;
    use crate::poc::github::contract::{
        GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource,
    };

    #[test]
    fn taxonomy_plan_exposes_high_risk_github_candidates_without_policy_or_record_logic() {
        let plan = TaxonomyPlan::default();

        assert_eq!(
            plan.sources,
            vec![
                GitHubSignalSource::ApiObservation,
                GitHubSignalSource::BrowserObservation,
            ]
        );
        assert_eq!(
            plan.semantic_surfaces,
            vec![
                GitHubSemanticSurface::GitHub,
                GitHubSemanticSurface::GitHubRepos,
                GitHubSemanticSurface::GitHubBranches,
                GitHubSemanticSurface::GitHubActions,
                GitHubSemanticSurface::GitHubPulls,
            ]
        );
        assert_eq!(
            plan.semantic_actions,
            vec![
                GitHubGovernanceActionKind::ReposUpdateVisibility,
                GitHubGovernanceActionKind::BranchesUpdateProtection,
                GitHubGovernanceActionKind::ActionsWorkflowDispatch,
                GitHubGovernanceActionKind::ActionsRunsRerun,
                GitHubGovernanceActionKind::PullsMerge,
                GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate,
            ]
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("audit"))
        );
    }

    #[test]
    fn taxonomy_summary_mentions_actions_and_stage_flow() {
        let summary = TaxonomyPlan::default().summary();

        assert!(summary.contains("semantic_actions=repos.update_visibility"));
        assert!(summary.contains("actions.workflow_dispatch"));
        assert!(summary.contains("stages=ingest->match->label->handoff"));
    }
}
