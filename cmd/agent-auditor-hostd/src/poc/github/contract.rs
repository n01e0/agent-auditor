use std::fmt;

use agenta_core::provider::{ActionKey, ProviderActionId, ProviderId, ProviderSemanticAction};

pub const GITHUB_GOVERNANCE_REDACTION_RULE: &str = "raw GitHub request or response payloads, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, and secret values must not cross the GitHub governance seams";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubSignalSource {
    ApiObservation,
    BrowserObservation,
}

impl fmt::Display for GitHubSignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ApiObservation => "api_observation",
            Self::BrowserObservation => "browser_observation",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubSemanticSurface {
    GitHub,
    GitHubRepos,
    GitHubBranches,
    GitHubActions,
    GitHubPulls,
}

impl GitHubSemanticSurface {
    pub fn label(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitHubRepos => "github.repos",
            Self::GitHubBranches => "github.branches",
            Self::GitHubActions => "github.actions",
            Self::GitHubPulls => "github.pulls",
        }
    }
}

impl fmt::Display for GitHubSemanticSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubGovernanceActionKind {
    ReposUpdateVisibility,
    BranchesUpdateProtection,
    ActionsWorkflowDispatch,
    ActionsRunsRerun,
    PullsMerge,
    ActionsSecretsCreateOrUpdate,
}

impl GitHubGovernanceActionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ReposUpdateVisibility => "repos.update_visibility",
            Self::BranchesUpdateProtection => "branches.update_protection",
            Self::ActionsWorkflowDispatch => "actions.workflow_dispatch",
            Self::ActionsRunsRerun => "actions.runs.rerun",
            Self::PullsMerge => "pulls.merge",
            Self::ActionsSecretsCreateOrUpdate => "actions.secrets.create_or_update",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "repos.update_visibility" => Some(Self::ReposUpdateVisibility),
            "branches.update_protection" => Some(Self::BranchesUpdateProtection),
            "actions.workflow_dispatch" => Some(Self::ActionsWorkflowDispatch),
            "actions.runs.rerun" => Some(Self::ActionsRunsRerun),
            "pulls.merge" => Some(Self::PullsMerge),
            "actions.secrets.create_or_update" => Some(Self::ActionsSecretsCreateOrUpdate),
            _ => None,
        }
    }

    pub fn surface(self) -> GitHubSemanticSurface {
        match self {
            Self::ReposUpdateVisibility => GitHubSemanticSurface::GitHubRepos,
            Self::BranchesUpdateProtection => GitHubSemanticSurface::GitHubBranches,
            Self::ActionsWorkflowDispatch
            | Self::ActionsRunsRerun
            | Self::ActionsSecretsCreateOrUpdate => GitHubSemanticSurface::GitHubActions,
            Self::PullsMerge => GitHubSemanticSurface::GitHubPulls,
        }
    }

    pub fn provider_id(self) -> ProviderId {
        ProviderId::github()
    }

    pub fn action_key(self) -> ActionKey {
        ActionKey::new(self.label())
            .expect("GitHub governance action labels must be valid provider action keys")
    }

    pub fn provider_action_id(self) -> ProviderActionId {
        ProviderActionId::new(self.provider_id(), self.action_key())
    }

    pub fn provider_semantic_action(
        self,
        target_hint: impl Into<String>,
    ) -> ProviderSemanticAction {
        ProviderSemanticAction::from_id(self.provider_action_id(), target_hint)
    }

    pub fn from_provider_action_id(action: &ProviderActionId) -> Option<Self> {
        if action.provider_id != ProviderId::github() {
            return None;
        }

        Self::from_label(action.action_key.as_str())
    }

    pub fn classifier_labels(self) -> Vec<&'static str> {
        vec![self.surface().label(), self.label()]
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ReposUpdateVisibility => {
                "PATCH repository settings path plus a visibility target hint maps to repository visibility changes"
            }
            Self::BranchesUpdateProtection => {
                "branch protection path maps to branch protection updates"
            }
            Self::ActionsWorkflowDispatch => {
                "workflow dispatch path maps to Actions workflow dispatch"
            }
            Self::ActionsRunsRerun => "workflow rerun path maps to Actions rerun",
            Self::PullsMerge => "pull merge path maps to pull request merge",
            Self::ActionsSecretsCreateOrUpdate => {
                "Actions secrets path maps to repository Actions secret writes"
            }
        }
    }
}

impl fmt::Display for GitHubGovernanceActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubGovernanceObservation {
    pub source: GitHubSignalSource,
    pub request_id: String,
    pub transport: String,
    pub authority_hint: Option<String>,
    pub method_hint: Option<String>,
    pub route_template_hint: Option<String>,
    pub path_hint: Option<String>,
    pub target_hint: Option<String>,
    pub semantic_surface_hint: GitHubSemanticSurface,
}

impl GitHubGovernanceObservation {
    pub fn preview_api_repos_update_visibility() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_repos_update_visibility_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("PATCH".to_owned()),
            route_template_hint: Some("/repos/{owner}/{repo}".to_owned()),
            path_hint: Some("/repos/n01e0/agent-auditor".to_owned()),
            target_hint: Some("repos/n01e0/agent-auditor/visibility".to_owned()),
            semantic_surface_hint: GitHubSemanticSurface::GitHubRepos,
        }
    }

    pub fn preview_api_branches_update_protection() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_branches_update_protection_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("PUT".to_owned()),
            route_template_hint: Some(
                "/repos/{owner}/{repo}/branches/{branch}/protection".to_owned(),
            ),
            path_hint: Some("/repos/n01e0/agent-auditor/branches/main/protection".to_owned()),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubBranches,
        }
    }

    pub fn preview_api_actions_workflow_dispatch() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_actions_workflow_dispatch_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("POST".to_owned()),
            route_template_hint: Some(
                "/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches".to_owned(),
            ),
            path_hint: Some(
                "/repos/n01e0/agent-auditor/actions/workflows/ci.yml/dispatches".to_owned(),
            ),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubActions,
        }
    }

    pub fn preview_api_actions_runs_rerun() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_actions_runs_rerun_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("POST".to_owned()),
            route_template_hint: Some(
                "/repos/{owner}/{repo}/actions/runs/{run_id}/rerun".to_owned(),
            ),
            path_hint: Some("/repos/n01e0/agent-auditor/actions/runs/123456/rerun".to_owned()),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubActions,
        }
    }

    pub fn preview_api_pulls_merge() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_pulls_merge_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("PUT".to_owned()),
            route_template_hint: Some("/repos/{owner}/{repo}/pulls/{pull_number}/merge".to_owned()),
            path_hint: Some("/repos/n01e0/agent-auditor/pulls/69/merge".to_owned()),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubPulls,
        }
    }

    pub fn preview_browser_pulls_merge() -> Self {
        Self {
            source: GitHubSignalSource::BrowserObservation,
            request_id: "req_github_browser_pulls_merge_preview".to_owned(),
            transport: "browser".to_owned(),
            authority_hint: Some("github.com".to_owned()),
            method_hint: Some("PUT".to_owned()),
            route_template_hint: Some("/repos/{owner}/{repo}/pulls/{pull_number}/merge".to_owned()),
            path_hint: None,
            target_hint: Some("repos/n01e0/agent-auditor/pulls/69".to_owned()),
            semantic_surface_hint: GitHubSemanticSurface::GitHubPulls,
        }
    }

    pub fn preview_api_actions_secrets_create_or_update() -> Self {
        Self {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_github_actions_secrets_create_or_update_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("PUT".to_owned()),
            route_template_hint: Some(
                "/repos/{owner}/{repo}/actions/secrets/{secret_name}".to_owned(),
            ),
            path_hint: Some("/repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN".to_owned()),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubActions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedGitHubGovernanceAction {
    pub source: GitHubSignalSource,
    pub request_id: String,
    pub transport: String,
    pub authority_hint: Option<String>,
    pub method_hint: Option<String>,
    pub route_template_hint: Option<String>,
    pub path_hint: Option<String>,
    pub semantic_surface: GitHubSemanticSurface,
    pub semantic_action: GitHubGovernanceActionKind,
    pub provider_action: ProviderSemanticAction,
    pub target_hint: String,
    pub classifier_labels: Vec<&'static str>,
    pub classifier_reasons: Vec<&'static str>,
    pub content_retained: bool,
}

impl ClassifiedGitHubGovernanceAction {
    pub fn provider_action_id(&self) -> ProviderActionId {
        self.provider_action.id()
    }

    pub fn log_line(&self) -> String {
        format!(
            "event=github.classified source={} request_id={} semantic_surface={} semantic_action={} provider_action_id={} target_hint={} content_retained={}",
            self.source,
            self.request_id,
            self.semantic_surface,
            self.semantic_action,
            self.provider_action_id(),
            self.target_hint,
            self.content_retained,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyBoundary {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub taxonomy_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBoundary {
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub contract_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub documentation_sources: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[cfg(test)]
mod tests {
    use agenta_core::provider::{ProviderActionId, ProviderId};

    use super::{
        GitHubGovernanceActionKind, GitHubGovernanceObservation, GitHubSemanticSurface,
        GitHubSignalSource,
    };

    #[test]
    fn github_boundary_labels_stay_redaction_safe_and_stable() {
        assert_eq!(
            GitHubSignalSource::ApiObservation.to_string(),
            "api_observation"
        );
        assert_eq!(
            GitHubSignalSource::BrowserObservation.to_string(),
            "browser_observation"
        );
        assert_eq!(
            GitHubSemanticSurface::GitHubActions.to_string(),
            "github.actions"
        );
        assert_eq!(
            GitHubGovernanceActionKind::PullsMerge.to_string(),
            "pulls.merge"
        );
    }

    #[test]
    fn github_governance_actions_map_onto_shared_provider_contract() {
        let action = GitHubGovernanceActionKind::ActionsWorkflowDispatch;
        let provider_action =
            action.provider_semantic_action("repos/n01e0/agent-auditor/actions/workflows/ci.yml");

        assert_eq!(provider_action.provider_id, ProviderId::github());
        assert_eq!(
            provider_action.action_key.as_str(),
            "actions.workflow_dispatch"
        );
        assert_eq!(
            provider_action.target_hint(),
            "repos/n01e0/agent-auditor/actions/workflows/ci.yml"
        );
        assert_eq!(
            action.provider_action_id().to_string(),
            "github:actions.workflow_dispatch"
        );
        assert_eq!(
            GitHubGovernanceActionKind::from_provider_action_id(&action.provider_action_id()),
            Some(action)
        );
    }

    #[test]
    fn github_governance_actions_reject_non_github_provider_contract_identity() {
        let gws_action = ProviderActionId::from_parts("gws", "drive.permissions.update").unwrap();

        assert_eq!(
            GitHubGovernanceActionKind::from_provider_action_id(&gws_action),
            None
        );
    }

    #[test]
    fn github_governance_actions_map_back_to_expected_surfaces() {
        assert_eq!(
            GitHubGovernanceActionKind::ReposUpdateVisibility.surface(),
            GitHubSemanticSurface::GitHubRepos
        );
        assert_eq!(
            GitHubGovernanceActionKind::BranchesUpdateProtection.surface(),
            GitHubSemanticSurface::GitHubBranches
        );
        assert_eq!(
            GitHubGovernanceActionKind::ActionsWorkflowDispatch.surface(),
            GitHubSemanticSurface::GitHubActions
        );
        assert_eq!(
            GitHubGovernanceActionKind::PullsMerge.surface(),
            GitHubSemanticSurface::GitHubPulls
        );
    }

    #[test]
    fn preview_observations_cover_api_and_browser_sources() {
        let api = GitHubGovernanceObservation::preview_api_repos_update_visibility();
        let browser = GitHubGovernanceObservation::preview_browser_pulls_merge();

        assert_eq!(api.source, GitHubSignalSource::ApiObservation);
        assert_eq!(browser.source, GitHubSignalSource::BrowserObservation);
        assert_eq!(
            api.semantic_surface_hint,
            GitHubSemanticSurface::GitHubRepos
        );
        assert_eq!(
            browser.semantic_surface_hint,
            GitHubSemanticSurface::GitHubPulls
        );
    }
}
