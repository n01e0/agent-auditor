use std::fmt;

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
}

impl fmt::Display for GitHubGovernanceActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
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
    use super::{GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource};

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
}
