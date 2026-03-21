use super::contract::{
    ClassifiedGitHubGovernanceAction, GITHUB_GOVERNANCE_REDACTION_RULE, GitHubGovernanceActionKind,
    GitHubGovernanceObservation, GitHubSemanticSurface, GitHubSignalSource, TaxonomyBoundary,
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
                "identify at least repos.update_visibility, branches.update_protection, actions.workflow_dispatch, actions.runs.rerun, pulls.merge, and actions.secrets.create_or_update from redaction-safe request hints",
                "attach provider_id plus action_key, target hints, and classifier-owned rationale without joining docs-backed metadata",
                "handoff redaction-safe GitHub governance candidates downstream without normalizing agenta-core events or deciding policy outcomes",
            ],
            stages: vec!["service_map", "taxonomy", "label", "handoff"],
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

    pub fn classify_signal(
        &self,
        observation: &GitHubGovernanceObservation,
    ) -> Option<ClassifiedGitHubGovernanceAction> {
        let method = observation.method_hint.as_deref()?;
        let normalized_authority = observation
            .authority_hint
            .as_deref()
            .map(normalize_authority);
        if !normalized_authority.is_some_and(is_github_authority) {
            return None;
        }

        let normalized_path = observation.path_hint.as_deref().map(strip_query);
        let normalized_template = observation
            .route_template_hint
            .as_deref()
            .map(normalize_route_template);

        let (semantic_action, target_hint) = classify_semantic_action(
            method,
            normalized_path,
            normalized_template,
            observation.target_hint.as_deref(),
            observation.semantic_surface_hint,
        )?;
        let provider_action = semantic_action.provider_semantic_action(target_hint.clone());

        Some(ClassifiedGitHubGovernanceAction {
            source: observation.source,
            request_id: observation.request_id.clone(),
            transport: observation.transport.clone(),
            authority_hint: observation.authority_hint.clone(),
            method_hint: observation.method_hint.clone(),
            route_template_hint: observation.route_template_hint.clone(),
            path_hint: observation.path_hint.clone(),
            semantic_surface: semantic_action.surface(),
            semantic_action,
            provider_action,
            target_hint,
            classifier_labels: semantic_action.classifier_labels(),
            classifier_reasons: vec![semantic_action.reason()],
            content_retained: false,
        })
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
            "sources={} surfaces={} input_fields={} taxonomy_fields={} actions={} stages={}",
            sources,
            surfaces,
            self.input_fields.join(","),
            self.taxonomy_fields.join(","),
            actions,
            self.stages.join("->")
        )
    }
}

fn classify_semantic_action(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
    semantic_surface_hint: GitHubSemanticSurface,
) -> Option<(GitHubGovernanceActionKind, String)> {
    if let Some(target_hint) =
        classify_repos_update_visibility(method, normalized_path, route_template_hint, target_hint)
    {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::ReposUpdateVisibility,
            target_hint,
        );
    }

    if let Some(target_hint) = classify_branches_update_protection(
        method,
        normalized_path,
        route_template_hint,
        target_hint,
    ) {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::BranchesUpdateProtection,
            target_hint,
        );
    }

    if let Some(target_hint) = classify_actions_workflow_dispatch(
        method,
        normalized_path,
        route_template_hint,
        target_hint,
    ) {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::ActionsWorkflowDispatch,
            target_hint,
        );
    }

    if let Some(target_hint) =
        classify_actions_runs_rerun(method, normalized_path, route_template_hint, target_hint)
    {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::ActionsRunsRerun,
            target_hint,
        );
    }

    if let Some(target_hint) =
        classify_pulls_merge(method, normalized_path, route_template_hint, target_hint)
    {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::PullsMerge,
            target_hint,
        );
    }

    if let Some(target_hint) = classify_actions_secrets_create_or_update(
        method,
        normalized_path,
        route_template_hint,
        target_hint,
    ) {
        return maybe_surface_match(
            semantic_surface_hint,
            GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate,
            target_hint,
        );
    }

    None
}

fn maybe_surface_match(
    semantic_surface_hint: GitHubSemanticSurface,
    action: GitHubGovernanceActionKind,
    target_hint: String,
) -> Option<(GitHubGovernanceActionKind, String)> {
    if semantic_surface_hint == GitHubSemanticSurface::GitHub
        || semantic_surface_hint == action.surface()
    {
        Some((action, target_hint))
    } else {
        None
    }
}

fn classify_repos_update_visibility(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("PATCH") {
        return None;
    }

    let target_hint = target_hint.filter(|target_hint| is_repo_visibility_target(target_hint))?;

    if matches_repos_root_path(normalized_path)
        || matches_route_template(route_template_hint, "repos/{owner}/{repo}")
    {
        return Some(target_hint.to_owned());
    }

    None
}

fn classify_branches_update_protection(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !matches_branch_protection_method(method) {
        return None;
    }

    if let Some(target_hint) =
        target_hint.filter(|target_hint| is_branch_protection_target(target_hint))
    {
        return Some(target_hint.to_owned());
    }

    if let Some(segments) = match_repos_branch_protection_path(normalized_path) {
        return Some(format!(
            "repos/{}/{}/branches/{}/protection",
            segments[1], segments[2], segments[4]
        ));
    }

    if matches_route_template(
        route_template_hint,
        "repos/{owner}/{repo}/branches/{branch}/protection",
    ) {
        return target_hint.map(ToOwned::to_owned);
    }

    None
}

fn classify_actions_workflow_dispatch(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }

    if let Some(target_hint) =
        target_hint.filter(|target_hint| is_workflow_dispatch_target(target_hint))
    {
        return Some(target_hint.to_owned());
    }

    if let Some(segments) = match_actions_workflow_dispatch_path(normalized_path) {
        return Some(format!(
            "repos/{}/{}/actions/workflows/{}",
            segments[1], segments[2], segments[5]
        ));
    }

    if matches_route_template(
        route_template_hint,
        "repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
    ) {
        return target_hint.map(ToOwned::to_owned);
    }

    None
}

fn classify_actions_runs_rerun(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }

    if let Some(target_hint) = target_hint.filter(|target_hint| is_actions_run_target(target_hint))
    {
        return Some(target_hint.to_owned());
    }

    if let Some(segments) = match_actions_runs_rerun_path(normalized_path) {
        return Some(format!(
            "repos/{}/{}/actions/runs/{}",
            segments[1], segments[2], segments[5]
        ));
    }

    if matches_route_template(
        route_template_hint,
        "repos/{owner}/{repo}/actions/runs/{run_id}/rerun",
    ) {
        return target_hint.map(ToOwned::to_owned);
    }

    None
}

fn classify_pulls_merge(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("PUT") {
        return None;
    }

    if let Some(target_hint) = target_hint.filter(|target_hint| is_pull_target(target_hint)) {
        return Some(target_hint.to_owned());
    }

    if let Some(segments) = match_pulls_merge_path(normalized_path) {
        return Some(format!(
            "repos/{}/{}/pulls/{}",
            segments[1], segments[2], segments[4]
        ));
    }

    if matches_route_template(
        route_template_hint,
        "repos/{owner}/{repo}/pulls/{pull_number}/merge",
    ) {
        return target_hint.map(ToOwned::to_owned);
    }

    None
}

fn classify_actions_secrets_create_or_update(
    method: &str,
    normalized_path: Option<&str>,
    route_template_hint: Option<&str>,
    target_hint: Option<&str>,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("PUT") {
        return None;
    }

    if let Some(target_hint) =
        target_hint.filter(|target_hint| is_actions_secret_target(target_hint))
    {
        return Some(target_hint.to_owned());
    }

    if let Some(segments) = match_actions_secret_path(normalized_path) {
        return Some(format!(
            "repos/{}/{}/actions/secrets/{}",
            segments[1], segments[2], segments[5]
        ));
    }

    if matches_route_template(
        route_template_hint,
        "repos/{owner}/{repo}/actions/secrets/{secret_name}",
    ) {
        return target_hint.map(ToOwned::to_owned);
    }

    None
}

fn matches_branch_protection_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("PUT") || method.eq_ignore_ascii_case("PATCH")
}

fn matches_repos_root_path(path: Option<&str>) -> bool {
    match_repos_root_path(path).is_some()
}

fn match_repos_root_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 3 && segments[0] == "repos" {
        Some(segments)
    } else {
        None
    }
}

fn match_repos_branch_protection_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "branches"
        && segments[5] == "protection"
    {
        Some(segments)
    } else {
        None
    }
}

fn match_actions_workflow_dispatch_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 7
        && segments[0] == "repos"
        && segments[3] == "actions"
        && segments[4] == "workflows"
        && segments[6] == "dispatches"
    {
        Some(segments)
    } else {
        None
    }
}

fn match_actions_runs_rerun_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 7
        && segments[0] == "repos"
        && segments[3] == "actions"
        && segments[4] == "runs"
        && segments[6] == "rerun"
    {
        Some(segments)
    } else {
        None
    }
}

fn match_pulls_merge_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "pulls"
        && segments[5] == "merge"
    {
        Some(segments)
    } else {
        None
    }
}

fn match_actions_secret_path(path: Option<&str>) -> Option<Vec<&str>> {
    let segments = path_segments(path?);
    if segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "actions"
        && segments[4] == "secrets"
    {
        Some(segments)
    } else {
        None
    }
}

fn path_segments(path: &str) -> Vec<&str> {
    strip_query(path)
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn normalize_authority(authority: &str) -> &str {
    authority.trim().trim_end_matches('.')
}

fn is_github_authority(authority: &str) -> bool {
    matches!(authority, "api.github.com" | "github.com")
}

fn strip_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn normalize_route_template(route_template_hint: &str) -> &str {
    strip_query(route_template_hint).trim_matches('/')
}

fn matches_route_template(route_template_hint: Option<&str>, expected: &str) -> bool {
    route_template_hint.is_some_and(|template| template == expected)
}

fn is_repo_visibility_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).ends_with("/visibility")
}

fn is_branch_protection_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).contains("/branches/")
        && normalize_target_hint(target_hint).ends_with("/protection")
}

fn is_workflow_dispatch_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).contains("/actions/workflows/")
}

fn is_actions_run_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).contains("/actions/runs/")
}

fn is_pull_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).contains("/pulls/")
}

fn is_actions_secret_target(target_hint: &str) -> bool {
    normalize_target_hint(target_hint).contains("/actions/secrets/")
}

fn normalize_target_hint(target_hint: &str) -> &str {
    target_hint.trim_matches('/')
}

#[cfg(test)]
mod tests {
    use super::{
        GitHubGovernanceObservation, TaxonomyPlan, classify_actions_runs_rerun,
        classify_actions_secrets_create_or_update, classify_actions_workflow_dispatch,
        classify_branches_update_protection, classify_pulls_merge,
        classify_repos_update_visibility, is_github_authority, match_actions_runs_rerun_path,
        match_actions_secret_path, match_actions_workflow_dispatch_path, match_pulls_merge_path,
        match_repos_branch_protection_path, matches_branch_protection_method, normalize_authority,
        normalize_route_template, strip_query,
    };
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
        assert!(plan.responsibilities.iter().any(|item| {
            item.contains("repos.update_visibility")
                && item.contains("actions.secrets.create_or_update")
        }));
    }

    #[test]
    fn classify_repos_update_visibility_from_api_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(&GitHubGovernanceObservation::preview_api_repos_update_visibility())
            .expect("preview repo visibility update should classify");

        assert_eq!(
            classified.semantic_surface,
            GitHubSemanticSurface::GitHubRepos
        );
        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::ReposUpdateVisibility
        );
        assert_eq!(
            classified.provider_action_id().to_string(),
            "github:repos.update_visibility"
        );
        assert_eq!(
            classified.target_hint,
            "repos/n01e0/agent-auditor/visibility"
        );
        assert!(!classified.content_retained);
    }

    #[test]
    fn classify_branches_update_protection_from_api_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(&GitHubGovernanceObservation::preview_api_branches_update_protection())
            .expect("preview branch protection update should classify");

        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::BranchesUpdateProtection
        );
        assert_eq!(
            classified.target_hint,
            "repos/n01e0/agent-auditor/branches/main/protection"
        );
    }

    #[test]
    fn classify_actions_workflow_dispatch_from_api_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(&GitHubGovernanceObservation::preview_api_actions_workflow_dispatch())
            .expect("preview workflow dispatch should classify");

        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::ActionsWorkflowDispatch
        );
        assert_eq!(
            classified.target_hint,
            "repos/n01e0/agent-auditor/actions/workflows/ci.yml"
        );
    }

    #[test]
    fn classify_actions_runs_rerun_from_api_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(&GitHubGovernanceObservation::preview_api_actions_runs_rerun())
            .expect("preview workflow rerun should classify");

        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::ActionsRunsRerun
        );
        assert_eq!(
            classified.target_hint,
            "repos/n01e0/agent-auditor/actions/runs/123456"
        );
    }

    #[test]
    fn classify_pulls_merge_from_browser_route_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(&GitHubGovernanceObservation::preview_browser_pulls_merge())
            .expect("preview browser merge should classify");

        assert_eq!(classified.source, GitHubSignalSource::BrowserObservation);
        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::PullsMerge
        );
        assert_eq!(classified.target_hint, "repos/n01e0/agent-auditor/pulls/69");
    }

    #[test]
    fn classify_actions_secrets_create_or_update_from_api_hint() {
        let plan = TaxonomyPlan::default();
        let classified = plan
            .classify_signal(
                &GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
            )
            .expect("preview actions secret write should classify");

        assert_eq!(
            classified.semantic_action,
            GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate
        );
        assert_eq!(
            classified.target_hint,
            "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN"
        );
    }

    #[test]
    fn classify_returns_none_for_unmatched_or_non_github_routes() {
        let plan = TaxonomyPlan::default();
        let unmatched = GitHubGovernanceObservation {
            source: GitHubSignalSource::ApiObservation,
            request_id: "req_unmatched".to_owned(),
            transport: "https".to_owned(),
            authority_hint: Some("api.github.com".to_owned()),
            method_hint: Some("GET".to_owned()),
            route_template_hint: Some("/repos/{owner}/{repo}/issues".to_owned()),
            path_hint: Some("/repos/n01e0/agent-auditor/issues".to_owned()),
            target_hint: None,
            semantic_surface_hint: GitHubSemanticSurface::GitHubRepos,
        };
        let wrong_authority = GitHubGovernanceObservation {
            authority_hint: Some("example.com".to_owned()),
            ..GitHubGovernanceObservation::preview_api_actions_runs_rerun()
        };

        assert_eq!(plan.classify_signal(&unmatched), None);
        assert_eq!(plan.classify_signal(&wrong_authority), None);
    }

    #[test]
    fn classify_respects_surface_mismatch() {
        let plan = TaxonomyPlan::default();
        let mismatched_surface = GitHubGovernanceObservation {
            semantic_surface_hint: GitHubSemanticSurface::GitHubPulls,
            ..GitHubGovernanceObservation::preview_api_actions_workflow_dispatch()
        };
        let generic_surface = GitHubGovernanceObservation {
            semantic_surface_hint: GitHubSemanticSurface::GitHub,
            ..GitHubGovernanceObservation::preview_api_actions_workflow_dispatch()
        };

        assert_eq!(plan.classify_signal(&mismatched_surface), None);
        assert!(plan.classify_signal(&generic_surface).is_some());
    }

    #[test]
    fn helper_matchers_cover_expected_supported_actions() {
        assert_eq!(normalize_authority("api.github.com."), "api.github.com");
        assert!(is_github_authority("api.github.com"));
        assert!(is_github_authority("github.com"));
        assert_eq!(strip_query("/repos/a/b?per_page=1"), "/repos/a/b");
        assert_eq!(
            normalize_route_template("/repos/{owner}/{repo}/actions/runs/{run_id}/rerun"),
            "repos/{owner}/{repo}/actions/runs/{run_id}/rerun"
        );
        assert!(matches_branch_protection_method("PUT"));
        assert!(matches_branch_protection_method("PATCH"));
        assert!(
            match_repos_branch_protection_path(Some(
                "/repos/n01e0/agent-auditor/branches/main/protection"
            ))
            .is_some()
        );
        assert!(
            match_actions_workflow_dispatch_path(Some(
                "/repos/n01e0/agent-auditor/actions/workflows/ci.yml/dispatches"
            ))
            .is_some()
        );
        assert!(
            match_actions_runs_rerun_path(Some(
                "/repos/n01e0/agent-auditor/actions/runs/123/rerun"
            ))
            .is_some()
        );
        assert!(
            match_pulls_merge_path(Some("/repos/n01e0/agent-auditor/pulls/69/merge")).is_some()
        );
        assert!(
            match_actions_secret_path(Some(
                "/repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN"
            ))
            .is_some()
        );
        assert_eq!(
            classify_repos_update_visibility(
                "PATCH",
                Some("/repos/n01e0/agent-auditor"),
                Some("repos/{owner}/{repo}"),
                Some("repos/n01e0/agent-auditor/visibility"),
            ),
            Some("repos/n01e0/agent-auditor/visibility".to_owned())
        );
        assert_eq!(
            classify_branches_update_protection(
                "PUT",
                Some("/repos/n01e0/agent-auditor/branches/main/protection"),
                None,
                None,
            ),
            Some("repos/n01e0/agent-auditor/branches/main/protection".to_owned())
        );
        assert_eq!(
            classify_actions_workflow_dispatch(
                "POST",
                Some("/repos/n01e0/agent-auditor/actions/workflows/ci.yml/dispatches"),
                None,
                None,
            ),
            Some("repos/n01e0/agent-auditor/actions/workflows/ci.yml".to_owned())
        );
        assert_eq!(
            classify_actions_runs_rerun(
                "POST",
                Some("/repos/n01e0/agent-auditor/actions/runs/123/rerun"),
                None,
                None,
            ),
            Some("repos/n01e0/agent-auditor/actions/runs/123".to_owned())
        );
        assert_eq!(
            classify_pulls_merge(
                "PUT",
                Some("/repos/n01e0/agent-auditor/pulls/69/merge"),
                None,
                None,
            ),
            Some("repos/n01e0/agent-auditor/pulls/69".to_owned())
        );
        assert_eq!(
            classify_actions_secrets_create_or_update(
                "PUT",
                Some("/repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN"),
                None,
                None,
            ),
            Some("repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN".to_owned())
        );
    }

    #[test]
    fn taxonomy_summary_mentions_actions_and_field_contract() {
        let summary = TaxonomyPlan::default().summary();

        assert!(summary.contains("actions=repos.update_visibility"));
        assert!(summary.contains("taxonomy_fields=semantic_surface,provider_id,action_key,target_hint,classifier_labels,classifier_reasons,content_retained"));
        assert!(summary.contains("stages=service_map->taxonomy->label->handoff"));
    }
}
