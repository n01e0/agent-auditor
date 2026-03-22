use std::fmt;

use agenta_core::{
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
        LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};

use crate::poc::github::{
    contract::{
        ClassifiedGitHubGovernanceAction, GitHubGovernanceObservation, GitHubSemanticSurface,
        GitHubSignalSource,
    },
    taxonomy::TaxonomyPlan,
};

use super::contract::LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

pub const LIVE_PROXY_GITHUB_REDACTION_RULE: &str = LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubLivePreviewAdapterPlan {
    pub upstream_fields: Vec<&'static str>,
    pub taxonomy_fields: Vec<&'static str>,
    pub semantic_actions: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
    taxonomy: TaxonomyPlan,
}

impl Default for GitHubLivePreviewAdapterPlan {
    fn default() -> Self {
        let taxonomy = TaxonomyPlan::default();
        Self {
            upstream_fields: GenericLiveActionEnvelope::field_names().to_vec(),
            taxonomy_fields: taxonomy.handoff().taxonomy_fields,
            semantic_actions: vec![
                "repos.update_visibility",
                "branches.update_protection",
                "actions.workflow_dispatch",
                "actions.runs.rerun",
                "pulls.merge",
                "actions.secrets.create_or_update",
            ],
            responsibilities: vec![
                "consume the shared live proxy envelope and project it into the redaction-safe GitHub governance observation boundary",
                "reuse the checked-in GitHub taxonomy classifier to derive provider semantic actions from live proxy previews without reopening raw request bodies or browser payloads",
                "keep target hints, route-template hints, and semantic-surface hints explicit so repository settings and browser-origin merge flows stay distinguishable",
            ],
            stages: vec!["observation_projection", "taxonomy", "provider_handoff"],
            redaction_contract: LIVE_PROXY_GITHUB_REDACTION_RULE,
            taxonomy,
        }
    }
}

impl GitHubLivePreviewAdapterPlan {
    pub fn classify_live_preview(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<ClassifiedGitHubGovernanceAction, LiveGitHubPreviewError> {
        let provider_hint = envelope
            .provider_hint
            .clone()
            .ok_or(LiveGitHubPreviewError::MissingProviderHint)?;
        if provider_hint != ProviderId::github() {
            return Err(LiveGitHubPreviewError::WrongProviderHint(provider_hint));
        }

        let observation = live_observation_from_envelope(envelope);
        self.taxonomy.classify_signal(&observation).ok_or_else(|| {
            LiveGitHubPreviewError::UnsupportedPreviewRoute {
                method: envelope.method,
                authority: envelope.authority.to_string(),
                path: envelope.path.to_string(),
                target_hint: envelope.target_hint.clone(),
            }
        })
    }

    pub fn preview_repos_update_visibility(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_repos_update_visibility())
            .expect("repos.update_visibility preview should classify")
    }

    pub fn preview_branches_update_protection(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_branches_update_protection())
            .expect("branches.update_protection preview should classify")
    }

    pub fn preview_actions_workflow_dispatch(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_actions_workflow_dispatch())
            .expect("actions.workflow_dispatch preview should classify")
    }

    pub fn preview_actions_runs_rerun(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_actions_runs_rerun())
            .expect("actions.runs.rerun preview should classify")
    }

    pub fn preview_pulls_merge(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_pulls_merge())
            .expect("pulls.merge preview should classify")
    }

    pub fn preview_actions_secrets_create_or_update(&self) -> ClassifiedGitHubGovernanceAction {
        self.classify_live_preview(&preview_actions_secrets_create_or_update())
            .expect("actions.secrets.create_or_update preview should classify")
    }

    pub fn summary(&self) -> String {
        format!(
            "semantic_actions={} taxonomy_fields={} stages={}",
            self.semantic_actions.join(","),
            self.taxonomy_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveGitHubPreviewError {
    MissingProviderHint,
    WrongProviderHint(ProviderId),
    UnsupportedPreviewRoute {
        method: ProviderMethod,
        authority: String,
        path: String,
        target_hint: Option<String>,
    },
}

impl fmt::Display for LiveGitHubPreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProviderHint => {
                write!(
                    f,
                    "GitHub live preview adapter requires provider_hint=github"
                )
            }
            Self::WrongProviderHint(provider) => write!(
                f,
                "GitHub live preview adapter expected provider_hint=github but received {}",
                provider
            ),
            Self::UnsupportedPreviewRoute {
                method,
                authority,
                path,
                target_hint,
            } => write!(
                f,
                "no GitHub live preview route matches method={} authority={} path={} target_hint={}",
                method,
                authority,
                path,
                target_hint.as_deref().unwrap_or("none")
            ),
        }
    }
}

fn live_observation_from_envelope(
    envelope: &GenericLiveActionEnvelope,
) -> GitHubGovernanceObservation {
    GitHubGovernanceObservation {
        source: map_live_source(envelope.source),
        request_id: envelope.request_id.to_string(),
        transport: envelope.transport.to_string(),
        authority_hint: Some(envelope.authority.to_string()),
        method_hint: Some(envelope.method.to_string()),
        route_template_hint: route_template_hint(envelope.path.as_str()),
        path_hint: Some(envelope.path.to_string()),
        target_hint: envelope.target_hint.clone(),
        semantic_surface_hint: GitHubSemanticSurface::GitHub,
    }
}

fn map_live_source(source: LiveCaptureSource) -> GitHubSignalSource {
    match source {
        LiveCaptureSource::BrowserRelay => GitHubSignalSource::BrowserObservation,
        LiveCaptureSource::ForwardProxy | LiveCaptureSource::SidecarProxy => {
            GitHubSignalSource::ApiObservation
        }
    }
}

fn route_template_hint(path: &str) -> Option<String> {
    let segments = path_segments(path);

    match segments.as_slice() {
        ["repos", _, _, "branches", _, "protection"] => {
            Some("/repos/{owner}/{repo}/branches/{branch}/protection".to_owned())
        }
        ["repos", _, _, "actions", "workflows", _, "dispatches"] => {
            Some("/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches".to_owned())
        }
        ["repos", _, _, "actions", "runs", _, "rerun"] => {
            Some("/repos/{owner}/{repo}/actions/runs/{run_id}/rerun".to_owned())
        }
        ["repos", _, _, "pulls", _, "merge"] => {
            Some("/repos/{owner}/{repo}/pulls/{pull_number}/merge".to_owned())
        }
        ["repos", _, _, "actions", "secrets", _] => {
            Some("/repos/{owner}/{repo}/actions/secrets/{secret_name}".to_owned())
        }
        ["repos", _, _] => Some("/repos/{owner}/{repo}".to_owned()),
        _ => None,
    }
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn preview_repos_update_visibility() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_github_repos_update_visibility_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_repos_update_visibility_preview").unwrap(),
        "sess_live_proxy_github_repos_update_visibility_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Patch,
        RestHost::new("api.github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        Some("repos/n01e0/agent-auditor/visibility".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_branches_update_protection() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_github_branches_update_protection_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_branches_update_protection_preview")
            .unwrap(),
        "sess_live_proxy_github_branches_update_protection_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("api.github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor/branches/main/protection").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_actions_workflow_dispatch() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_github_actions_workflow_dispatch_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_actions_workflow_dispatch_preview").unwrap(),
        "sess_live_proxy_github_actions_workflow_dispatch_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("api.github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor/actions/workflows/ci.yml/dispatches").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_actions_runs_rerun() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_github_actions_runs_rerun_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_actions_runs_rerun_preview").unwrap(),
        "sess_live_proxy_github_actions_runs_rerun_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("api.github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor/actions/runs/123456/rerun").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::Shadow,
    )
}

fn preview_pulls_merge() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        LiveRequestId::new("req_live_proxy_github_pulls_merge_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_pulls_merge_preview").unwrap(),
        "sess_live_proxy_github_pulls_merge_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor/pulls/69/merge").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::BrowserFetch,
        ]),
        LiveBodyClass::Json,
        LiveAuthHint::CookieSession,
        Some("repos/n01e0/agent-auditor/pulls/69".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_actions_secrets_create_or_update() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_github_actions_secrets_create_or_update_preview")
            .unwrap(),
        LiveCorrelationId::new("corr_live_proxy_github_actions_secrets_create_or_update_preview")
            .unwrap(),
        "sess_live_proxy_github_actions_secrets_create_or_update_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("api.github.com").unwrap(),
        LivePath::new("/repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        live::{
            GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
            LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
            LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
        },
        provider::{ProviderId, ProviderMethod},
        rest::RestHost,
    };

    use super::{GitHubLivePreviewAdapterPlan, LiveGitHubPreviewError};

    #[test]
    fn github_live_preview_plan_uses_the_shared_live_envelope_contract() {
        let plan = GitHubLivePreviewAdapterPlan::default();

        assert_eq!(
            plan.upstream_fields,
            GenericLiveActionEnvelope::field_names().to_vec()
        );
        assert_eq!(
            plan.semantic_actions,
            vec![
                "repos.update_visibility",
                "branches.update_protection",
                "actions.workflow_dispatch",
                "actions.runs.rerun",
                "pulls.merge",
                "actions.secrets.create_or_update",
            ]
        );
        assert!(
            plan.summary()
                .contains("stages=observation_projection->taxonomy->provider_handoff")
        );
    }

    #[test]
    fn github_live_preview_classifies_all_checked_in_semantic_actions() {
        let plan = GitHubLivePreviewAdapterPlan::default();

        assert_eq!(
            plan.preview_repos_update_visibility()
                .semantic_action
                .to_string(),
            "repos.update_visibility"
        );
        assert_eq!(
            plan.preview_branches_update_protection()
                .semantic_action
                .to_string(),
            "branches.update_protection"
        );
        assert_eq!(
            plan.preview_actions_workflow_dispatch()
                .semantic_action
                .to_string(),
            "actions.workflow_dispatch"
        );
        assert_eq!(
            plan.preview_actions_runs_rerun()
                .semantic_action
                .to_string(),
            "actions.runs.rerun"
        );
        let pulls_merge = plan.preview_pulls_merge();
        assert_eq!(pulls_merge.semantic_action.to_string(), "pulls.merge");
        assert_eq!(pulls_merge.source.to_string(), "browser_observation");
        assert_eq!(
            plan.preview_actions_secrets_create_or_update()
                .semantic_action
                .to_string(),
            "actions.secrets.create_or_update"
        );
    }

    #[test]
    fn github_live_preview_rejects_wrong_provider_hint_or_unmatched_route() {
        let plan = GitHubLivePreviewAdapterPlan::default();
        let wrong_provider = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_github_live_preview_wrong_provider").unwrap(),
            LiveCorrelationId::new("corr_github_live_preview_wrong_provider").unwrap(),
            "sess_github_live_preview_wrong_provider",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::gws()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Patch,
            RestHost::new("api.github.com").unwrap(),
            LivePath::new("/repos/n01e0/agent-auditor").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            Some("repos/n01e0/agent-auditor/visibility".to_owned()),
            LiveInterceptionMode::Shadow,
        );
        let unsupported = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_github_live_preview_unsupported").unwrap(),
            LiveCorrelationId::new("corr_github_live_preview_unsupported").unwrap(),
            "sess_github_live_preview_unsupported",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::github()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Delete,
            RestHost::new("api.github.com").unwrap(),
            LivePath::new("/repos/n01e0/agent-auditor/issues/1").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::None,
            LiveAuthHint::Bearer,
            None,
            LiveInterceptionMode::Shadow,
        );

        assert!(matches!(
            plan.classify_live_preview(&wrong_provider),
            Err(LiveGitHubPreviewError::WrongProviderHint(_))
        ));
        assert!(matches!(
            plan.classify_live_preview(&unsupported),
            Err(LiveGitHubPreviewError::UnsupportedPreviewRoute { .. })
        ));
    }
}
