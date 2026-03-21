use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{
    ClassifiedGitHubGovernanceAction, GitHubGovernanceActionKind, GitHubSemanticSurface,
    GitHubSignalSource, MetadataBoundary, RecordBoundary, TaxonomyBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub taxonomy_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: RecordBoundary,
}

impl PolicyPlan {
    pub fn from_boundaries(taxonomy: TaxonomyBoundary, metadata: MetadataBoundary) -> Self {
        Self {
            sources: taxonomy.sources.clone(),
            semantic_surfaces: taxonomy.semantic_surfaces.clone(),
            taxonomy_fields: taxonomy.taxonomy_fields.clone(),
            metadata_fields: metadata.metadata_fields.clone(),
            semantic_actions: metadata.semantic_actions.clone(),
            responsibilities: vec![
                "normalize redaction-safe GitHub governance candidates toward agenta-core without redefining GitHub taxonomy or mutating the metadata catalog",
                "preserve the shared provider contract on normalized GitHub governance events so downstream policy can derive provider_id plus action_key plus target_hint without legacy-only labels",
                "join docs-backed provider metadata onto provider_id plus action_key before agenta-policy evaluation",
                "bridge normalized GitHub governance events into agenta-policy and project allow / deny / require_approval outcomes",
                "carry the GitHub governance redaction contract forward into audit and approval recording",
            ],
            stages: vec!["normalize", "annotate", "evaluate", "project"],
            handoff: RecordBoundary {
                sources: taxonomy.sources,
                semantic_surfaces: taxonomy.semantic_surfaces,
                semantic_actions: metadata.semantic_actions,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: taxonomy.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        self.handoff.clone()
    }

    pub fn normalize_classified_action(
        &self,
        action: &ClassifiedGitHubGovernanceAction,
        session: &SessionRecord,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(action.source.to_string()));
        attributes.insert("request_id".to_owned(), json!(action.request_id));
        attributes.insert("transport".to_owned(), json!(action.transport));
        attributes.insert(
            "semantic_surface".to_owned(),
            json!(action.semantic_surface.to_string()),
        );
        attributes.insert(
            "provider_id".to_owned(),
            json!(action.provider_action.provider_id.to_string()),
        );
        attributes.insert(
            "action_key".to_owned(),
            json!(action.provider_action.action_key.to_string()),
        );
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(action.provider_action_id().to_string()),
        );
        attributes.insert(
            "semantic_action_label".to_owned(),
            json!(action.semantic_action.to_string()),
        );
        attributes.insert(
            "target_hint".to_owned(),
            json!(action.provider_action.target_hint()),
        );
        attributes.insert(
            "classifier_labels".to_owned(),
            json!(action.classifier_labels),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(action.classifier_reasons),
        );
        attributes.insert(
            "content_retained".to_owned(),
            json!(action.content_retained),
        );

        if let Some(authority_hint) = &action.authority_hint {
            attributes.insert("authority_hint".to_owned(), json!(authority_hint));
        }

        if let Some(method_hint) = &action.method_hint {
            attributes.insert("method_hint".to_owned(), json!(method_hint));
        }

        if let Some(route_template_hint) = &action.route_template_hint {
            attributes.insert("route_template_hint".to_owned(), json!(route_template_hint));
        }

        if let Some(path_hint) = &action.path_hint {
            attributes.insert("path_hint".to_owned(), json!(path_hint));
        }

        EventEnvelope::new(
            format!(
                "poc_github_action_{}_{}_{}",
                action.source,
                action.semantic_action,
                sanitize_id_segment(&action.request_id)
            ),
            EventType::GithubAction,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Github,
                verb: Some(action.provider_action.action_key.to_string()),
                target: Some(action.provider_action.target_hint().to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd GitHub semantic-governance PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(action.source),
        )
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
            "sources={} surfaces={} taxonomy_fields={} metadata_fields={} stages={}",
            sources,
            surfaces,
            self.taxonomy_fields.join(","),
            self.metadata_fields.join(","),
            self.stages.join("->")
        )
    }
}

fn session_ref_from_record(session: &SessionRecord) -> SessionRef {
    SessionRef {
        session_id: session.session_id.clone(),
        agent_id: Some(session.agent_id.clone()),
        initiator_id: session.initiator_id.clone(),
        workspace_id: session
            .workspace
            .as_ref()
            .and_then(|workspace| workspace.workspace_id.clone()),
        policy_bundle_version: session.policy_bundle_version.clone(),
        environment: None,
    }
}

fn hostd_actor() -> Actor {
    Actor {
        kind: ActorKind::System,
        id: Some("agent-auditor-hostd".to_owned()),
        display_name: Some("agent-auditor-hostd PoC".to_owned()),
    }
}

fn source_info(source: GitHubSignalSource) -> SourceInfo {
    SourceInfo {
        collector: collector_for_source(source),
        host_id: Some("hostd-poc".to_owned()),
        container_id: None,
        pod_uid: None,
        pid: None,
        ppid: None,
    }
}

fn collector_for_source(_source: GitHubSignalSource) -> CollectorKind {
    CollectorKind::RuntimeHint
}

fn sanitize_id_segment(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, ActorKind, CollectorKind, EventType, ResultStatus, SessionRecord,
        SessionWorkspace,
    };
    use agenta_policy::PolicyInput;
    use serde_json::json;

    use super::PolicyPlan;
    use crate::poc::github::{
        contract::{GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource},
        metadata::MetadataPlan,
        taxonomy::TaxonomyPlan,
    };

    #[test]
    fn policy_plan_threads_github_surfaces_and_taxonomy_contract_fields() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let plan = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());

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
        assert!(plan.taxonomy_fields.contains(&"provider_id"));
        assert!(plan.taxonomy_fields.contains(&"action_key"));
        assert!(plan.taxonomy_fields.contains(&"target_hint"));
        assert!(plan.metadata_fields.contains(&"method"));
        assert!(plan.metadata_fields.contains(&"canonical_resource"));
    }

    #[test]
    fn normalize_api_classified_action_uses_agenta_core_github_shape() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let classified = taxonomy
            .classify_signal(&crate::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility())
            .expect("repo visibility preview should classify");
        let session = fixture_session();

        let envelope = policy.normalize_classified_action(&classified, &session);

        assert_eq!(
            envelope.event_id,
            "poc_github_action_api_observation_repos.update_visibility_req_github_repos_update_visibility_preview"
        );
        assert_eq!(envelope.event_type, EventType::GithubAction);
        assert_eq!(envelope.session.session_id, "sess_github_policy");
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Github);
        assert_eq!(
            envelope.action.verb.as_deref(),
            Some("repos.update_visibility")
        );
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("repos/n01e0/agent-auditor/visibility")
        );
        assert_eq!(
            envelope.action.attributes.get("source_kind"),
            Some(&json!("api_observation"))
        );
        assert_eq!(
            envelope.action.attributes.get("request_id"),
            Some(&json!("req_github_repos_update_visibility_preview"))
        );
        assert_eq!(
            envelope.action.attributes.get("semantic_surface"),
            Some(&json!("github.repos"))
        );
        assert_eq!(
            envelope.action.attributes.get("provider_id"),
            Some(&json!("github"))
        );
        assert_eq!(
            envelope.action.attributes.get("action_key"),
            Some(&json!("repos.update_visibility"))
        );
        assert_eq!(
            envelope.action.attributes.get("provider_action_id"),
            Some(&json!("github:repos.update_visibility"))
        );
        assert_eq!(
            envelope.action.attributes.get("semantic_action_label"),
            Some(&json!("repos.update_visibility"))
        );
        assert_eq!(
            envelope.action.attributes.get("route_template_hint"),
            Some(&json!("/repos/{owner}/{repo}"))
        );
        assert_eq!(
            envelope.action.attributes.get("path_hint"),
            Some(&json!("/repos/n01e0/agent-auditor"))
        );
        assert_eq!(
            envelope.result.reason.as_deref(),
            Some("observed by hostd GitHub semantic-governance PoC")
        );
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(envelope.source.collector, CollectorKind::RuntimeHint);
    }

    #[test]
    fn normalize_browser_classified_action_preserves_browser_route_hints() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let classified = taxonomy
            .classify_signal(&crate::poc::github::contract::GitHubGovernanceObservation::preview_browser_pulls_merge())
            .expect("browser merge preview should classify");
        let session = fixture_session();

        let envelope = policy.normalize_classified_action(&classified, &session);

        assert_eq!(envelope.event_type, EventType::GithubAction);
        assert_eq!(envelope.action.class, ActionClass::Github);
        assert_eq!(envelope.action.verb.as_deref(), Some("pulls.merge"));
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("repos/n01e0/agent-auditor/pulls/69")
        );
        assert_eq!(
            envelope.action.attributes.get("source_kind"),
            Some(&json!("browser_observation"))
        );
        assert_eq!(
            envelope.action.attributes.get("transport"),
            Some(&json!("browser"))
        );
        assert_eq!(
            envelope.action.attributes.get("authority_hint"),
            Some(&json!("github.com"))
        );
        assert_eq!(
            envelope.action.attributes.get("route_template_hint"),
            Some(&json!("/repos/{owner}/{repo}/pulls/{pull_number}/merge"))
        );
        assert_eq!(envelope.action.attributes.get("path_hint"), None);
    }

    #[test]
    fn normalized_github_events_derive_shared_provider_action_for_policy_input() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let classified = taxonomy
            .classify_signal(&crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update())
            .expect("actions secret preview should classify");
        let session = fixture_session();

        let envelope = policy.normalize_classified_action(&classified, &session);
        let provider_action = PolicyInput::from_event(&envelope)
            .provider_action
            .expect("normalized GitHub event should derive shared provider action");

        assert_eq!(provider_action.provider_id.to_string(), "github");
        assert_eq!(
            provider_action.action_key.to_string(),
            "actions.secrets.create_or_update"
        );
        assert_eq!(
            provider_action.target_hint(),
            "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN"
        );
    }

    #[test]
    fn normalized_github_events_cover_all_supported_high_risk_actions() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let session = fixture_session();
        let previews = [
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_branches_update_protection(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_workflow_dispatch(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_pulls_merge(),
            crate::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
        ];
        let expected_actions = vec![
            GitHubGovernanceActionKind::ReposUpdateVisibility,
            GitHubGovernanceActionKind::BranchesUpdateProtection,
            GitHubGovernanceActionKind::ActionsWorkflowDispatch,
            GitHubGovernanceActionKind::ActionsRunsRerun,
            GitHubGovernanceActionKind::PullsMerge,
            GitHubGovernanceActionKind::ActionsSecretsCreateOrUpdate,
        ];

        let normalized_actions = previews
            .iter()
            .map(|preview| {
                taxonomy
                    .classify_signal(preview)
                    .expect("preview should classify for normalization")
            })
            .map(|classified| policy.normalize_classified_action(&classified, &session))
            .collect::<Vec<_>>();

        assert_eq!(
            normalized_actions
                .iter()
                .map(|event| event.event_type)
                .collect::<Vec<_>>(),
            vec![EventType::GithubAction; 6]
        );
        assert_eq!(
            normalized_actions
                .iter()
                .map(|event| event.action.class)
                .collect::<Vec<_>>(),
            vec![ActionClass::Github; 6]
        );
        assert_eq!(
            normalized_actions
                .iter()
                .map(|event| event.action.verb.clone().expect("verb should exist"))
                .collect::<Vec<_>>(),
            expected_actions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn policy_plan_joins_taxonomy_and_metadata_without_owning_either_boundary() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let plan = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());

        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("join docs-backed provider metadata"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("shared provider contract"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("durable audit"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("live request matching"))
        );
        assert_eq!(
            plan.handoff().record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
    }

    #[test]
    fn policy_summary_mentions_normalize_and_evaluate_stages() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let summary = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff()).summary();

        assert!(summary.contains("stages=normalize->annotate->evaluate->project"));
        assert!(summary.contains(
            "metadata_fields=method,canonical_resource,side_effect,oauth_scopes,privilege_class"
        ));
        assert!(summary.contains(
            "taxonomy_fields=semantic_surface,provider_id,action_key,target_hint,classifier_labels,classifier_reasons,content_retained"
        ));
    }

    fn fixture_session() -> SessionRecord {
        let mut session = SessionRecord::placeholder("openclaw-main", "sess_github_policy");
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("ws_github_policy".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
