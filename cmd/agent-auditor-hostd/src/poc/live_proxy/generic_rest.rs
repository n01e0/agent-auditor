use std::fmt;

use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRef, SourceInfo,
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationStatus, LiveHeaderClass, LiveInterceptionMode,
    },
    provider::{
        ActionKey, CanonicalResource, OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionId,
        ProviderActionMetadata, ProviderId, ProviderMetadataCatalog, ProviderMethod,
        ProviderSemanticAction, SideEffect,
    },
    rest::{GenericRestAction, PathTemplate, QueryClass, RestHost},
};
use serde_json::json;

use super::session_correlation::{CorrelatedLiveRequest, LiveRequestProvenance};

const LIVE_PROXY_GENERIC_REST_REDACTION_RULE: &str = "live generic REST preview seams carry only redaction-safe live envelope lineage, route templates, authority labels, query classes, shared action identity, target hints, mode labels, and docs-backed auth/risk descriptors; raw header values, request bodies, response bodies, token values, message text, file bytes, and full query strings must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRestLivePreviewPlan {
    pub providers: Vec<&'static str>,
    pub upstream_fields: Vec<&'static str>,
    pub generic_contract_fields: Vec<&'static str>,
    pub preview_actions: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
    metadata_catalog: ProviderMetadataCatalog,
}

impl Default for GenericRestLivePreviewPlan {
    fn default() -> Self {
        Self {
            providers: vec!["gws", "github"],
            upstream_fields: agenta_core::live::GenericLiveActionEnvelope::field_names().to_vec(),
            generic_contract_fields: vec![
                "provider_id",
                "action_key",
                "target_hint",
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ],
            preview_actions: vec![
                "admin.reports.activities.list",
                "gmail.users.messages.send",
                "actions.secrets.create_or_update",
            ],
            responsibilities: vec![
                "consume the shared live proxy envelope and derive one redaction-safe generic REST preview event before provider-specific family adapters run",
                "match only the small checked-in preview route set needed to prove allow, require_approval, and deny policy inputs without claiming full provider taxonomy coverage",
                "join docs-backed provider metadata so agenta-policy can evaluate the existing generic REST contract against live proxy previews",
                "avoid owning durable audit / approval persistence or inline enforcement outcomes on the live path",
            ],
            stages: vec![
                "match_preview_route",
                "join_provider_metadata",
                "normalize_generic_rest_event",
            ],
            redaction_contract: LIVE_PROXY_GENERIC_REST_REDACTION_RULE,
            metadata_catalog: preview_provider_metadata_catalog(),
        }
    }
}

impl GenericRestLivePreviewPlan {
    pub fn normalize_live_request(
        &self,
        correlated: &CorrelatedLiveRequest,
    ) -> Result<EventEnvelope, LiveGenericRestPreviewError> {
        let envelope = &correlated.envelope;
        let route = preview_route_for(envelope)?;
        let metadata = self
            .metadata_catalog
            .find(&route.provider_action.id())
            .ok_or_else(|| LiveGenericRestPreviewError::MissingProviderMetadata {
                provider_action: route.provider_action.id(),
            })?;
        let action = GenericRestAction::from_provider_metadata(
            route.provider_action.clone(),
            route.host.clone(),
            route.path_template.clone(),
            route.query_class,
            metadata,
        )
        .map_err(
            |error| LiveGenericRestPreviewError::InvalidGenericRestContract {
                provider_action: route.provider_action.id(),
                message: error.to_string(),
            },
        )?;

        Ok(EventEnvelope::new(
            format!(
                "evt_live_proxy_{}_{}",
                action.id(),
                correlated.event_suffix()
            ),
            event_type_for(action.provider_id.clone()),
            correlated.session.clone(),
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd-live-proxy".to_owned()),
                display_name: Some("agent-auditor-hostd live proxy preview".to_owned()),
            },
            Action {
                class: action_class_for(action.provider_id.clone()),
                verb: Some(action.action_key.to_string()),
                target: Some(action.target_hint.clone()),
                attributes: action_attributes(correlated, &action, &route, metadata),
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some(correlated.result_reason().to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some(correlated.host_id().to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        ))
    }

    pub fn normalize_live_preview(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<EventEnvelope, LiveGenericRestPreviewError> {
        let correlated = CorrelatedLiveRequest {
            envelope: envelope.clone(),
            session: session_ref_from_live_envelope(
                envelope,
                LiveRequestProvenance::FixturePreview.policy_bundle_version(),
            ),
            provenance: LiveRequestProvenance::FixturePreview,
            session_correlation_status: LiveRequestProvenance::FixturePreview
                .session_correlation_status(),
            session_correlation_reason: LiveRequestProvenance::FixturePreview
                .session_correlation_reason(),
        };
        self.normalize_live_request(&correlated)
    }

    pub fn preview_allow_admin_reports_activities_list(&self) -> EventEnvelope {
        self.normalize_live_preview(&preview_admin_reports_activities_list())
            .expect("preview allow envelope should normalize")
    }

    pub fn preview_hold_gmail_users_messages_send(&self) -> EventEnvelope {
        self.normalize_live_preview(&preview_gmail_users_messages_send())
            .expect("preview hold envelope should normalize")
    }

    pub fn preview_deny_github_actions_secrets_create_or_update(&self) -> EventEnvelope {
        self.normalize_live_preview(&preview_github_actions_secrets_create_or_update())
            .expect("preview deny envelope should normalize")
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} preview_actions={} generic_contract_fields={} stages={}",
            self.providers.join(","),
            self.preview_actions.join(","),
            self.generic_contract_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewRouteMatch {
    provider_action: ProviderSemanticAction,
    host: RestHost,
    path_template: PathTemplate,
    query_class: QueryClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveGenericRestPreviewError {
    MissingProviderHint,
    UnsupportedPreviewRoute {
        provider_hint: Option<ProviderId>,
        method: ProviderMethod,
        authority: RestHost,
        path: String,
    },
    MissingProviderMetadata {
        provider_action: ProviderActionId,
    },
    InvalidGenericRestContract {
        provider_action: ProviderActionId,
        message: String,
    },
}

impl fmt::Display for LiveGenericRestPreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProviderHint => {
                write!(f, "generic REST live preview requires a provider_hint")
            }
            Self::UnsupportedPreviewRoute {
                provider_hint,
                method,
                authority,
                path,
            } => {
                let provider_hint = provider_hint
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "none".to_owned());
                write!(
                    f,
                    "no generic REST live preview route matches provider_hint={provider_hint} method={method} authority={authority} path={path}"
                )
            }
            Self::MissingProviderMetadata { provider_action } => write!(
                f,
                "generic REST live preview metadata is missing for provider action `{provider_action}`"
            ),
            Self::InvalidGenericRestContract {
                provider_action,
                message,
            } => write!(
                f,
                "generic REST live preview contract for `{provider_action}` is invalid: {message}"
            ),
        }
    }
}

fn preview_route_for(
    envelope: &GenericLiveActionEnvelope,
) -> Result<PreviewRouteMatch, LiveGenericRestPreviewError> {
    let provider_hint = envelope
        .provider_hint
        .clone()
        .ok_or(LiveGenericRestPreviewError::MissingProviderHint)?;

    if provider_hint == ProviderId::gws()
        && envelope.method == ProviderMethod::Get
        && envelope.authority == rest_host("admin.googleapis.com")
        && envelope
            .path
            .as_str()
            .starts_with("/admin/reports/v1/activity/users/all/applications/")
    {
        let application_name = envelope
            .path
            .as_str()
            .trim_start_matches("/admin/reports/v1/activity/users/all/applications/");
        return Ok(PreviewRouteMatch {
            provider_action: ProviderSemanticAction::new(
                ProviderId::gws(),
                action_key("admin.reports.activities.list"),
                format!("admin.reports/users/all/applications/{application_name}"),
            ),
            host: rest_host("admin.googleapis.com"),
            path_template: path_template(
                "/admin/reports/v1/activity/users/all/applications/{applicationName}",
            ),
            query_class: QueryClass::Filter,
        });
    }

    if provider_hint == ProviderId::gws()
        && envelope.method == ProviderMethod::Post
        && envelope.authority == rest_host("gmail.googleapis.com")
        && envelope.path.as_str() == "/gmail/v1/users/me/messages/send"
    {
        return Ok(PreviewRouteMatch {
            provider_action: ProviderSemanticAction::new(
                ProviderId::gws(),
                action_key("gmail.users.messages.send"),
                "gmail.users/me".to_owned(),
            ),
            host: rest_host("gmail.googleapis.com"),
            path_template: path_template("/gmail/v1/users/{userId}/messages/send"),
            query_class: QueryClass::ActionArguments,
        });
    }

    if provider_hint == ProviderId::github()
        && envelope.method == ProviderMethod::Put
        && envelope.authority == rest_host("api.github.com")
        && is_github_actions_secret_path(envelope.path.as_str())
    {
        return Ok(PreviewRouteMatch {
            provider_action: ProviderSemanticAction::new(
                ProviderId::github(),
                action_key("actions.secrets.create_or_update"),
                envelope.path.as_str().trim_start_matches('/').to_owned(),
            ),
            host: rest_host("api.github.com"),
            path_template: path_template("/repos/{owner}/{repo}/actions/secrets/{secret_name}"),
            query_class: QueryClass::None,
        });
    }

    Err(LiveGenericRestPreviewError::UnsupportedPreviewRoute {
        provider_hint: Some(provider_hint),
        method: envelope.method,
        authority: envelope.authority.clone(),
        path: envelope.path.to_string(),
    })
}

fn action_attributes(
    correlated: &CorrelatedLiveRequest,
    action: &GenericRestAction,
    route: &PreviewRouteMatch,
    metadata: &ProviderActionMetadata,
) -> JsonMap {
    let envelope = &correlated.envelope;
    let mut attributes = JsonMap::new();
    attributes.insert("source_kind".to_owned(), json!(correlated.source_kind()));
    attributes.insert(
        "live_source".to_owned(),
        json!(live_source_label(envelope.source)),
    );
    attributes.insert("request_id".to_owned(), json!(envelope.request_id.as_str()));
    attributes.insert(
        "correlation_id".to_owned(),
        json!(envelope.correlation_id.as_str()),
    );
    attributes.insert(
        "correlation_status".to_owned(),
        json!(live_correlation_status_label(envelope.correlation_status)),
    );
    attributes.insert(
        "session_correlation_status".to_owned(),
        json!(correlated.session_correlation_status),
    );
    attributes.insert(
        "session_correlation_reason".to_owned(),
        json!(correlated.session_correlation_reason),
    );
    attributes.insert(
        "live_surface".to_owned(),
        json!(envelope.live_surface.as_str()),
    );
    attributes.insert("transport".to_owned(), json!(envelope.transport.as_str()));
    attributes.insert(
        "provider_hint".to_owned(),
        json!(action.provider_id.as_str()),
    );
    attributes.insert("provider_id".to_owned(), json!(action.provider_id.as_str()));
    attributes.insert("action_key".to_owned(), json!(action.action_key.as_str()));
    attributes.insert(
        "provider_action_id".to_owned(),
        json!(action.id().to_string()),
    );
    attributes.insert("target_hint".to_owned(), json!(action.target_hint()));
    attributes.insert("method".to_owned(), json!(action.method.to_string()));
    attributes.insert("host".to_owned(), json!(action.host.as_str()));
    attributes.insert(
        "path_template".to_owned(),
        json!(route.path_template.as_str()),
    );
    attributes.insert(
        "query_class".to_owned(),
        json!(route.query_class.to_string()),
    );
    attributes.insert(
        "oauth_scope_labels".to_owned(),
        json!({
            "primary": metadata.oauth_scopes.primary.as_str(),
            "documented": metadata
                .oauth_scopes
                .documented
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
        }),
    );
    attributes.insert(
        "side_effect".to_owned(),
        json!(metadata.side_effect.as_str()),
    );
    attributes.insert(
        "privilege_class".to_owned(),
        json!(metadata.privilege_class.to_string()),
    );
    attributes.insert(
        "header_classes".to_owned(),
        json!(envelope.headers.labels().into_iter().collect::<Vec<_>>()),
    );
    attributes.insert(
        "body_class".to_owned(),
        json!(live_body_class_label(envelope.body_class)),
    );
    attributes.insert(
        "auth_hint".to_owned(),
        json!(live_auth_hint_label(envelope.auth_hint)),
    );
    attributes.insert("mode".to_owned(), json!(live_mode_label(envelope.mode)));
    attributes.insert(
        "content_retained".to_owned(),
        json!(envelope.content_retained),
    );
    attributes
}

fn session_ref_from_live_envelope(
    envelope: &GenericLiveActionEnvelope,
    policy_bundle_version: impl Into<String>,
) -> SessionRef {
    SessionRef {
        session_id: envelope.session_id.clone(),
        agent_id: envelope.agent_id.clone(),
        initiator_id: None,
        workspace_id: envelope.workspace_id.clone(),
        policy_bundle_version: Some(policy_bundle_version.into()),
        environment: Some("dev".to_owned()),
    }
}

fn event_type_for(provider_id: ProviderId) -> EventType {
    if provider_id == ProviderId::github() {
        EventType::GithubAction
    } else {
        EventType::GwsAction
    }
}

fn action_class_for(provider_id: ProviderId) -> ActionClass {
    if provider_id == ProviderId::github() {
        ActionClass::Github
    } else {
        ActionClass::Gws
    }
}

fn preview_provider_metadata_catalog() -> ProviderMetadataCatalog {
    ProviderMetadataCatalog::new(vec![
        ProviderActionMetadata::new(
            ProviderActionId::from_parts("gws", "admin.reports.activities.list")
                .expect("preview provider action should be valid"),
            ProviderMethod::Get,
            CanonicalResource::new("admin.reports.activities/{applicationName}")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("returns Admin Reports activity entries for the requested application")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                oauth_scope("https://www.googleapis.com/auth/admin.reports.audit.readonly"),
                vec![oauth_scope(
                    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                )],
            ),
            PrivilegeClass::AdminRead,
        ),
        ProviderActionMetadata::new(
            ProviderActionId::from_parts("gws", "gmail.users.messages.send")
                .expect("preview provider action should be valid"),
            ProviderMethod::Post,
            CanonicalResource::new("gmail.users/{userId}/messages:send")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("sends the specified message to the listed recipients")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                oauth_scope("https://www.googleapis.com/auth/gmail.send"),
                vec![oauth_scope("https://www.googleapis.com/auth/gmail.send")],
            ),
            PrivilegeClass::OutboundSend,
        ),
        ProviderActionMetadata::new(
            ProviderActionId::from_parts("github", "actions.secrets.create_or_update")
                .expect("preview provider action should be valid"),
            ProviderMethod::Put,
            CanonicalResource::new("repos/{owner}/{repo}/actions/secrets/{secret_name}")
                .expect("preview canonical resource should be valid"),
            SideEffect::new("creates or updates an encrypted repository Actions secret")
                .expect("preview side effect should be valid"),
            OAuthScopeSet::new(
                oauth_scope("github.permission:secrets:write"),
                vec![
                    oauth_scope("github.permission:secrets:write"),
                    oauth_scope("github.oauth:repo"),
                ],
            ),
            PrivilegeClass::AdminWrite,
        ),
    ])
}

fn preview_admin_reports_activities_list() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        agenta_core::live::LiveRequestId::new(
            "req_live_proxy_admin_reports_activities_list_preview",
        )
        .expect("preview request id should be valid"),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_admin_reports_activities_list_preview",
        )
        .expect("preview correlation id should be valid"),
        "sess_live_proxy_admin_reports_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
        LiveCorrelationStatus::Confirmed,
        agenta_core::live::LiveSurface::http_request(),
        agenta_core::live::LiveTransport::new("https").expect("preview transport should be valid"),
        ProviderMethod::Get,
        rest_host("admin.googleapis.com"),
        agenta_core::live::LivePath::new("/admin/reports/v1/activity/users/all/applications/drive")
            .expect("preview path should be valid"),
        agenta_core::live::LiveHeaders::new([LiveHeaderClass::Authorization]),
        LiveBodyClass::None,
        LiveAuthHint::OAuthUser,
        Some("admin.reports/users/all/applications/drive".to_owned()),
        LiveInterceptionMode::Shadow,
    )
}

fn preview_gmail_users_messages_send() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        agenta_core::live::LiveRequestId::new("req_live_proxy_gmail_users_messages_send_preview")
            .expect("preview request id should be valid"),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_gmail_users_messages_send_preview",
        )
        .expect("preview correlation id should be valid"),
        "sess_live_proxy_gmail_send_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
        LiveCorrelationStatus::Confirmed,
        agenta_core::live::LiveSurface::http_request(),
        agenta_core::live::LiveTransport::new("https").expect("preview transport should be valid"),
        ProviderMethod::Post,
        rest_host("gmail.googleapis.com"),
        agenta_core::live::LivePath::new("/gmail/v1/users/me/messages/send")
            .expect("preview path should be valid"),
        agenta_core::live::LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentJson,
            LiveHeaderClass::MessageMetadata,
        ]),
        LiveBodyClass::Json,
        LiveAuthHint::OAuthUser,
        Some("gmail.users/me".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_github_actions_secrets_create_or_update() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        agenta_core::live::LiveRequestId::new(
            "req_live_proxy_github_actions_secrets_create_or_update_preview",
        )
        .expect("preview request id should be valid"),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_github_actions_secrets_create_or_update_preview",
        )
        .expect("preview correlation id should be valid"),
        "sess_live_proxy_github_secret_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::github()),
        LiveCorrelationStatus::Confirmed,
        agenta_core::live::LiveSurface::http_request(),
        agenta_core::live::LiveTransport::new("https").expect("preview transport should be valid"),
        ProviderMethod::Put,
        rest_host("api.github.com"),
        agenta_core::live::LivePath::new("/repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN")
            .expect("preview path should be valid"),
        agenta_core::live::LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentJson,
        ]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        Some("repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn rest_host(value: &str) -> RestHost {
    RestHost::new(value).expect("preview host should be valid")
}

fn path_template(value: &str) -> PathTemplate {
    PathTemplate::new(value).expect("preview path template should be valid")
}

fn action_key(value: &str) -> ActionKey {
    ActionKey::new(value).expect("preview action key should be valid")
}

fn oauth_scope(value: &str) -> OAuthScope {
    OAuthScope::new(value).expect("preview OAuth scope should be valid")
}

fn is_github_actions_secret_path(path: &str) -> bool {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "actions"
        && segments[4] == "secrets"
        && !segments[5].is_empty()
}

fn live_source_label(source: LiveCaptureSource) -> &'static str {
    match source {
        LiveCaptureSource::ForwardProxy => "forward_proxy",
        LiveCaptureSource::BrowserRelay => "browser_relay",
        LiveCaptureSource::SidecarProxy => "sidecar_proxy",
    }
}

fn live_correlation_status_label(status: LiveCorrelationStatus) -> &'static str {
    match status {
        LiveCorrelationStatus::Confirmed => "confirmed",
        LiveCorrelationStatus::Provisional => "provisional",
        LiveCorrelationStatus::Uncorrelated => "uncorrelated",
    }
}

fn live_body_class_label(body_class: LiveBodyClass) -> &'static str {
    match body_class {
        LiveBodyClass::Binary => "binary",
        LiveBodyClass::FormUrlencoded => "form_urlencoded",
        LiveBodyClass::Json => "json",
        LiveBodyClass::MultipartFormData => "multipart_form_data",
        LiveBodyClass::None => "none",
        LiveBodyClass::Text => "text",
        LiveBodyClass::Unknown => "unknown",
    }
}

fn live_auth_hint_label(auth_hint: LiveAuthHint) -> &'static str {
    match auth_hint {
        LiveAuthHint::ApiKey => "api_key",
        LiveAuthHint::Basic => "basic",
        LiveAuthHint::Bearer => "bearer",
        LiveAuthHint::CookieSession => "cookie_session",
        LiveAuthHint::None => "none",
        LiveAuthHint::OAuthServiceAccount => "oauth_service_account",
        LiveAuthHint::OAuthUser => "oauth_user",
        LiveAuthHint::Unknown => "unknown",
    }
}

fn live_mode_label(mode: LiveInterceptionMode) -> &'static str {
    match mode {
        LiveInterceptionMode::Shadow => "shadow",
        LiveInterceptionMode::EnforcePreview => "enforce_preview",
        LiveInterceptionMode::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use agenta_policy::{PolicyEvaluator, PolicyInput, RegoPolicyEvaluator};

    use super::{
        GenericRestLivePreviewPlan, LIVE_PROXY_GENERIC_REST_REDACTION_RULE,
        LiveGenericRestPreviewError,
    };
    use agenta_core::{
        ActionClass, EventType, PolicyDecisionKind,
        live::{
            GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
            LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
            LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
        },
        provider::{ProviderId, ProviderMethod},
        rest::RestHost,
    };

    #[test]
    fn bootstrap_plan_describes_the_generic_rest_live_preview_contract() {
        let plan = GenericRestLivePreviewPlan::default();

        assert_eq!(plan.providers, vec!["gws", "github"]);
        assert_eq!(
            plan.upstream_fields,
            GenericLiveActionEnvelope::field_names().to_vec()
        );
        assert_eq!(
            plan.generic_contract_fields,
            vec![
                "provider_id",
                "action_key",
                "target_hint",
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ]
        );
        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("join docs-backed provider metadata"))
        );
        assert_eq!(
            plan.redaction_contract,
            LIVE_PROXY_GENERIC_REST_REDACTION_RULE
        );
        assert!(plan.summary().contains(
            "stages=match_preview_route->join_provider_metadata->normalize_generic_rest_event"
        ));
    }

    #[test]
    fn allow_preview_normalizes_live_proxy_envelope_into_generic_rest_event() {
        let plan = GenericRestLivePreviewPlan::default();
        let event = plan.preview_allow_admin_reports_activities_list();
        let input = PolicyInput::from_event(&event);
        let generic_rest_action = input
            .generic_rest_action
            .expect("generic REST action should derive from normalized event");

        assert_eq!(event.event_type, EventType::GwsAction);
        assert_eq!(event.action.class, ActionClass::Gws);
        assert_eq!(
            event.action.verb.as_deref(),
            Some("admin.reports.activities.list")
        );
        assert_eq!(
            event.action.target.as_deref(),
            Some("admin.reports/users/all/applications/drive")
        );
        assert_eq!(
            event
                .action
                .attributes
                .get("source_kind")
                .and_then(|value| value.as_str()),
            Some("live_proxy_preview")
        );
        assert_eq!(
            event
                .action
                .attributes
                .get("live_source")
                .and_then(|value| value.as_str()),
            Some("forward_proxy")
        );
        assert_eq!(generic_rest_action.provider_id, ProviderId::gws());
        assert_eq!(
            generic_rest_action.action_key.as_str(),
            "admin.reports.activities.list"
        );
        assert_eq!(generic_rest_action.method, ProviderMethod::Get);
        assert_eq!(
            generic_rest_action.host,
            RestHost::new("admin.googleapis.com").unwrap()
        );
        assert_eq!(
            generic_rest_action.path_template.as_str(),
            "/admin/reports/v1/activity/users/all/applications/{applicationName}"
        );
        assert_eq!(generic_rest_action.query_class.to_string(), "filter");
    }

    #[test]
    fn hold_preview_normalizes_live_proxy_envelope_and_hits_existing_generic_rest_policy() {
        let plan = GenericRestLivePreviewPlan::default();
        let event = plan.preview_hold_gmail_users_messages_send();
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .expect("hold preview should evaluate");

        assert_eq!(event.event_type, EventType::GwsAction);
        assert_eq!(event.action.class, ActionClass::Gws);
        assert_eq!(
            event.action.verb.as_deref(),
            Some("gmail.users.messages.send")
        );
        assert_eq!(
            event
                .action
                .attributes
                .get("mode")
                .and_then(|value| value.as_str()),
            Some("enforce_preview")
        );
        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
    }

    #[test]
    fn deny_preview_normalizes_live_proxy_envelope_and_hits_existing_generic_rest_policy() {
        let plan = GenericRestLivePreviewPlan::default();
        let event = plan.preview_deny_github_actions_secrets_create_or_update();
        let input = PolicyInput::from_event(&event);
        let decision = RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .expect("deny preview should evaluate");

        assert_eq!(event.event_type, EventType::GithubAction);
        assert_eq!(event.action.class, ActionClass::Github);
        assert_eq!(
            event.action.verb.as_deref(),
            Some("actions.secrets.create_or_update")
        );
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
    }

    #[test]
    fn normalize_live_preview_requires_provider_hint_and_known_route() {
        let plan = GenericRestLivePreviewPlan::default();
        let missing_provider = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_missing_provider_hint").unwrap(),
            LiveCorrelationId::new("corr_missing_provider_hint").unwrap(),
            "sess_missing_provider_hint",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            None,
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Get,
            RestHost::new("admin.googleapis.com").unwrap(),
            LivePath::new("/admin/reports/v1/activity/users/all/applications/drive").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::None,
            LiveAuthHint::OAuthUser,
            Some("admin.reports/users/all/applications/drive".to_owned()),
            LiveInterceptionMode::Shadow,
        );
        let unsupported_route = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_unsupported_route").unwrap(),
            LiveCorrelationId::new("corr_unsupported_route").unwrap(),
            "sess_unsupported_route",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::github()),
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

        assert!(matches!(
            plan.normalize_live_preview(&missing_provider),
            Err(LiveGenericRestPreviewError::MissingProviderHint)
        ));
        assert!(matches!(
            plan.normalize_live_preview(&unsupported_route),
            Err(LiveGenericRestPreviewError::UnsupportedPreviewRoute { .. })
        ));
    }
}
