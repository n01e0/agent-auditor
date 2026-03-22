use std::fmt;

use agenta_core::{
    SessionRef,
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationStatus, LiveHeaderClass, LiveHeaders, LiveInterceptionMode, LivePath,
        LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};

use crate::poc::gws::contract::{
    ClassifiedGwsAction, GwsActionKind, GwsSemanticSurface, GwsSignalSource, SessionLinkedGwsAction,
};

use super::contract::LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

pub const LIVE_PROXY_GWS_REDACTION_RULE: &str = LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GwsLivePreviewAdapterPlan {
    pub upstream_fields: Vec<&'static str>,
    pub provider_fields: Vec<&'static str>,
    pub semantic_actions: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl Default for GwsLivePreviewAdapterPlan {
    fn default() -> Self {
        Self {
            upstream_fields: GenericLiveActionEnvelope::field_names().to_vec(),
            provider_fields: vec![
                "source",
                "request_id",
                "transport",
                "authority_hint",
                "method_hint",
                "path_hint",
                "semantic_surface",
                "provider_id",
                "action_key",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ],
            semantic_actions: vec![
                "drive.permissions.update",
                "drive.files.get_media",
                "gmail.users.messages.send",
                "admin.reports.activities.list",
            ],
            responsibilities: vec![
                "consume the shared live proxy envelope and derive one GWS live preview candidate without reopening raw request bytes or session correlation",
                "identify the checked-in Drive, Gmail, and Admin Reports semantic actions from redaction-safe authority, method, path, and target hints",
                "preserve the shared live session lineage while handing off a provider semantic action candidate to the existing GWS governance slice",
            ],
            stages: vec!["route_match", "target_projection", "provider_handoff"],
            redaction_contract: LIVE_PROXY_GWS_REDACTION_RULE,
        }
    }
}

impl GwsLivePreviewAdapterPlan {
    pub fn classify_live_preview(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<ClassifiedGwsAction, LiveGwsPreviewError> {
        let action = classify_gws_semantic_action(envelope)?;
        let provider_action = action
            .kind
            .provider_semantic_action(action.target_hint.clone());

        Ok(ClassifiedGwsAction {
            source: map_live_source(envelope.source),
            request_id: envelope.request_id.to_string(),
            transport: envelope.transport.to_string(),
            authority_hint: Some(envelope.authority.to_string()),
            method_hint: Some(envelope.method.to_string()),
            path_hint: Some(envelope.path.to_string()),
            destination_ip: None,
            destination_port: None,
            semantic_surface: action.kind.surface(),
            semantic_action: action.kind,
            provider_action,
            target_hint: action.target_hint,
            classifier_labels: action.kind.classifier_labels(),
            classifier_reasons: vec![action.kind.reason()],
            content_retained: false,
        })
    }

    pub fn preview_drive_permissions_update(&self) -> ClassifiedGwsAction {
        self.classify_live_preview(&preview_drive_permissions_update())
            .expect("Drive permissions update preview should classify")
    }

    pub fn preview_drive_files_get_media(&self) -> ClassifiedGwsAction {
        self.classify_live_preview(&preview_drive_files_get_media())
            .expect("Drive files get_media preview should classify")
    }

    pub fn preview_gmail_users_messages_send(&self) -> ClassifiedGwsAction {
        self.classify_live_preview(&preview_gmail_users_messages_send())
            .expect("Gmail send preview should classify")
    }

    pub fn preview_admin_reports_activities_list(&self) -> ClassifiedGwsAction {
        self.classify_live_preview(&preview_admin_reports_activities_list())
            .expect("Admin Reports preview should classify")
    }

    pub fn preview_session_linkage(&self) -> SessionLinkedGwsAction {
        let envelope = preview_gmail_users_messages_send();

        SessionLinkedGwsAction {
            source: map_live_source(envelope.source),
            request_id: envelope.request_id.to_string(),
            transport: envelope.transport.to_string(),
            authority_hint: Some(envelope.authority.to_string()),
            method_hint: Some(envelope.method.to_string()),
            path_hint: Some(envelope.path.to_string()),
            destination_ip: None,
            destination_port: None,
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspace,
            session: session_ref_from_live_envelope(&envelope),
            linkage_reason:
                "reused shared live proxy session correlation for the provider-specific GWS preview adapter"
                    .to_owned(),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "semantic_actions={} provider_fields={} stages={}",
            self.semantic_actions.join(","),
            self.provider_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedGwsAction {
    kind: GwsActionKind,
    target_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveGwsPreviewError {
    MissingProviderHint,
    WrongProviderHint(ProviderId),
    UnsupportedPreviewRoute {
        method: ProviderMethod,
        authority: String,
        path: String,
        target_hint: Option<String>,
    },
}

impl fmt::Display for LiveGwsPreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProviderHint => {
                write!(f, "GWS live preview adapter requires provider_hint=gws")
            }
            Self::WrongProviderHint(provider) => write!(
                f,
                "GWS live preview adapter expected provider_hint=gws but received {}",
                provider
            ),
            Self::UnsupportedPreviewRoute {
                method,
                authority,
                path,
                target_hint,
            } => write!(
                f,
                "no GWS live preview route matches method={} authority={} path={} target_hint={}",
                method,
                authority,
                path,
                target_hint.as_deref().unwrap_or("none")
            ),
        }
    }
}

fn classify_gws_semantic_action(
    envelope: &GenericLiveActionEnvelope,
) -> Result<MatchedGwsAction, LiveGwsPreviewError> {
    let provider_hint = envelope
        .provider_hint
        .clone()
        .ok_or(LiveGwsPreviewError::MissingProviderHint)?;
    if provider_hint != ProviderId::gws() {
        return Err(LiveGwsPreviewError::WrongProviderHint(provider_hint));
    }

    let method = envelope.method;
    let authority = normalize_authority(envelope.authority.as_str());
    let path = envelope.path.as_str();
    let target_hint = envelope.target_hint.as_deref();

    if let Some(target_hint) = match_drive_permissions_update(method, path) {
        return Ok(MatchedGwsAction {
            kind: GwsActionKind::DrivePermissionsUpdate,
            target_hint,
        });
    }

    if let Some(target_hint) = match_drive_files_get_media(method, authority, path, target_hint) {
        return Ok(MatchedGwsAction {
            kind: GwsActionKind::DriveFilesGetMedia,
            target_hint,
        });
    }

    if let Some(target_hint) = match_gmail_users_messages_send(method, authority, path) {
        return Ok(MatchedGwsAction {
            kind: GwsActionKind::GmailUsersMessagesSend,
            target_hint,
        });
    }

    if let Some(target_hint) = match_admin_reports_activities_list(method, authority, path) {
        return Ok(MatchedGwsAction {
            kind: GwsActionKind::AdminReportsActivitiesList,
            target_hint,
        });
    }

    Err(LiveGwsPreviewError::UnsupportedPreviewRoute {
        method,
        authority: envelope.authority.to_string(),
        path: envelope.path.to_string(),
        target_hint: envelope.target_hint.clone(),
    })
}

fn match_drive_permissions_update(method: ProviderMethod, path: &str) -> Option<String> {
    if method != ProviderMethod::Patch {
        return None;
    }

    let segments = path_segments(path);
    if segments.len() == 6
        && segments[0] == "drive"
        && segments[1] == "v3"
        && segments[2] == "files"
        && segments[4] == "permissions"
    {
        return Some(format!(
            "drive.files/{}/permissions/{}",
            segments[3], segments[5]
        ));
    }

    None
}

fn match_drive_files_get_media(
    method: ProviderMethod,
    authority: &str,
    path: &str,
    target_hint: Option<&str>,
) -> Option<String> {
    if method != ProviderMethod::Get || authority != "www.googleapis.com" {
        return None;
    }

    let segments = path_segments(path);
    if segments.len() == 4
        && segments[0] == "drive"
        && segments[1] == "v3"
        && segments[2] == "files"
    {
        let file_target = format!("drive.files/{}", segments[3]);
        let content_target = format!("{}/content", file_target);
        if target_hint == Some(content_target.as_str()) || target_hint == Some(file_target.as_str())
        {
            return Some(file_target);
        }
    }

    None
}

fn match_gmail_users_messages_send(
    method: ProviderMethod,
    authority: &str,
    path: &str,
) -> Option<String> {
    if method != ProviderMethod::Post || authority != "gmail.googleapis.com" {
        return None;
    }

    let segments = path_segments(path);
    if segments.len() == 6
        && segments[0] == "gmail"
        && segments[1] == "v1"
        && segments[2] == "users"
        && segments[4] == "messages"
        && segments[5] == "send"
    {
        return Some(format!("gmail.users/{}", segments[3]));
    }

    None
}

fn match_admin_reports_activities_list(
    method: ProviderMethod,
    authority: &str,
    path: &str,
) -> Option<String> {
    if method != ProviderMethod::Get || authority != "admin.googleapis.com" {
        return None;
    }

    let segments = path_segments(path);
    if segments.len() == 8
        && segments[0] == "admin"
        && segments[1] == "reports"
        && segments[2] == "v1"
        && segments[3] == "activity"
        && segments[4] == "users"
        && segments[5] == "all"
        && segments[6] == "applications"
    {
        return Some(format!(
            "admin.reports/users/all/applications/{}",
            segments[7]
        ));
    }

    None
}

fn normalize_authority(authority: &str) -> &str {
    authority.trim()
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn map_live_source(source: LiveCaptureSource) -> GwsSignalSource {
    match source {
        LiveCaptureSource::ForwardProxy
        | LiveCaptureSource::BrowserRelay
        | LiveCaptureSource::SidecarProxy => GwsSignalSource::ApiObservation,
    }
}

fn session_ref_from_live_envelope(envelope: &GenericLiveActionEnvelope) -> SessionRef {
    SessionRef {
        session_id: envelope.session_id.clone(),
        agent_id: envelope.agent_id.clone(),
        initiator_id: None,
        workspace_id: envelope.workspace_id.clone(),
        policy_bundle_version: Some("bundle-live-proxy-preview".to_owned()),
        environment: Some("dev".to_owned()),
    }
}

fn preview_drive_permissions_update() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_drive_permissions_update_preview").unwrap(),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_drive_permissions_update_preview",
        )
        .unwrap(),
        "sess_live_proxy_drive_permissions_update_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Patch,
        RestHost::new("www.googleapis.com").unwrap(),
        LivePath::new("/drive/v3/files/abc123/permissions/perm456").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::OAuthUser,
        Some("drive.files/abc123/permissions/perm456".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_drive_files_get_media() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::SidecarProxy,
        LiveRequestId::new("req_live_proxy_drive_files_get_media_preview").unwrap(),
        agenta_core::live::LiveCorrelationId::new("corr_live_proxy_drive_files_get_media_preview")
            .unwrap(),
        "sess_live_proxy_drive_files_get_media_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Get,
        RestHost::new("www.googleapis.com").unwrap(),
        LivePath::new("/drive/v3/files/abc123").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization]),
        LiveBodyClass::None,
        LiveAuthHint::OAuthUser,
        Some("drive.files/abc123/content".to_owned()),
        LiveInterceptionMode::Shadow,
    )
}

fn preview_gmail_users_messages_send() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        LiveRequestId::new("req_live_proxy_gmail_users_messages_send_preview").unwrap(),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_gmail_users_messages_send_preview",
        )
        .unwrap(),
        "sess_live_proxy_gmail_users_messages_send_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("gmail.googleapis.com").unwrap(),
        LivePath::new("/gmail/v1/users/me/messages/send").unwrap(),
        LiveHeaders::new([
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

fn preview_admin_reports_activities_list() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_admin_reports_activities_list_preview").unwrap(),
        agenta_core::live::LiveCorrelationId::new(
            "corr_live_proxy_admin_reports_activities_list_preview",
        )
        .unwrap(),
        "sess_live_proxy_admin_reports_activities_list_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(ProviderId::gws()),
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

    use super::{GwsLivePreviewAdapterPlan, LiveGwsPreviewError, preview_drive_files_get_media};

    #[test]
    fn gws_live_preview_plan_uses_the_shared_live_envelope_contract() {
        let plan = GwsLivePreviewAdapterPlan::default();

        assert_eq!(
            plan.upstream_fields,
            GenericLiveActionEnvelope::field_names().to_vec()
        );
        assert_eq!(
            plan.semantic_actions,
            vec![
                "drive.permissions.update",
                "drive.files.get_media",
                "gmail.users.messages.send",
                "admin.reports.activities.list",
            ]
        );
        assert!(
            plan.summary()
                .contains("stages=route_match->target_projection->provider_handoff")
        );
    }

    #[test]
    fn gws_live_preview_classifies_all_checked_in_semantic_actions() {
        let plan = GwsLivePreviewAdapterPlan::default();

        let drive_permissions = plan.preview_drive_permissions_update();
        assert_eq!(
            drive_permissions.semantic_action.to_string(),
            "drive.permissions.update"
        );
        assert_eq!(
            drive_permissions.target_hint,
            "drive.files/abc123/permissions/perm456"
        );

        let drive_get_media = plan.preview_drive_files_get_media();
        assert_eq!(
            drive_get_media.semantic_action.to_string(),
            "drive.files.get_media"
        );
        assert_eq!(drive_get_media.target_hint, "drive.files/abc123");

        let gmail_send = plan.preview_gmail_users_messages_send();
        assert_eq!(
            gmail_send.semantic_action.to_string(),
            "gmail.users.messages.send"
        );
        assert_eq!(gmail_send.target_hint, "gmail.users/me");

        let admin_reports = plan.preview_admin_reports_activities_list();
        assert_eq!(
            admin_reports.semantic_action.to_string(),
            "admin.reports.activities.list"
        );
        assert_eq!(
            admin_reports.target_hint,
            "admin.reports/users/all/applications/drive"
        );
    }

    #[test]
    fn gws_live_preview_preserves_shared_session_lineage_for_provider_boundary() {
        let plan = GwsLivePreviewAdapterPlan::default();
        let linked = plan.preview_session_linkage();

        assert_eq!(
            linked.session.session_id,
            "sess_live_proxy_gmail_users_messages_send_preview"
        );
        assert_eq!(linked.session.agent_id.as_deref(), Some("openclaw-main"));
        assert_eq!(
            linked.session.workspace_id.as_deref(),
            Some("agent-auditor")
        );
        assert_eq!(
            linked.linkage_reason,
            "reused shared live proxy session correlation for the provider-specific GWS preview adapter"
        );
    }

    #[test]
    fn gws_live_preview_rejects_wrong_provider_hint_or_unmatched_route() {
        let plan = GwsLivePreviewAdapterPlan::default();
        let mut wrong_provider = preview_drive_files_get_media();
        wrong_provider.provider_hint = Some(ProviderId::github());
        let unsupported = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_gws_live_preview_unsupported").unwrap(),
            LiveCorrelationId::new("corr_gws_live_preview_unsupported").unwrap(),
            "sess_gws_live_preview_unsupported",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::gws()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Get,
            RestHost::new("www.googleapis.com").unwrap(),
            LivePath::new("/drive/v3/files/abc123").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::None,
            LiveAuthHint::OAuthUser,
            None,
            LiveInterceptionMode::Shadow,
        );

        assert!(matches!(
            plan.classify_live_preview(&wrong_provider),
            Err(LiveGwsPreviewError::WrongProviderHint(_))
        ));
        assert!(matches!(
            plan.classify_live_preview(&unsupported),
            Err(LiveGwsPreviewError::UnsupportedPreviewRoute { .. })
        ));
    }
}
