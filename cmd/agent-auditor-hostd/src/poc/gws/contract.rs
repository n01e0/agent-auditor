use std::fmt;

use agenta_core::{
    SessionRef,
    provider::{ActionKey, ProviderActionId, ProviderId, ProviderSemanticAction},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsSignalSource {
    ApiObservation,
    NetworkObservation,
}

impl fmt::Display for GwsSignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ApiObservation => "api_observation",
            Self::NetworkObservation => "network_observation",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsSemanticSurface {
    GoogleWorkspace,
    GoogleWorkspaceDrive,
    GoogleWorkspaceGmail,
    GoogleWorkspaceAdmin,
}

impl GwsSemanticSurface {
    pub fn label(self) -> &'static str {
        match self {
            Self::GoogleWorkspace => "gws",
            Self::GoogleWorkspaceDrive => "gws.drive",
            Self::GoogleWorkspaceGmail => "gws.gmail",
            Self::GoogleWorkspaceAdmin => "gws.admin",
        }
    }
}

impl fmt::Display for GwsSemanticSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsActionKind {
    DrivePermissionsUpdate,
    DriveFilesGetMedia,
    GmailUsersMessagesSend,
    AdminReportsActivitiesList,
}

impl GwsActionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::DrivePermissionsUpdate => "drive.permissions.update",
            Self::DriveFilesGetMedia => "drive.files.get_media",
            Self::GmailUsersMessagesSend => "gmail.users.messages.send",
            Self::AdminReportsActivitiesList => "admin.reports.activities.list",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "drive.permissions.update" => Some(Self::DrivePermissionsUpdate),
            "drive.files.get_media" => Some(Self::DriveFilesGetMedia),
            "gmail.users.messages.send" => Some(Self::GmailUsersMessagesSend),
            "admin.reports.activities.list" => Some(Self::AdminReportsActivitiesList),
            _ => None,
        }
    }

    pub fn surface(self) -> GwsSemanticSurface {
        match self {
            Self::DrivePermissionsUpdate | Self::DriveFilesGetMedia => {
                GwsSemanticSurface::GoogleWorkspaceDrive
            }
            Self::GmailUsersMessagesSend => GwsSemanticSurface::GoogleWorkspaceGmail,
            Self::AdminReportsActivitiesList => GwsSemanticSurface::GoogleWorkspaceAdmin,
        }
    }

    pub fn provider_id(self) -> ProviderId {
        ProviderId::gws()
    }

    pub fn action_key(self) -> ActionKey {
        ActionKey::new(self.label()).expect("GWS action labels must be valid provider action keys")
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
        if action.provider_id != ProviderId::gws() {
            return None;
        }

        Self::from_label(action.action_key.as_str())
    }

    pub fn classifier_labels(self) -> Vec<&'static str> {
        vec![self.surface().label(), self.label()]
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::DrivePermissionsUpdate => {
                "PATCH drive permissions path maps to Drive sharing updates"
            }
            Self::DriveFilesGetMedia => {
                "GET drive files path with alt=media maps to Drive content download"
            }
            Self::GmailUsersMessagesSend => "POST Gmail send path maps to outbound message send",
            Self::AdminReportsActivitiesList => {
                "GET Admin Reports activity path maps to activity-list retrieval"
            }
        }
    }
}

impl fmt::Display for GwsActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequestObservation {
    pub request_id: String,
    pub transport: String,
    pub authority_hint: String,
    pub method_hint: String,
    pub path_hint: String,
    pub semantic_surface_hint: GwsSemanticSurface,
}

impl ApiRequestObservation {
    pub fn preview_drive_permissions_update() -> Self {
        Self {
            request_id: "req_drive_permissions_update_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: "www.googleapis.com".to_owned(),
            method_hint: "PATCH".to_owned(),
            path_hint: "/drive/v3/files/abc123/permissions/perm456".to_owned(),
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceDrive,
        }
    }

    pub fn preview_drive_files_get_media() -> Self {
        Self {
            request_id: "req_drive_files_get_media_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: "www.googleapis.com".to_owned(),
            method_hint: "GET".to_owned(),
            path_hint: "/drive/v3/files/abc123?alt=media".to_owned(),
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceDrive,
        }
    }

    pub fn preview_gmail_users_messages_send() -> Self {
        Self {
            request_id: "req_gmail_users_messages_send_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: "gmail.googleapis.com".to_owned(),
            method_hint: "POST".to_owned(),
            path_hint: "/gmail/v1/users/me/messages/send".to_owned(),
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceGmail,
        }
    }

    pub fn preview_admin_reports_activities_list() -> Self {
        Self {
            request_id: "req_admin_reports_activities_list_preview".to_owned(),
            transport: "https".to_owned(),
            authority_hint: "admin.googleapis.com".to_owned(),
            method_hint: "GET".to_owned(),
            path_hint: "/admin/reports/v1/activity/users/all/applications/drive".to_owned(),
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceAdmin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRequestObservation {
    pub request_id: Option<String>,
    pub transport: String,
    pub authority_hint: Option<String>,
    pub method_hint: Option<String>,
    pub path_hint: Option<String>,
    pub destination_ip: String,
    pub destination_port: u16,
    pub semantic_surface_hint: GwsSemanticSurface,
}

impl NetworkRequestObservation {
    pub fn preview_drive_api_connect() -> Self {
        Self {
            request_id: None,
            transport: "tcp".to_owned(),
            authority_hint: Some("www.googleapis.com".to_owned()),
            method_hint: Some("PATCH".to_owned()),
            path_hint: Some("/drive/v3/files/abc123/permissions/perm456".to_owned()),
            destination_ip: "142.250.191.138".to_owned(),
            destination_port: 443,
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceDrive,
        }
    }

    pub fn preview_drive_files_get_media() -> Self {
        Self {
            request_id: None,
            transport: "tcp".to_owned(),
            authority_hint: Some("www.googleapis.com".to_owned()),
            method_hint: Some("GET".to_owned()),
            path_hint: Some("/drive/v3/files/abc123?alt=media".to_owned()),
            destination_ip: "142.250.191.139".to_owned(),
            destination_port: 443,
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceDrive,
        }
    }

    pub fn preview_gmail_users_messages_send() -> Self {
        Self {
            request_id: None,
            transport: "tcp".to_owned(),
            authority_hint: Some("gmail.googleapis.com".to_owned()),
            method_hint: Some("POST".to_owned()),
            path_hint: Some("/gmail/v1/users/me/messages/send".to_owned()),
            destination_ip: "142.250.191.140".to_owned(),
            destination_port: 443,
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceGmail,
        }
    }

    pub fn preview_admin_reports_activities_list() -> Self {
        Self {
            request_id: None,
            transport: "tcp".to_owned(),
            authority_hint: Some("admin.googleapis.com".to_owned()),
            method_hint: Some("GET".to_owned()),
            path_hint: Some("/admin/reports/v1/activity/users/all/applications/drive".to_owned()),
            destination_ip: "142.250.191.141".to_owned(),
            destination_port: 443,
            semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceAdmin,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GwsActionSignal {
    Api(ApiRequestObservation),
    Network(NetworkRequestObservation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLinkedGwsAction {
    pub source: GwsSignalSource,
    pub request_id: String,
    pub transport: String,
    pub authority_hint: Option<String>,
    pub method_hint: Option<String>,
    pub path_hint: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub semantic_surface_hint: GwsSemanticSurface,
    pub session: SessionRef,
    pub linkage_reason: String,
}

impl SessionLinkedGwsAction {
    pub fn log_line(&self) -> String {
        format!(
            "event=gws.session_linked source={} request_id={} transport={} authority_hint={} method_hint={} path_hint={} destination_ip={} destination_port={} semantic_surface_hint={} session_id={} agent_id={} workspace_id={} linkage_reason={}",
            self.source,
            self.request_id,
            self.transport,
            self.authority_hint.as_deref().unwrap_or("-"),
            self.method_hint.as_deref().unwrap_or("-"),
            self.path_hint.as_deref().unwrap_or("-"),
            self.destination_ip.as_deref().unwrap_or("-"),
            self.destination_port
                .map(|port| port.to_string())
                .as_deref()
                .unwrap_or("-"),
            self.semantic_surface_hint,
            self.session.session_id,
            self.session.agent_id.as_deref().unwrap_or("-"),
            self.session.workspace_id.as_deref().unwrap_or("-"),
            self.linkage_reason,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedGwsAction {
    pub source: GwsSignalSource,
    pub request_id: String,
    pub transport: String,
    pub authority_hint: Option<String>,
    pub method_hint: Option<String>,
    pub path_hint: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub semantic_surface: GwsSemanticSurface,
    pub semantic_action: GwsActionKind,
    pub provider_action: ProviderSemanticAction,
    pub target_hint: String,
    pub classifier_labels: Vec<&'static str>,
    pub classifier_reasons: Vec<&'static str>,
    pub content_retained: bool,
}

impl ClassifiedGwsAction {
    pub fn provider_action_id(&self) -> ProviderActionId {
        self.provider_action.id()
    }

    pub fn log_line(&self) -> String {
        format!(
            "event=gws.classified source={} request_id={} semantic_surface={} semantic_action={} provider_action_id={} target_hint={} content_retained={}",
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
pub struct SessionLinkageBoundary {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationBoundary {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[cfg(test)]
mod tests {
    use agenta_core::provider::ProviderId;

    use super::GwsActionKind;

    #[test]
    fn gws_action_kind_maps_onto_shared_provider_contract() {
        let action = GwsActionKind::DrivePermissionsUpdate;
        let provider_action =
            action.provider_semantic_action("drive.files/abc123/permissions/perm456");

        assert_eq!(provider_action.provider_id, ProviderId::gws());
        assert_eq!(
            provider_action.action_key.as_str(),
            "drive.permissions.update"
        );
        assert_eq!(
            provider_action.target_hint(),
            "drive.files/abc123/permissions/perm456"
        );
        assert_eq!(
            action.provider_action_id().to_string(),
            "gws:drive.permissions.update"
        );
        assert_eq!(
            GwsActionKind::from_provider_action_id(&action.provider_action_id()),
            Some(action)
        );
    }

    #[test]
    fn gws_action_kind_rejects_non_gws_provider_contract_identity() {
        let github_action =
            agenta_core::provider::ProviderActionId::from_parts("github", "repos.contents.get")
                .unwrap();

        assert_eq!(GwsActionKind::from_provider_action_id(&github_action), None);
    }
}
