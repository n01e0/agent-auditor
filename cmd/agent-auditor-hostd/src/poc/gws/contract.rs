use std::fmt;

use agenta_core::SessionRef;

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
