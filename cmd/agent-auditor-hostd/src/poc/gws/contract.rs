use std::fmt;

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
