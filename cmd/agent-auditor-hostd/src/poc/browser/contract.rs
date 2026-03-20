use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSignalSource {
    ExtensionRelay,
    AutomationBridge,
}

impl fmt::Display for BrowserSignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ExtensionRelay => "extension_relay",
            Self::AutomationBridge => "automation_bridge",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSemanticSurface {
    Browser,
    GoogleWorkspaceDrive,
    GoogleWorkspaceGmail,
    GoogleWorkspaceAdmin,
}

impl BrowserSemanticSurface {
    pub fn label(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::GoogleWorkspaceDrive => "gws.drive",
            Self::GoogleWorkspaceGmail => "gws.gmail",
            Self::GoogleWorkspaceAdmin => "gws.admin",
        }
    }
}

impl fmt::Display for BrowserSemanticSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLinkageBoundary {
    pub sources: Vec<BrowserSignalSource>,
    pub semantic_surfaces: Vec<BrowserSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationBoundary {
    pub sources: Vec<BrowserSignalSource>,
    pub semantic_surfaces: Vec<BrowserSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub sources: Vec<BrowserSignalSource>,
    pub semantic_surfaces: Vec<BrowserSemanticSurface>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}
