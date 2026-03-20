use super::contract::{BrowserSemanticSurface, BrowserSignalSource, SessionLinkageBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLinkagePlan {
    pub sources: Vec<BrowserSignalSource>,
    pub semantic_surfaces: Vec<BrowserSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SessionLinkageBoundary,
}

impl Default for SessionLinkagePlan {
    fn default() -> Self {
        Self {
            sources: vec![
                BrowserSignalSource::ExtensionRelay,
                BrowserSignalSource::AutomationBridge,
            ],
            semantic_surfaces: vec![
                BrowserSemanticSurface::Browser,
                BrowserSemanticSurface::GoogleWorkspaceDrive,
                BrowserSemanticSurface::GoogleWorkspaceGmail,
                BrowserSemanticSurface::GoogleWorkspaceAdmin,
            ],
            linkage_fields: vec![
                "source_kind",
                "browser_session_id",
                "tab_id",
                "frame_id",
                "document_url",
                "document_title",
                "top_level_origin",
                "semantic_surface_hint",
                "session_id",
                "agent_id",
                "workspace_id",
                "linkage_reason",
            ],
            responsibilities: vec![
                "accept browser-originated action hints from relay and automation surfaces",
                "link browser context to the same session identity used by runtime hostd events",
                "preserve browser-owned context and semantic-surface hints without deciding the final semantic action taxonomy",
                "handoff session-linked browser action candidates downstream without normalizing agenta-core events or evaluating policy",
            ],
            stages: vec!["ingest", "session_correlate", "surface_hint", "handoff"],
            handoff: SessionLinkageBoundary {
                sources: vec![
                    BrowserSignalSource::ExtensionRelay,
                    BrowserSignalSource::AutomationBridge,
                ],
                semantic_surfaces: vec![
                    BrowserSemanticSurface::Browser,
                    BrowserSemanticSurface::GoogleWorkspaceDrive,
                    BrowserSemanticSurface::GoogleWorkspaceGmail,
                    BrowserSemanticSurface::GoogleWorkspaceAdmin,
                ],
                linkage_fields: vec![
                    "source_kind",
                    "browser_session_id",
                    "tab_id",
                    "frame_id",
                    "document_url",
                    "document_title",
                    "top_level_origin",
                    "semantic_surface_hint",
                    "session_id",
                    "agent_id",
                    "workspace_id",
                    "linkage_reason",
                ],
                redaction_contract: "raw page bodies, email bodies, and document contents must not cross the browser linkage boundary",
            },
        }
    }
}

impl SessionLinkagePlan {
    pub fn handoff(&self) -> SessionLinkageBoundary {
        self.handoff.clone()
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
            "sources={} surfaces={} linkage_fields={} stages={}",
            sources,
            surfaces,
            self.linkage_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SessionLinkagePlan;
    use crate::poc::browser::contract::{BrowserSemanticSurface, BrowserSignalSource};

    #[test]
    fn session_linkage_plan_exposes_browser_sources_and_surfaces() {
        let plan = SessionLinkagePlan::default();

        assert_eq!(
            plan.sources,
            vec![
                BrowserSignalSource::ExtensionRelay,
                BrowserSignalSource::AutomationBridge,
            ]
        );
        assert_eq!(
            plan.semantic_surfaces,
            vec![
                BrowserSemanticSurface::Browser,
                BrowserSemanticSurface::GoogleWorkspaceDrive,
                BrowserSemanticSurface::GoogleWorkspaceGmail,
                BrowserSemanticSurface::GoogleWorkspaceAdmin,
            ]
        );
        assert_eq!(
            plan.linkage_fields,
            vec![
                "source_kind",
                "browser_session_id",
                "tab_id",
                "frame_id",
                "document_url",
                "document_title",
                "top_level_origin",
                "semantic_surface_hint",
                "session_id",
                "agent_id",
                "workspace_id",
                "linkage_reason",
            ]
        );
    }

    #[test]
    fn session_linkage_boundary_carries_the_browser_redaction_contract() {
        let handoff = SessionLinkagePlan::default().handoff();

        assert_eq!(
            handoff.redaction_contract,
            "raw page bodies, email bodies, and document contents must not cross the browser linkage boundary"
        );
        assert_eq!(handoff.linkage_fields[0], "source_kind");
        assert_eq!(
            handoff.linkage_fields[handoff.linkage_fields.len() - 1],
            "linkage_reason"
        );
    }

    #[test]
    fn session_linkage_summary_mentions_surfaces_and_stages() {
        let summary = SessionLinkagePlan::default().summary();

        assert!(summary.contains("sources=extension_relay,automation_bridge"));
        assert!(summary.contains("surfaces=browser,gws.drive,gws.gmail,gws.admin"));
        assert!(summary.contains("stages=ingest->session_correlate->surface_hint->handoff"));
    }
}
