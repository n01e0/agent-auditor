use super::contract::{GwsSemanticSurface, GwsSignalSource, SessionLinkageBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLinkagePlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SessionLinkageBoundary,
}

impl Default for SessionLinkagePlan {
    fn default() -> Self {
        Self {
            sources: vec![
                GwsSignalSource::ApiObservation,
                GwsSignalSource::NetworkObservation,
            ],
            semantic_surfaces: vec![
                GwsSemanticSurface::GoogleWorkspace,
                GwsSemanticSurface::GoogleWorkspaceDrive,
                GwsSemanticSurface::GoogleWorkspaceGmail,
                GwsSemanticSurface::GoogleWorkspaceAdmin,
            ],
            linkage_fields: vec![
                "source_kind",
                "request_id",
                "transport",
                "authority_hint",
                "method_hint",
                "path_hint",
                "destination_ip",
                "destination_port",
                "semantic_surface_hint",
                "session_id",
                "agent_id",
                "workspace_id",
                "linkage_reason",
            ],
            responsibilities: vec![
                "accept API and network-originated GWS action hints from request adapters and egress observation",
                "link API and network context to the same session identity used by runtime hostd events",
                "preserve request-owned context and GWS surface hints without deciding the final semantic action taxonomy",
                "handoff session-linked API/network action candidates downstream without normalizing agenta-core events or evaluating policy",
            ],
            stages: vec!["ingest", "session_correlate", "surface_hint", "handoff"],
            handoff: SessionLinkageBoundary {
                sources: vec![
                    GwsSignalSource::ApiObservation,
                    GwsSignalSource::NetworkObservation,
                ],
                semantic_surfaces: vec![
                    GwsSemanticSurface::GoogleWorkspace,
                    GwsSemanticSurface::GoogleWorkspaceDrive,
                    GwsSemanticSurface::GoogleWorkspaceGmail,
                    GwsSemanticSurface::GoogleWorkspaceAdmin,
                ],
                linkage_fields: vec![
                    "source_kind",
                    "request_id",
                    "transport",
                    "authority_hint",
                    "method_hint",
                    "path_hint",
                    "destination_ip",
                    "destination_port",
                    "semantic_surface_hint",
                    "session_id",
                    "agent_id",
                    "workspace_id",
                    "linkage_reason",
                ],
                redaction_contract: "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary",
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
    use crate::poc::gws::contract::{GwsSemanticSurface, GwsSignalSource};

    #[test]
    fn session_linkage_plan_exposes_gws_sources_and_surfaces() {
        let plan = SessionLinkagePlan::default();

        assert_eq!(
            plan.sources,
            vec![
                GwsSignalSource::ApiObservation,
                GwsSignalSource::NetworkObservation,
            ]
        );
        assert_eq!(
            plan.semantic_surfaces,
            vec![
                GwsSemanticSurface::GoogleWorkspace,
                GwsSemanticSurface::GoogleWorkspaceDrive,
                GwsSemanticSurface::GoogleWorkspaceGmail,
                GwsSemanticSurface::GoogleWorkspaceAdmin,
            ]
        );
        assert_eq!(
            plan.linkage_fields,
            vec![
                "source_kind",
                "request_id",
                "transport",
                "authority_hint",
                "method_hint",
                "path_hint",
                "destination_ip",
                "destination_port",
                "semantic_surface_hint",
                "session_id",
                "agent_id",
                "workspace_id",
                "linkage_reason",
            ]
        );
    }

    #[test]
    fn session_linkage_boundary_carries_the_gws_redaction_contract() {
        let handoff = SessionLinkagePlan::default().handoff();

        assert_eq!(
            handoff.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
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

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("surfaces=gws,gws.drive,gws.gmail,gws.admin"));
        assert!(summary.contains("stages=ingest->session_correlate->surface_hint->handoff"));
    }
}
