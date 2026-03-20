use agenta_core::{SessionRecord, SessionRef};

use super::contract::{
    ApiRequestObservation, GwsActionSignal, GwsSemanticSurface, GwsSignalSource,
    NetworkRequestObservation, SessionLinkageBoundary, SessionLinkedGwsAction,
};

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

    pub fn link_signal(
        &self,
        signal: &GwsActionSignal,
        session: &SessionRecord,
    ) -> SessionLinkedGwsAction {
        match signal {
            GwsActionSignal::Api(observation) => self.link_api_observation(observation, session),
            GwsActionSignal::Network(observation) => {
                self.link_network_observation(observation, session)
            }
        }
    }

    pub fn link_api_observation(
        &self,
        observation: &ApiRequestObservation,
        session: &SessionRecord,
    ) -> SessionLinkedGwsAction {
        SessionLinkedGwsAction {
            source: GwsSignalSource::ApiObservation,
            request_id: observation.request_id.clone(),
            transport: observation.transport.clone(),
            authority_hint: Some(observation.authority_hint.clone()),
            method_hint: Some(observation.method_hint.clone()),
            path_hint: Some(observation.path_hint.clone()),
            destination_ip: None,
            destination_port: None,
            semantic_surface_hint: observation.semantic_surface_hint,
            session: session_ref_from_record(session),
            linkage_reason: "request adapter supplied session-owned API metadata".to_owned(),
        }
    }

    pub fn link_network_observation(
        &self,
        observation: &NetworkRequestObservation,
        session: &SessionRecord,
    ) -> SessionLinkedGwsAction {
        SessionLinkedGwsAction {
            source: GwsSignalSource::NetworkObservation,
            request_id: observation
                .request_id
                .clone()
                .unwrap_or_else(|| derived_network_request_id(observation, session)),
            transport: observation.transport.clone(),
            authority_hint: observation.authority_hint.clone(),
            method_hint: observation.method_hint.clone(),
            path_hint: observation.path_hint.clone(),
            destination_ip: Some(observation.destination_ip.clone()),
            destination_port: Some(observation.destination_port),
            semantic_surface_hint: observation.semantic_surface_hint,
            session: session_ref_from_record(session),
            linkage_reason: if observation.request_id.is_some() {
                "network observation carried a request adapter correlation id into the session seam"
                    .to_owned()
            } else {
                "network observation linked session identity from session-scoped GWS egress metadata"
                    .to_owned()
            },
        }
    }

    pub fn preview_session_linked_api_action(
        &self,
        session: &SessionRecord,
    ) -> SessionLinkedGwsAction {
        self.link_api_observation(
            &ApiRequestObservation::preview_drive_permissions_update(),
            session,
        )
    }

    pub fn preview_session_linked_network_action(
        &self,
        session: &SessionRecord,
    ) -> SessionLinkedGwsAction {
        self.link_network_observation(
            &NetworkRequestObservation::preview_drive_api_connect(),
            session,
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
            "sources={} surfaces={} linkage_fields={} stages={}",
            sources,
            surfaces,
            self.linkage_fields.join(","),
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

fn derived_network_request_id(
    observation: &NetworkRequestObservation,
    session: &SessionRecord,
) -> String {
    format!(
        "req_{}_{}_{}",
        sanitize_id_segment(&session.session_id),
        sanitize_id_segment(&observation.destination_ip),
        observation.destination_port,
    )
}

fn sanitize_id_segment(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use agenta_core::{SessionRecord, SessionWorkspace};

    use super::SessionLinkagePlan;
    use crate::poc::gws::contract::{
        ApiRequestObservation, GwsActionSignal, GwsSemanticSurface, GwsSignalSource,
        NetworkRequestObservation,
    };

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
    fn session_linkage_plan_links_api_observation_to_runtime_session_identity() {
        let plan = SessionLinkagePlan::default();
        let session = fixture_session();

        let linked = plan.link_api_observation(
            &ApiRequestObservation::preview_drive_permissions_update(),
            &session,
        );

        assert_eq!(linked.source, GwsSignalSource::ApiObservation);
        assert_eq!(linked.request_id, "req_drive_permissions_update_preview");
        assert_eq!(linked.transport, "https");
        assert_eq!(linked.authority_hint.as_deref(), Some("www.googleapis.com"));
        assert_eq!(linked.method_hint.as_deref(), Some("PATCH"));
        assert_eq!(
            linked.path_hint.as_deref(),
            Some("/drive/v3/files/abc123/permissions/perm456")
        );
        assert_eq!(linked.destination_ip, None);
        assert_eq!(linked.destination_port, None);
        assert_eq!(
            linked.semantic_surface_hint,
            GwsSemanticSurface::GoogleWorkspaceDrive
        );
        assert_eq!(linked.session.session_id, session.session_id);
        assert_eq!(linked.session.agent_id.as_deref(), Some("openclaw-main"));
        assert_eq!(
            linked.session.workspace_id.as_deref(),
            Some("ws_gws_preview")
        );
        assert_eq!(
            linked.linkage_reason,
            "request adapter supplied session-owned API metadata"
        );
        assert!(linked.log_line().contains("event=gws.session_linked"));
    }

    #[test]
    fn session_linkage_plan_links_network_observation_even_without_request_id() {
        let plan = SessionLinkagePlan::default();
        let session = fixture_session();

        let linked = plan.link_network_observation(
            &NetworkRequestObservation::preview_drive_api_connect(),
            &session,
        );

        assert_eq!(linked.source, GwsSignalSource::NetworkObservation);
        assert_eq!(
            linked.request_id,
            "req_sess_gws_preview_142_250_191_138_443"
        );
        assert_eq!(linked.transport, "tcp");
        assert_eq!(linked.authority_hint.as_deref(), Some("www.googleapis.com"));
        assert_eq!(linked.method_hint.as_deref(), Some("PATCH"));
        assert_eq!(
            linked.path_hint.as_deref(),
            Some("/drive/v3/files/abc123/permissions/perm456")
        );
        assert_eq!(linked.destination_ip.as_deref(), Some("142.250.191.138"));
        assert_eq!(linked.destination_port, Some(443));
        assert_eq!(
            linked.semantic_surface_hint,
            GwsSemanticSurface::GoogleWorkspaceDrive
        );
        assert_eq!(linked.session.session_id, session.session_id);
        assert_eq!(
            linked.linkage_reason,
            "network observation linked session identity from session-scoped GWS egress metadata"
        );
    }

    #[test]
    fn session_linkage_signal_routes_api_and_network_variants() {
        let plan = SessionLinkagePlan::default();
        let session = fixture_session();

        let api = plan.link_signal(
            &GwsActionSignal::Api(ApiRequestObservation::preview_drive_permissions_update()),
            &session,
        );
        let network = plan.link_signal(
            &GwsActionSignal::Network(NetworkRequestObservation::preview_drive_api_connect()),
            &session,
        );

        assert_eq!(api.source, GwsSignalSource::ApiObservation);
        assert_eq!(network.source, GwsSignalSource::NetworkObservation);
    }

    #[test]
    fn session_linkage_summary_mentions_surfaces_and_stages() {
        let summary = SessionLinkagePlan::default().summary();

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("surfaces=gws,gws.drive,gws.gmail,gws.admin"));
        assert!(summary.contains("stages=ingest->session_correlate->surface_hint->handoff"));
    }

    fn fixture_session() -> SessionRecord {
        let mut session = SessionRecord::placeholder("openclaw-main", "sess_gws_preview");
        session.initiator_id = Some("user:demo".to_owned());
        session.policy_bundle_version = Some("bundle-test".to_owned());
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("ws_gws_preview".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
