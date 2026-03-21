use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{
    ClassificationBoundary, ClassifiedGwsAction, GwsSemanticSurface, GwsSignalSource,
    RecordBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatePlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: RecordBoundary,
}

impl EvaluatePlan {
    pub fn from_classification_boundary(boundary: ClassificationBoundary) -> Self {
        Self {
            sources: boundary.sources.clone(),
            semantic_surfaces: boundary.semantic_surfaces.clone(),
            linkage_fields: boundary.linkage_fields,
            classification_fields: boundary.classification_fields,
            responsibilities: vec![
                "normalize classified GWS semantic action candidates toward agenta-core event shapes with the shared provider contract as the primary identity",
                "bridge normalized GWS semantic actions into agenta-policy without re-linking sessions or re-running semantic classification",
                "project allow, deny, and require_approval outcomes plus approval-request candidates for recording",
                "carry the GWS redaction contract forward so downstream audit never needs raw HTTP payloads or document or message content",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: RecordBoundary {
                sources: boundary.sources,
                semantic_surfaces: boundary.semantic_surfaces,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: boundary.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        self.handoff.clone()
    }

    pub fn normalize_classified_action(
        &self,
        action: &ClassifiedGwsAction,
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

        if let Some(path_hint) = &action.path_hint {
            attributes.insert("path_hint".to_owned(), json!(path_hint));
        }

        if let Some(destination_ip) = &action.destination_ip {
            attributes.insert("destination_ip".to_owned(), json!(destination_ip));
        }

        if let Some(destination_port) = action.destination_port {
            attributes.insert("destination_port".to_owned(), json!(destination_port));
        }

        EventEnvelope::new(
            format!(
                "poc_gws_action_{}_{}_{}",
                action.source,
                action.semantic_action,
                sanitize_id_segment(&action.request_id)
            ),
            EventType::GwsAction,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Gws,
                verb: Some(action.provider_action.action_key.to_string()),
                target: Some(action.provider_action.target_hint().to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd API/network GWS PoC".to_owned()),
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
            "sources={} surfaces={} linkage_fields={} classification_fields={} stages={}",
            sources,
            surfaces,
            self.linkage_fields.join(","),
            self.classification_fields.join(","),
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

fn source_info(source: GwsSignalSource) -> SourceInfo {
    SourceInfo {
        collector: collector_for_source(source),
        host_id: Some("hostd-poc".to_owned()),
        container_id: None,
        pod_uid: None,
        pid: None,
        ppid: None,
    }
}

fn collector_for_source(source: GwsSignalSource) -> CollectorKind {
    match source {
        GwsSignalSource::ApiObservation => CollectorKind::RuntimeHint,
        GwsSignalSource::NetworkObservation => CollectorKind::Ebpf,
    }
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
    use serde_json::json;

    use super::EvaluatePlan;
    use crate::poc::gws::{
        classify::ClassifyPlan,
        contract::{GwsActionKind, GwsSemanticSurface, GwsSignalSource},
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn evaluate_plan_threads_gws_surfaces_and_upstream_fields() {
        let plan = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff(),
        );

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
        assert!(plan.linkage_fields.contains(&"session_id"));
        assert!(plan.classification_fields.contains(&"provider_id"));
        assert!(plan.classification_fields.contains(&"action_key"));
        assert!(
            plan.classification_fields
                .contains(&"semantic_action_label")
        );
    }

    #[test]
    fn evaluate_handoff_prepares_record_stage_inputs() {
        let handoff = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff(),
        )
        .handoff();

        assert_eq!(
            handoff.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            handoff.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn normalize_api_classified_action_uses_agenta_core_gws_shape() {
        let classify =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let linked = SessionLinkagePlan::default().link_api_observation(
            &crate::poc::gws::contract::ApiRequestObservation::preview_drive_permissions_update(),
            &fixture_session(),
        );
        let classified = classify
            .classify_action(&linked)
            .expect("drive permissions update should classify");
        let session = fixture_session();

        let envelope = evaluate.normalize_classified_action(&classified, &session);

        assert_eq!(
            envelope.event_id,
            "poc_gws_action_api_observation_drive.permissions.update_req_drive_permissions_update_preview"
        );
        assert_eq!(envelope.event_type, EventType::GwsAction);
        assert_eq!(envelope.session.session_id, "sess_gws_evaluate");
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Gws);
        assert_eq!(
            envelope.action.verb.as_deref(),
            Some("drive.permissions.update")
        );
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("drive.files/abc123/permissions/perm456")
        );
        assert_eq!(
            envelope.action.attributes.get("source_kind"),
            Some(&json!("api_observation"))
        );
        assert_eq!(
            envelope.action.attributes.get("request_id"),
            Some(&json!("req_drive_permissions_update_preview"))
        );
        assert_eq!(
            envelope.action.attributes.get("semantic_surface"),
            Some(&json!("gws.drive"))
        );
        assert_eq!(
            envelope.action.attributes.get("provider_id"),
            Some(&json!("gws"))
        );
        assert_eq!(
            envelope.action.attributes.get("action_key"),
            Some(&json!("drive.permissions.update"))
        );
        assert_eq!(
            envelope.action.attributes.get("provider_action_id"),
            Some(&json!("gws:drive.permissions.update"))
        );
        assert_eq!(
            envelope.action.attributes.get("semantic_action_label"),
            Some(&json!("drive.permissions.update"))
        );
        assert_eq!(
            envelope.action.attributes.get("classifier_labels"),
            Some(&json!(["gws.drive", "drive.permissions.update"]))
        );
        assert_eq!(
            envelope.action.attributes.get("content_retained"),
            Some(&json!(false))
        );
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(
            envelope.result.reason.as_deref(),
            Some("observed by hostd API/network GWS PoC")
        );
        assert_eq!(envelope.source.collector, CollectorKind::RuntimeHint);
        assert_eq!(envelope.source.pid, None);
    }

    #[test]
    fn normalize_network_classified_action_preserves_network_hints() {
        let classify =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let linked = SessionLinkagePlan::default().link_network_observation(
            &crate::poc::gws::contract::NetworkRequestObservation::preview_drive_files_get_media(),
            &fixture_session(),
        );
        let classified = classify
            .classify_action(&linked)
            .expect("drive files get_media should classify");
        let session = fixture_session();

        let envelope = evaluate.normalize_classified_action(&classified, &session);

        assert_eq!(envelope.event_type, EventType::GwsAction);
        assert_eq!(envelope.action.class, ActionClass::Gws);
        assert_eq!(
            envelope.action.verb.as_deref(),
            Some("drive.files.get_media")
        );
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("drive.files/abc123")
        );
        assert_eq!(
            envelope.action.attributes.get("destination_ip"),
            Some(&json!("142.250.191.139"))
        );
        assert_eq!(
            envelope.action.attributes.get("destination_port"),
            Some(&json!(443))
        );
        assert_eq!(
            envelope.action.attributes.get("provider_id"),
            Some(&json!("gws"))
        );
        assert_eq!(
            envelope.action.attributes.get("action_key"),
            Some(&json!("drive.files.get_media"))
        );
        assert_eq!(
            envelope.action.attributes.get("semantic_action_label"),
            Some(&json!("drive.files.get_media"))
        );
        assert_eq!(
            envelope.action.attributes.get("classifier_reasons"),
            Some(&json!([
                "GET drive files path with alt=media maps to Drive content download"
            ]))
        );
        assert_eq!(envelope.source.collector, CollectorKind::Ebpf);
    }

    #[test]
    fn normalize_gmail_and_admin_classified_actions_keep_supported_labels() {
        let classify =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let session = fixture_session();

        let gmail_classified = classify
            .classify_action(&SessionLinkagePlan::default().link_api_observation(
                &crate::poc::gws::contract::ApiRequestObservation::preview_gmail_users_messages_send(),
                &session,
            ))
            .expect("gmail send should classify");
        let admin_classified = classify
            .classify_action(&SessionLinkagePlan::default().link_api_observation(
                &crate::poc::gws::contract::ApiRequestObservation::preview_admin_reports_activities_list(),
                &session,
            ))
            .expect("admin reports list should classify");

        let gmail = evaluate.normalize_classified_action(&gmail_classified, &session);
        let admin = evaluate.normalize_classified_action(&admin_classified, &session);

        assert_eq!(gmail.event_type, EventType::GwsAction);
        assert_eq!(admin.event_type, EventType::GwsAction);
        assert_eq!(gmail.action.class, ActionClass::Gws);
        assert_eq!(admin.action.class, ActionClass::Gws);
        assert_eq!(
            gmail.action.attributes.get("provider_id"),
            Some(&json!("gws"))
        );
        assert_eq!(
            admin.action.attributes.get("provider_id"),
            Some(&json!("gws"))
        );
        assert_eq!(
            gmail.action.attributes.get("action_key"),
            Some(&json!(GwsActionKind::GmailUsersMessagesSend.to_string()))
        );
        assert_eq!(
            gmail.action.attributes.get("semantic_action_label"),
            Some(&json!(GwsActionKind::GmailUsersMessagesSend.to_string()))
        );
        assert_eq!(
            admin.action.attributes.get("action_key"),
            Some(&json!(
                GwsActionKind::AdminReportsActivitiesList.to_string()
            ))
        );
        assert_eq!(
            admin.action.attributes.get("semantic_action_label"),
            Some(&json!(
                GwsActionKind::AdminReportsActivitiesList.to_string()
            ))
        );
        assert_eq!(
            gmail.action.attributes.get("semantic_surface"),
            Some(&json!(GwsSemanticSurface::GoogleWorkspaceGmail.to_string()))
        );
        assert_eq!(
            admin.action.attributes.get("semantic_surface"),
            Some(&json!(GwsSemanticSurface::GoogleWorkspaceAdmin.to_string()))
        );
    }

    #[test]
    fn evaluate_summary_mentions_policy_projection_stages() {
        let summary = EvaluatePlan::from_classification_boundary(
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff(),
        )
        .summary();

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("stages=normalize->policy->approval_projection"));
        assert!(summary.contains("classification_fields=semantic_surface,provider_id,action_key,semantic_action_label,target_hint,classifier_labels,classifier_reasons,content_retained"));
    }

    fn fixture_session() -> SessionRecord {
        let mut session = SessionRecord::placeholder("openclaw-main", "sess_gws_evaluate");
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("ws_gws_evaluate".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
