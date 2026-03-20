use super::contract::{
    ClassificationBoundary, ClassifiedGwsAction, GwsActionKind, GwsSemanticSurface,
    GwsSignalSource, SessionLinkageBoundary, SessionLinkedGwsAction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub sources: Vec<GwsSignalSource>,
    pub semantic_surfaces: Vec<GwsSemanticSurface>,
    pub linkage_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub semantic_actions: Vec<GwsActionKind>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ClassificationBoundary,
}

impl ClassifyPlan {
    pub fn from_session_linkage_boundary(boundary: SessionLinkageBoundary) -> Self {
        Self {
            sources: boundary.sources.clone(),
            semantic_surfaces: boundary.semantic_surfaces.clone(),
            linkage_fields: boundary.linkage_fields.clone(),
            classification_fields: vec![
                "semantic_surface",
                "semantic_action_label",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ],
            semantic_actions: vec![
                GwsActionKind::DrivePermissionsUpdate,
                GwsActionKind::DriveFilesGetMedia,
                GwsActionKind::GmailUsersMessagesSend,
                GwsActionKind::AdminReportsActivitiesList,
            ],
            responsibilities: vec![
                "accept session-linked API/network action candidates without reopening session identity resolution",
                "classify GWS request and network context into semantic action candidates and target hints",
                "identify at least drive.permissions.update, drive.files.get_media, gmail.users.messages.send, and admin.reports.activities.list semantics from redaction-safe request hints",
                "attach classifier-owned labels and rationale without retaining raw HTTP payloads or document or message content",
                "handoff classified semantic actions downstream without normalizing agenta-core events or writing durable records",
            ],
            stages: vec!["service_map", "taxonomy", "label", "handoff"],
            handoff: ClassificationBoundary {
                sources: boundary.sources,
                semantic_surfaces: boundary.semantic_surfaces,
                linkage_fields: boundary.linkage_fields,
                classification_fields: vec![
                    "semantic_surface",
                    "semantic_action_label",
                    "target_hint",
                    "classifier_labels",
                    "classifier_reasons",
                    "content_retained",
                ],
                redaction_contract: boundary.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> ClassificationBoundary {
        self.handoff.clone()
    }

    pub fn classify_action(&self, action: &SessionLinkedGwsAction) -> Option<ClassifiedGwsAction> {
        let method = action.method_hint.as_deref()?;
        let path = action.path_hint.as_deref()?;
        let normalized_authority = action.authority_hint.as_deref().map(normalize_authority);
        let normalized_path = strip_query(path);

        let (semantic_action, target_hint) =
            classify_semantic_action(method, normalized_path, path, normalized_authority)?;

        Some(ClassifiedGwsAction {
            source: action.source,
            request_id: action.request_id.clone(),
            transport: action.transport.clone(),
            authority_hint: action.authority_hint.clone(),
            method_hint: action.method_hint.clone(),
            path_hint: action.path_hint.clone(),
            destination_ip: action.destination_ip.clone(),
            destination_port: action.destination_port,
            semantic_surface: semantic_action.surface(),
            semantic_action,
            target_hint,
            classifier_labels: semantic_action.classifier_labels(),
            classifier_reasons: vec![semantic_action.reason()],
            content_retained: false,
        })
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
        let actions = self
            .semantic_actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} surfaces={} linkage_fields={} classification_fields={} actions={} stages={}",
            sources,
            surfaces,
            self.linkage_fields.join(","),
            self.classification_fields.join(","),
            actions,
            self.stages.join("->")
        )
    }
}

fn classify_semantic_action(
    method: &str,
    normalized_path: &str,
    raw_path: &str,
    authority_hint: Option<&str>,
) -> Option<(GwsActionKind, String)> {
    if let Some(target_hint) = classify_drive_permissions_update(method, normalized_path) {
        return Some((GwsActionKind::DrivePermissionsUpdate, target_hint));
    }

    if let Some(target_hint) = classify_drive_files_get_media(method, normalized_path, raw_path) {
        return Some((GwsActionKind::DriveFilesGetMedia, target_hint));
    }

    if let Some(target_hint) = classify_gmail_users_messages_send(method, normalized_path) {
        return Some((GwsActionKind::GmailUsersMessagesSend, target_hint));
    }

    if let Some(target_hint) = classify_admin_reports_activities_list(method, normalized_path) {
        return Some((GwsActionKind::AdminReportsActivitiesList, target_hint));
    }

    let authority = authority_hint?;

    if authority == "gmail.googleapis.com"
        && method.eq_ignore_ascii_case("POST")
        && normalized_path.ends_with("/messages/send")
    {
        return Some((
            GwsActionKind::GmailUsersMessagesSend,
            normalized_path.to_owned(),
        ));
    }

    None
}

fn classify_drive_permissions_update(method: &str, normalized_path: &str) -> Option<String> {
    if !method.eq_ignore_ascii_case("PATCH") {
        return None;
    }

    let segments = path_segments(normalized_path);
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

fn classify_drive_files_get_media(
    method: &str,
    normalized_path: &str,
    raw_path: &str,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") || !query_contains_alt_media(raw_path) {
        return None;
    }

    let segments = path_segments(normalized_path);
    if segments.len() == 4
        && segments[0] == "drive"
        && segments[1] == "v3"
        && segments[2] == "files"
    {
        return Some(format!("drive.files/{}", segments[3]));
    }

    None
}

fn classify_gmail_users_messages_send(method: &str, normalized_path: &str) -> Option<String> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }

    let segments = path_segments(normalized_path);
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

fn classify_admin_reports_activities_list(method: &str, normalized_path: &str) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }

    let segments = path_segments(normalized_path);
    if segments.len() == 8
        && segments[0] == "admin"
        && segments[1] == "reports"
        && segments[2] == "v1"
        && segments[3] == "activity"
        && segments[4] == "users"
        && segments[6] == "applications"
    {
        return Some(format!(
            "admin.reports/users/{}/applications/{}",
            segments[5], segments[7]
        ));
    }

    None
}

fn normalize_authority(authority: &str) -> &str {
    authority.trim().trim_end_matches('.')
}

fn strip_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn query_contains_alt_media(path: &str) -> bool {
    path.split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|pair| {
            pair.eq_ignore_ascii_case("alt=media")
                || pair
                    .split_once('=')
                    .is_some_and(|(key, value)| key.eq_ignore_ascii_case("alt") && value == "media")
        })
    })
}

fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use agenta_core::{SessionRecord, SessionWorkspace};

    use super::{
        ClassifyPlan, classify_admin_reports_activities_list, classify_drive_files_get_media,
        classify_drive_permissions_update, classify_gmail_users_messages_send,
        query_contains_alt_media,
    };
    use crate::poc::gws::{
        contract::{
            ApiRequestObservation, GwsActionKind, GwsSemanticSurface, GwsSignalSource,
            NetworkRequestObservation,
        },
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn classify_plan_threads_linkage_inputs_and_surfaces() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());

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
            plan.semantic_actions,
            vec![
                GwsActionKind::DrivePermissionsUpdate,
                GwsActionKind::DriveFilesGetMedia,
                GwsActionKind::GmailUsersMessagesSend,
                GwsActionKind::AdminReportsActivitiesList,
            ]
        );
        assert!(plan.linkage_fields.contains(&"session_id"));
        assert!(plan.linkage_fields.contains(&"semantic_surface_hint"));
    }

    #[test]
    fn classify_handoff_defines_semantic_action_fields_without_content_retention() {
        let handoff =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .handoff();

        assert_eq!(
            handoff.classification_fields,
            vec![
                "semantic_surface",
                "semantic_action_label",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ]
        );
        assert_eq!(
            handoff.redaction_contract,
            "raw HTTP payloads, email bodies, and document contents must not cross the GWS linkage boundary"
        );
    }

    #[test]
    fn classify_drive_permissions_update_from_api_linkage() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let linked = SessionLinkagePlan::default().link_api_observation(
            &ApiRequestObservation::preview_drive_permissions_update(),
            &fixture_session(),
        );

        let classified = plan
            .classify_action(&linked)
            .expect("drive permissions update should classify");

        assert_eq!(
            classified.semantic_surface,
            GwsSemanticSurface::GoogleWorkspaceDrive
        );
        assert_eq!(
            classified.semantic_action,
            GwsActionKind::DrivePermissionsUpdate
        );
        assert_eq!(
            classified.target_hint,
            "drive.files/abc123/permissions/perm456"
        );
        assert_eq!(
            classified.classifier_labels,
            vec!["gws.drive", "drive.permissions.update"]
        );
        assert_eq!(
            classified.classifier_reasons,
            vec!["PATCH drive permissions path maps to Drive sharing updates"]
        );
        assert!(!classified.content_retained);
        assert!(
            classified
                .log_line()
                .contains("semantic_action=drive.permissions.update")
        );
    }

    #[test]
    fn classify_drive_files_get_media_from_network_linkage() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let linked = SessionLinkagePlan::default().link_network_observation(
            &NetworkRequestObservation::preview_drive_files_get_media(),
            &fixture_session(),
        );

        let classified = plan
            .classify_action(&linked)
            .expect("drive get media should classify");

        assert_eq!(
            classified.semantic_surface,
            GwsSemanticSurface::GoogleWorkspaceDrive
        );
        assert_eq!(
            classified.semantic_action,
            GwsActionKind::DriveFilesGetMedia
        );
        assert_eq!(classified.target_hint, "drive.files/abc123");
        assert_eq!(
            classified.destination_ip.as_deref(),
            Some("142.250.191.139")
        );
        assert_eq!(classified.destination_port, Some(443));
    }

    #[test]
    fn classify_gmail_users_messages_send_from_api_linkage() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let linked = SessionLinkagePlan::default().link_api_observation(
            &ApiRequestObservation::preview_gmail_users_messages_send(),
            &fixture_session(),
        );

        let classified = plan
            .classify_action(&linked)
            .expect("gmail send should classify");

        assert_eq!(
            classified.semantic_surface,
            GwsSemanticSurface::GoogleWorkspaceGmail
        );
        assert_eq!(
            classified.semantic_action,
            GwsActionKind::GmailUsersMessagesSend
        );
        assert_eq!(classified.target_hint, "gmail.users/me");
    }

    #[test]
    fn classify_admin_reports_activities_list_from_api_linkage() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let linked = SessionLinkagePlan::default().link_api_observation(
            &ApiRequestObservation::preview_admin_reports_activities_list(),
            &fixture_session(),
        );

        let classified = plan
            .classify_action(&linked)
            .expect("admin reports list should classify");

        assert_eq!(
            classified.semantic_surface,
            GwsSemanticSurface::GoogleWorkspaceAdmin
        );
        assert_eq!(
            classified.semantic_action,
            GwsActionKind::AdminReportsActivitiesList
        );
        assert_eq!(
            classified.target_hint,
            "admin.reports/users/all/applications/drive"
        );
    }

    #[test]
    fn classify_returns_none_for_unknown_gws_path() {
        let plan =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff());
        let linked = SessionLinkagePlan::default().link_api_observation(
            &ApiRequestObservation {
                request_id: "req_unknown".to_owned(),
                transport: "https".to_owned(),
                authority_hint: "www.googleapis.com".to_owned(),
                method_hint: "GET".to_owned(),
                path_hint: "/drive/v3/about".to_owned(),
                semantic_surface_hint: GwsSemanticSurface::GoogleWorkspaceDrive,
            },
            &fixture_session(),
        );

        assert_eq!(plan.classify_action(&linked), None);
    }

    #[test]
    fn helper_matchers_cover_expected_supported_actions() {
        assert_eq!(
            classify_drive_permissions_update(
                "PATCH",
                "/drive/v3/files/abc123/permissions/perm456"
            ),
            Some("drive.files/abc123/permissions/perm456".to_owned())
        );
        assert_eq!(
            classify_drive_files_get_media(
                "GET",
                "/drive/v3/files/abc123",
                "/drive/v3/files/abc123?alt=media"
            ),
            Some("drive.files/abc123".to_owned())
        );
        assert_eq!(
            classify_gmail_users_messages_send("POST", "/gmail/v1/users/me/messages/send"),
            Some("gmail.users/me".to_owned())
        );
        assert_eq!(
            classify_admin_reports_activities_list(
                "GET",
                "/admin/reports/v1/activity/users/all/applications/drive",
            ),
            Some("admin.reports/users/all/applications/drive".to_owned())
        );
        assert!(query_contains_alt_media("/drive/v3/files/abc123?alt=media"));
    }

    #[test]
    fn classify_summary_mentions_actions_and_stages() {
        let summary =
            ClassifyPlan::from_session_linkage_boundary(SessionLinkagePlan::default().handoff())
                .summary();

        assert!(summary.contains("sources=api_observation,network_observation"));
        assert!(summary.contains("actions=drive.permissions.update,drive.files.get_media,gmail.users.messages.send,admin.reports.activities.list"));
        assert!(summary.contains("stages=service_map->taxonomy->label->handoff"));
    }

    fn fixture_session() -> SessionRecord {
        let mut session = SessionRecord::placeholder("openclaw-main", "sess_gws_classify");
        session.workspace = Some(SessionWorkspace {
            workspace_id: Some("ws_gws_classify".to_owned()),
            path: Some("/workspace".to_owned()),
            repo: Some("n01e0/agent-auditor".to_owned()),
            branch: Some("main".to_owned()),
        });
        session
    }
}
