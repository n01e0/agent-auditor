use std::path::PathBuf;

use agenta_core::{ApprovalRequest, EventEnvelope};

use crate::poc::persistence::{
    PersistenceError, PersistencePaths, append_json_line, bootstrap_paths, fresh_paths,
    read_last_json_line,
};

const STORE_DIR_NAME: &str = "agent-auditor-hostd-gws-poc-store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GwsPocStore {
    paths: PersistencePaths,
}

impl GwsPocStore {
    pub fn bootstrap() -> Result<Self, PersistenceError> {
        Ok(Self {
            paths: bootstrap_paths(STORE_DIR_NAME)?,
        })
    }

    pub fn fresh(root: impl Into<PathBuf>) -> Result<Self, PersistenceError> {
        Ok(Self {
            paths: fresh_paths(root)?,
        })
    }

    pub fn paths(&self) -> &PersistencePaths {
        &self.paths
    }

    pub fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), PersistenceError> {
        append_json_line(&self.paths.audit_log, event)
    }

    pub fn append_approval_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<(), PersistenceError> {
        append_json_line(&self.paths.approval_log, request)
    }

    pub fn latest_audit_record(&self) -> Result<Option<EventEnvelope>, PersistenceError> {
        read_last_json_line(&self.paths.audit_log)
    }

    pub fn latest_approval_request(&self) -> Result<Option<ApprovalRequest>, PersistenceError> {
        read_last_json_line(&self.paths.approval_log)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest,
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EventEnvelope, EventType, JsonMap,
        PolicyDecisionKind, PolicyMetadata, ResultInfo, ResultStatus, SessionRef, Severity,
        SourceInfo,
    };
    use serde_json::json;

    use super::GwsPocStore;

    #[test]
    fn store_appends_and_reads_back_gws_audit_and_approval_records() {
        let store = GwsPocStore::fresh(unique_test_root()).expect("store should init");
        let event = fixture_event();
        let request = fixture_request();

        store
            .append_audit_record(&event)
            .expect("audit record should append");
        store
            .append_approval_request(&request)
            .expect("approval request should append");

        assert_eq!(
            store
                .latest_audit_record()
                .expect("audit record should read"),
            Some(event)
        );
        assert_eq!(
            store
                .latest_approval_request()
                .expect("approval request should read"),
            Some(request)
        );
    }

    #[test]
    fn fresh_store_clears_old_gws_records_before_bootstrap() {
        let root = unique_test_root();
        let first = GwsPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = GwsPocStore::fresh(&root).expect("second store should reset");

        assert_eq!(
            second
                .latest_audit_record()
                .expect("audit read should work"),
            None
        );
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-gws-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("api_observation"));
        attributes.insert(
            "request_id".to_owned(),
            json!("req_drive_permissions_update_preview"),
        );
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!("gws.drive"));
        attributes.insert("provider_id".to_owned(), json!("gws"));
        attributes.insert("action_key".to_owned(), json!("drive.permissions.update"));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!("gws:drive.permissions.update"),
        );
        attributes.insert(
            "semantic_action_label".to_owned(),
            json!("drive.permissions.update"),
        );
        attributes.insert(
            "target_hint".to_owned(),
            json!("drive.files/abc123/permissions/perm456"),
        );
        attributes.insert(
            "classifier_labels".to_owned(),
            json!(["gws.drive", "drive.permissions.update"]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["PATCH drive permissions path maps to Drive sharing updates"]),
        );
        attributes.insert("content_retained".to_owned(), json!(false));

        let mut event = EventEnvelope::new(
            "poc_gws_action_api_observation_drive.permissions.update_req_drive_permissions_update_preview",
            EventType::GwsAction,
            SessionRef {
                session_id: "sess_bootstrap_hostd".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Gws,
                verb: Some("drive.permissions.update".to_owned()),
                target: Some("drive.files/abc123/permissions/perm456".to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("Drive permission updates require approval".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        );
        event.policy = Some(PolicyMetadata {
            decision: Some(PolicyDecisionKind::RequireApproval),
            rule_id: Some("gws.drive.permissions_update.requires_approval".to_owned()),
            severity: Some(Severity::High),
            explanation: Some("Drive permission updates require approval".to_owned()),
        });
        event
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_poc_gws_action_api_observation_drive.permissions.update_req_drive_permissions_update_preview".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_bootstrap_hostd".to_owned(),
            event_id: Some(
                "poc_gws_action_api_observation_drive.permissions.update_req_drive_permissions_update_preview"
                    .to_owned(),
            ),
            request: ApprovalRequestAction {
                action_class: ActionClass::Gws,
                action_verb: "drive.permissions.update".to_owned(),
                target: Some("drive.files/abc123/permissions/perm456".to_owned()),
                summary: Some("Drive permission updates require approval".to_owned()),
                attributes: [
                    ("source_kind".to_owned(), json!("api_observation")),
                    ("provider_id".to_owned(), json!("gws")),
                    ("action_key".to_owned(), json!("drive.permissions.update")),
                    (
                        "semantic_action_label".to_owned(),
                        json!("drive.permissions.update"),
                    ),
                ]
                .into_iter()
                .collect(),
            },
            policy: ApprovalPolicy {
                rule_id: "gws.drive.permissions_update.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("Drive permission updates require approval".to_owned()),
                scope: Some(agenta_core::ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            presentation: None,
            requester_context: None,
            decision: None,
            enforcement: None,
        }
    }
}
