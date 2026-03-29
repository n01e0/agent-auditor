use std::path::PathBuf;

use agenta_core::{ApprovalRequest, EventEnvelope};

use crate::poc::persistence::{
    PersistenceError, PersistencePaths, append_json_line, bootstrap_paths, fresh_paths,
    read_last_json_line,
};

const STORE_DIR_NAME: &str = "agent-auditor-hostd-poc-store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemPocStore {
    paths: PersistencePaths,
}

impl FilesystemPocStore {
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
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EventEnvelope, EventType, ResultInfo,
        ResultStatus, SessionRef, SourceInfo,
    };
    use serde_json::json;

    use super::FilesystemPocStore;

    #[test]
    fn store_appends_and_reads_back_audit_and_approval_records() {
        let store = FilesystemPocStore::fresh(unique_test_root()).expect("store should init");
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
    fn fresh_store_clears_old_records_before_bootstrap() {
        let root = unique_test_root();
        let first = FilesystemPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = FilesystemPocStore::fresh(&root).expect("second store should reset");

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
        env::temp_dir().join(format!("agent-auditor-hostd-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        EventEnvelope::new(
            "evt_fs_1",
            EventType::FilesystemAccess,
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
                class: ActionClass::Filesystem,
                verb: Some("read".to_owned()),
                target: Some("/home/agent/.ssh/id_ed25519".to_owned()),
                attributes: [("sensitive".to_owned(), json!(true))]
                    .into_iter()
                    .collect(),
            },
            ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("sensitive path access requires approval".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Fanotify,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4242),
                ppid: None,
            },
        )
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_evt_fs_1".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_bootstrap_hostd".to_owned(),
            event_id: Some("evt_fs_1".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Filesystem,
                action_verb: "read".to_owned(),
                target: Some("/home/agent/.ssh/id_ed25519".to_owned()),
                summary: Some("sensitive path access requires approval".to_owned()),
                attributes: [("sensitive".to_owned(), json!(true))]
                    .into_iter()
                    .collect(),
            },
            policy: ApprovalPolicy {
                rule_id: "fs.sensitive.read".to_owned(),
                severity: Some(agenta_core::Severity::High),
                reason: Some("sensitive path access requires approval".to_owned()),
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
