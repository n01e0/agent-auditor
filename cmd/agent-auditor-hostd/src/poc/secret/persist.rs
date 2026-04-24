use std::path::PathBuf;

use agenta_core::{ApprovalRequest, EventEnvelope};

use crate::poc::persistence::{
    PersistenceError, PersistencePaths, append_durable_approval_request,
    append_durable_audit_record, bootstrap_paths, fresh_paths, read_last_json_line,
};

const STORE_DIR_NAME: &str = "agent-auditor-hostd-secret-poc-store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPocStore {
    paths: PersistencePaths,
}

impl SecretPocStore {
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
        append_durable_audit_record(
            &self.paths.audit_log,
            &self.paths.audit_integrity_log,
            event,
        )
        .map(|_| ())
    }

    pub fn append_approval_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<(), PersistenceError> {
        append_durable_approval_request(
            &self.paths.approval_log,
            &self.paths.approval_integrity_log,
            request,
        )
        .map(|_| ())
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

    use super::SecretPocStore;

    #[test]
    fn store_appends_and_reads_back_secret_audit_and_approval_records() {
        let store = SecretPocStore::fresh(unique_test_root()).expect("store should init");
        let event = fixture_event();
        let request = fixture_request();

        store
            .append_audit_record(&event)
            .expect("audit record should append");
        store
            .append_approval_request(&request)
            .expect("approval request should append");

        assert_persisted_event(
            store
                .latest_audit_record()
                .expect("audit record should read"),
            event,
        );
        assert_persisted_request(
            store
                .latest_approval_request()
                .expect("approval request should read"),
            request,
        );
    }

    #[test]
    fn fresh_store_clears_old_secret_records_before_bootstrap() {
        let root = unique_test_root();
        let first = SecretPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = SecretPocStore::fresh(&root).expect("second store should reset");

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
        env::temp_dir().join(format!("agent-auditor-hostd-secret-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("broker_adapter"));
        attributes.insert("taxonomy_kind".to_owned(), json!("brokered_secret_request"));
        attributes.insert("taxonomy_variant".to_owned(), json!("secret_reference"));
        attributes.insert("locator_hint".to_owned(), json!("kv/prod/db/password"));
        attributes.insert(
            "classifier_labels".to_owned(),
            json!(["brokered_secret_request", "secret_reference"]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["request came from a broker adapter with a redaction-safe locator hint"]),
        );
        attributes.insert("plaintext_retained".to_owned(), json!(false));
        attributes.insert("broker_id".to_owned(), json!("vault"));
        attributes.insert("broker_action".to_owned(), json!("read"));

        let mut event = EventEnvelope::new(
            "poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference",
            EventType::SecretAccess,
            SessionRef {
                session_id: "sess_bootstrap_hostd".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: None,
                environment: None,
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Secret,
                verb: Some("fetch".to_owned()),
                target: Some("kv/prod/db/password".to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("brokered secret retrieval requires approval".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::ControlPlane,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
        );
        event.policy = Some(PolicyMetadata {
            decision: Some(PolicyDecisionKind::RequireApproval),
            rule_id: Some("secret.brokered.requires_approval".to_owned()),
            severity: Some(Severity::High),
            explanation: Some("brokered secret retrieval requires approval".to_owned()),
        });
        event
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id:
                "apr_poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference"
                    .to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_bootstrap_hostd".to_owned(),
            event_id: Some(
                "poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference"
                    .to_owned(),
            ),
            request: ApprovalRequestAction {
                action_class: ActionClass::Secret,
                action_verb: "fetch".to_owned(),
                target: Some("kv/prod/db/password".to_owned()),
                summary: Some("brokered secret retrieval requires approval".to_owned()),
                attributes: [
                    ("source_kind".to_owned(), json!("broker_adapter")),
                    (
                        "taxonomy_kind".to_owned(),
                        json!("brokered_secret_request"),
                    ),
                ]
                .into_iter()
                .collect(),
            },
            policy: ApprovalPolicy {
                rule_id: "secret.brokered.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("brokered secret retrieval requires approval".to_owned()),
                scope: Some(agenta_core::ApprovalScope::SingleAction),
                ttl_seconds: Some(1200),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            presentation: None,
            requester_context: None,
            decision: None,
            enforcement: None,
            integrity: None,
        }
    }

    fn assert_persisted_event(actual: Option<EventEnvelope>, expected: EventEnvelope) {
        let mut actual = actual.expect("persisted event should exist");
        assert!(
            actual
                .integrity
                .as_ref()
                .and_then(|integrity| integrity.hash.as_deref())
                .is_some()
        );
        actual.integrity = None;
        assert_eq!(actual, expected);
    }

    fn assert_persisted_request(actual: Option<ApprovalRequest>, expected: ApprovalRequest) {
        let mut actual = actual.expect("persisted approval request should exist");
        assert!(
            actual
                .integrity
                .as_ref()
                .and_then(|integrity| integrity.hash.as_deref())
                .is_some()
        );
        actual.integrity = None;
        assert_eq!(actual, expected);
    }
}
