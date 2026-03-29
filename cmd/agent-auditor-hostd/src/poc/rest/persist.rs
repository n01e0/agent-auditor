use std::path::PathBuf;

use agenta_core::{ApprovalRequest, EventEnvelope};

use crate::poc::persistence::{
    PersistenceError, PersistencePaths, append_json_line, bootstrap_paths, fresh_paths,
    read_last_json_line,
};

const STORE_DIR_NAME: &str = "agent-auditor-hostd-generic-rest-poc-store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRestPocStore {
    paths: PersistencePaths,
}

impl GenericRestPocStore {
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
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EnforcementDirective,
        EnforcementInfo, EnforcementStatus, EventEnvelope, EventType, JsonMap, PolicyDecisionKind,
        PolicyMetadata, ResultInfo, ResultStatus, SessionRef, Severity, SourceInfo,
    };
    use serde_json::json;

    use super::GenericRestPocStore;

    #[test]
    fn store_appends_and_reads_back_generic_rest_audit_and_approval_records() {
        let store = GenericRestPocStore::fresh(unique_test_root()).expect("store should init");
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
    fn fresh_store_clears_old_generic_rest_records_before_bootstrap() {
        let root = unique_test_root();
        let first = GenericRestPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = GenericRestPocStore::fresh(&root).expect("second store should reset");

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
        env::temp_dir().join(format!(
            "agent-auditor-hostd-generic-rest-store-test-{nonce}"
        ))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("api_observation"));
        attributes.insert(
            "request_id".to_owned(),
            json!("req_rest_gmail_send_preview"),
        );
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!("gws.gmail"));
        attributes.insert("provider_id".to_owned(), json!("gws"));
        attributes.insert("action_key".to_owned(), json!("gmail.users.messages.send"));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!("gws:gmail.users.messages.send"),
        );
        attributes.insert("target_hint".to_owned(), json!("gmail.users/me"));
        attributes.insert("method".to_owned(), json!("POST"));
        attributes.insert("host".to_owned(), json!("gmail.googleapis.com"));
        attributes.insert(
            "path_template".to_owned(),
            json!("/gmail/v1/users/{userId}/messages/send"),
        );
        attributes.insert("query_class".to_owned(), json!("action_arguments"));
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": "https://www.googleapis.com/auth/gmail.send",
                "documented": ["https://www.googleapis.com/auth/gmail.send"],
            }),
        );
        attributes.insert(
            "side_effect".to_owned(),
            json!("sends a Gmail message to one or more recipients"),
        );
        attributes.insert("privilege_class".to_owned(), json!("outbound_send"));
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope {
            event_id: "evt_rest_gmail_send_record".to_owned(),
            event_type: EventType::GwsAction,
            timestamp: chrono::Utc::now(),
            session: SessionRef {
                session_id: "sess_generic_rest_persist".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_generic_rest_persist".to_owned()),
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            actor: Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            action: Action {
                class: ActionClass::Gws,
                verb: Some("gmail.users.messages.send".to_owned()),
                target: Some("gmail.users/me".to_owned()),
                attributes,
            },
            result: ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("Outbound REST actions require approval".to_owned()),
                exit_code: None,
                error: None,
            },
            source: SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
            policy: Some(PolicyMetadata {
                decision: Some(PolicyDecisionKind::RequireApproval),
                rule_id: Some("generic_rest.outbound_send.requires_approval".to_owned()),
                severity: Some(Severity::High),
                explanation: Some("Outbound REST actions require approval".to_owned()),
            }),
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Outbound REST actions require approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_rest_gmail_send_record".to_owned()),
                expires_at: None,
            }),
            integrity: None,
        }
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_evt_rest_gmail_send_record".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_generic_rest_persist".to_owned(),
            event_id: Some("evt_rest_gmail_send_record".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Gws,
                action_verb: "gmail.users.messages.send".to_owned(),
                target: Some("gmail.users/me".to_owned()),
                summary: Some("Outbound REST actions require approval".to_owned()),
                attributes: fixture_event().action.attributes,
            },
            policy: ApprovalPolicy {
                rule_id: "generic_rest.outbound_send.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("Outbound REST actions require approval".to_owned()),
                scope: Some(agenta_core::ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            presentation: None,
            requester_context: None,
            decision: None,
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Outbound REST actions require approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_rest_gmail_send_record".to_owned()),
                expires_at: None,
            }),
        }
    }
}
