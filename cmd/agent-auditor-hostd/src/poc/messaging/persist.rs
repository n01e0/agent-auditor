use std::path::PathBuf;

use agenta_core::{ApprovalRequest, EventEnvelope};

use crate::poc::persistence::{
    PersistenceError, PersistencePaths, append_durable_approval_request,
    append_durable_audit_record, bootstrap_paths, fresh_paths, read_last_json_line,
};

const STORE_DIR_NAME: &str = "agent-auditor-hostd-messaging-poc-store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingPocStore {
    paths: PersistencePaths,
}

impl MessagingPocStore {
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
        ApprovalRequestAction, ApprovalScope, ApprovalStatus, CollectorKind, EnforcementDirective,
        EnforcementInfo, EnforcementStatus, EventEnvelope, EventType, JsonMap, PolicyDecisionKind,
        PolicyMetadata, ResultInfo, ResultStatus, SessionRef, Severity, SourceInfo,
    };
    use serde_json::json;

    use super::MessagingPocStore;

    #[test]
    fn store_appends_and_reads_back_messaging_audit_and_approval_records() {
        let store = MessagingPocStore::fresh(unique_test_root()).expect("store should init");
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
    fn fresh_store_clears_old_messaging_records_before_bootstrap() {
        let root = unique_test_root();
        let first = MessagingPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = MessagingPocStore::fresh(&root).expect("second store should reset");

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
        env::temp_dir().join(format!("agent-auditor-hostd-messaging-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("browser_observation"));
        attributes.insert(
            "request_id".to_owned(),
            json!("req_msg_discord_invite_preview"),
        );
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!("discord.threads"));
        attributes.insert("provider_id".to_owned(), json!("discord"));
        attributes.insert(
            "action_key".to_owned(),
            json!("channels.thread_members.put"),
        );
        attributes.insert(
            "provider_action_id".to_owned(),
            json!("discord:channels.thread_members.put"),
        );
        attributes.insert(
            "target_hint".to_owned(),
            json!("discord.threads/123456789012345678/members/234567890123456789"),
        );
        attributes.insert("method".to_owned(), json!("PUT"));
        attributes.insert("host".to_owned(), json!("discord.com"));
        attributes.insert(
            "path_template".to_owned(),
            json!("/api/v10/channels/{thread_id}/thread-members/{user_id}"),
        );
        attributes.insert("query_class".to_owned(), json!("none"));
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": "discord.permission:create_public_threads",
                "documented": [
                    "discord.permission:create_public_threads",
                    "discord.permission:send_messages_in_threads"
                ],
            }),
        );
        attributes.insert(
            "side_effect".to_owned(),
            json!("adds a member into a Discord thread"),
        );
        attributes.insert("privilege_class".to_owned(), json!("sharing_write"));
        attributes.insert("action_family".to_owned(), json!("channel.invite"));
        attributes.insert(
            "conversation_hint".to_owned(),
            json!("discord.threads/123456789012345678"),
        );
        attributes.insert("delivery_scope".to_owned(), json!("thread"));
        attributes.insert("membership_target_kind".to_owned(), json!("thread_member"));
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope {
            event_id: "evt_msg_discord_invite_record".to_owned(),
            event_type: EventType::NetworkConnect,
            timestamp: chrono::Utc::now(),
            session: SessionRef {
                session_id: "sess_messaging_persist".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_messaging_persist".to_owned()),
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            actor: Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            action: Action {
                class: ActionClass::Browser,
                verb: Some("channels.thread_members.put".to_owned()),
                target: Some(
                    "discord.threads/123456789012345678/members/234567890123456789".to_owned(),
                ),
                attributes,
            },
            result: ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("Messaging membership expansion requires approval".to_owned()),
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
                rule_id: Some("messaging.channel_invite.requires_approval".to_owned()),
                severity: Some(Severity::High),
                explanation: Some("Messaging membership expansion requires approval".to_owned()),
            }),
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Messaging membership expansion requires approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_msg_discord_invite_record".to_owned()),
                expires_at: None,
            }),
            integrity: None,
        }
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_evt_msg_discord_invite_record".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_messaging_persist".to_owned(),
            event_id: Some("evt_msg_discord_invite_record".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Browser,
                action_verb: "channels.thread_members.put".to_owned(),
                target: Some(
                    "discord.threads/123456789012345678/members/234567890123456789".to_owned(),
                ),
                summary: Some("Messaging membership expansion requires approval".to_owned()),
                attributes: fixture_event().action.attributes,
            },
            policy: ApprovalPolicy {
                rule_id: "messaging.channel_invite.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("Messaging membership expansion requires approval".to_owned()),
                scope: Some(ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            presentation: None,
            requester_context: None,
            decision: None,
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Messaging membership expansion requires approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_msg_discord_invite_record".to_owned()),
                expires_at: None,
            }),
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
