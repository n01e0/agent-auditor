pub mod contract;
pub mod persist;
pub mod policy;
pub mod record;
pub mod taxonomy;

use self::{policy::PolicyPlan, record::RecordPlan, taxonomy::TaxonomyPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingCollaborationGovernancePlan {
    pub taxonomy: TaxonomyPlan,
    pub policy: PolicyPlan,
    pub record: RecordPlan,
}

impl MessagingCollaborationGovernancePlan {
    pub fn bootstrap() -> Self {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let record = RecordPlan::from_policy_boundary(policy.handoff());

        Self {
            taxonomy,
            policy,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalStatus, CollectorKind, EventEnvelope,
        EventType, JsonMap, ResultInfo, ResultStatus, SessionRef, SourceInfo,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };
    use serde_json::json;

    use super::MessagingCollaborationGovernancePlan;
    use crate::poc::messaging::persist::MessagingPocStore;

    #[test]
    fn bootstrap_plan_keeps_taxonomy_policy_and_record_responsibilities_separate() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("shared collaboration action family"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .all(|item| !item.contains("append redaction-safe messaging audit records"))
        );

        assert!(
            plan.policy
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-policy"))
        );
        assert!(
            plan.policy
                .responsibilities
                .iter()
                .all(|item| !item.contains("append-only storage"))
        );

        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("append redaction-safe messaging audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_and_generic_rest_inputs_into_messaging_boundary() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert_eq!(plan.taxonomy.providers, vec!["slack", "discord"]);
        assert_eq!(
            plan.taxonomy.action_families,
            vec![
                "message.send",
                "channel.invite",
                "permission.update",
                "file.upload",
            ]
        );
        assert_eq!(
            plan.taxonomy.upstream_provider_contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(
            plan.taxonomy.upstream_generic_rest_fields,
            vec![
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.taxonomy.messaging_contract_fields,
            vec![
                "provider_id",
                "action_key",
                "action_family",
                "target_hint",
                "channel_hint",
                "conversation_hint",
                "delivery_scope",
                "membership_target_kind",
                "permission_target_kind",
                "file_target_kind",
                "attachment_count_hint",
            ]
        );
        assert_eq!(plan.taxonomy.providers, plan.policy.providers);
        assert_eq!(plan.policy.providers, plan.record.providers);
        assert_eq!(plan.taxonomy.action_families, plan.policy.action_families);
        assert_eq!(plan.policy.action_families, plan.record.action_families);
        assert_eq!(
            plan.policy.input_fields,
            plan.taxonomy.messaging_contract_fields
        );
        assert_eq!(plan.policy.decision_fields, plan.record.input_fields);
        assert_eq!(
            plan.record.record_fields,
            plan.record.handoff().record_fields
        );
    }

    #[test]
    fn bootstrap_plan_preserves_messaging_redaction_guardrails() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert_eq!(
            plan.taxonomy.provider_input().redaction_contract,
            "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam"
        );
        assert_eq!(
            plan.taxonomy.provider_input().redaction_contract,
            plan.taxonomy.handoff().redaction_contract
        );
        assert_eq!(
            plan.taxonomy.handoff().redaction_contract,
            plan.policy.handoff().redaction_contract
        );
        assert_eq!(
            plan.policy.handoff().redaction_contract,
            plan.record.redaction_contract
        );
    }

    #[test]
    fn messaging_pipeline_reflects_and_persists_allow_hold_and_deny_records() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();
        let store = MessagingPocStore::fresh(unique_test_root()).expect("store should init");

        let allow_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_slack_send_allow",
            provider_id: "slack",
            action_key: "chat.post_message",
            target: "slack.channels/C12345678",
            semantic_surface: "slack.chat",
            method: "POST",
            host: "slack.com",
            path_template: "/api/chat.postMessage",
            query_class: "action_arguments",
            primary_scope: "slack.scope:chat:write",
            documented_scopes: &["slack.scope:chat:write"],
            side_effect: "sends a message into a Slack conversation",
            privilege_class: "outbound_send",
            action_family: "message.send",
            channel_hint: Some("slack.channels/C12345678"),
            conversation_hint: None,
            delivery_scope: Some("public_channel"),
            membership_target_kind: None,
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        });
        let allow_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&allow_observed))
            .expect("allow decision should evaluate");
        let allow_enriched = plan
            .record
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");
        store
            .append_audit_record(&allow_enriched)
            .expect("allow audit record should append");
        assert_eq!(allow_enriched.result.status, ResultStatus::Allowed);
        assert!(allow_enriched.enforcement.is_none());

        let hold_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_discord_invite_hold",
            provider_id: "discord",
            action_key: "channels.thread_members.put",
            target: "discord.threads/123456789012345678/members/234567890123456789",
            semantic_surface: "discord.threads",
            method: "PUT",
            host: "discord.com",
            path_template: "/api/v10/channels/{thread_id}/thread-members/{user_id}",
            query_class: "none",
            primary_scope: "discord.permission:create_public_threads",
            documented_scopes: &[
                "discord.permission:create_public_threads",
                "discord.permission:send_messages_in_threads",
            ],
            side_effect: "adds a member into a Discord thread",
            privilege_class: "sharing_write",
            action_family: "channel.invite",
            channel_hint: None,
            conversation_hint: Some("discord.threads/123456789012345678"),
            delivery_scope: Some("thread"),
            membership_target_kind: Some("thread_member"),
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        });
        let hold_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&hold_observed))
            .expect("hold decision should evaluate");
        let hold_request = approval_request_from_decision(
            &agenta_policy::apply_decision_to_event(&hold_observed, &hold_decision),
            &hold_decision,
        )
        .expect("hold decision should create approval request");
        let (hold_enriched, hold_request) = plan
            .record
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");
        store
            .append_audit_record(&hold_enriched)
            .expect("hold audit record should append");
        store
            .append_approval_request(&hold_request)
            .expect("hold approval request should append");
        assert_eq!(hold_enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(hold_request.status, ApprovalStatus::Pending);
        assert_eq!(
            hold_enriched
                .enforcement
                .as_ref()
                .and_then(|info| info.approval_id.as_deref()),
            Some(hold_request.approval_id.as_str())
        );

        let deny_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_discord_permission_deny",
            provider_id: "discord",
            action_key: "channels.permissions.put",
            target: "discord.channels/123456789012345678/permissions/role:345678901234567890",
            semantic_surface: "discord.permissions",
            method: "PUT",
            host: "discord.com",
            path_template: "/api/v10/channels/{channel_id}/permissions/{overwrite_id}",
            query_class: "none",
            primary_scope: "discord.permission:manage_roles",
            documented_scopes: &["discord.permission:manage_channels"],
            side_effect: "updates a Discord channel permission overwrite",
            privilege_class: "sharing_write",
            action_family: "permission.update",
            channel_hint: Some("discord.channels/123456789012345678"),
            conversation_hint: None,
            delivery_scope: None,
            membership_target_kind: None,
            permission_target_kind: Some("channel_permission_overwrite"),
            file_target_kind: None,
            attachment_count_hint: None,
        });
        let deny_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&deny_observed))
            .expect("deny decision should evaluate");
        let deny_enriched = plan
            .record
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");
        store
            .append_audit_record(&deny_enriched)
            .expect("deny audit record should append");
        assert_eq!(deny_enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            deny_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );

        assert_eq!(
            store
                .latest_audit_record()
                .expect("latest audit record should read"),
            Some(deny_enriched)
        );
        assert_eq!(
            store
                .latest_approval_request()
                .expect("latest approval request should read"),
            Some(hold_request)
        );
    }

    struct MessagingFixture<'a> {
        event_id: &'a str,
        provider_id: &'a str,
        action_key: &'a str,
        target: &'a str,
        semantic_surface: &'a str,
        method: &'a str,
        host: &'a str,
        path_template: &'a str,
        query_class: &'a str,
        primary_scope: &'a str,
        documented_scopes: &'a [&'a str],
        side_effect: &'a str,
        privilege_class: &'a str,
        action_family: &'a str,
        channel_hint: Option<&'a str>,
        conversation_hint: Option<&'a str>,
        delivery_scope: Option<&'a str>,
        membership_target_kind: Option<&'a str>,
        permission_target_kind: Option<&'a str>,
        file_target_kind: Option<&'a str>,
        attachment_count_hint: Option<u16>,
    }

    fn fixture_event(fixture: MessagingFixture<'_>) -> EventEnvelope {
        let MessagingFixture {
            event_id,
            provider_id,
            action_key,
            target,
            semantic_surface,
            method,
            host,
            path_template,
            query_class,
            primary_scope,
            documented_scopes,
            side_effect,
            privilege_class,
            action_family,
            channel_hint,
            conversation_hint,
            delivery_scope,
            membership_target_kind,
            permission_target_kind,
            file_target_kind,
            attachment_count_hint,
        } = fixture;

        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("api_observation"));
        attributes.insert("request_id".to_owned(), json!(format!("req_{event_id}")));
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!(semantic_surface));
        attributes.insert("provider_id".to_owned(), json!(provider_id));
        attributes.insert("action_key".to_owned(), json!(action_key));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!(format!("{provider_id}:{action_key}")),
        );
        attributes.insert("target_hint".to_owned(), json!(target));
        attributes.insert("method".to_owned(), json!(method));
        attributes.insert("host".to_owned(), json!(host));
        attributes.insert("path_template".to_owned(), json!(path_template));
        attributes.insert("query_class".to_owned(), json!(query_class));
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": primary_scope,
                "documented": documented_scopes,
            }),
        );
        attributes.insert("side_effect".to_owned(), json!(side_effect));
        attributes.insert("privilege_class".to_owned(), json!(privilege_class));
        attributes.insert("action_family".to_owned(), json!(action_family));
        if let Some(channel_hint) = channel_hint {
            attributes.insert("channel_hint".to_owned(), json!(channel_hint));
        }
        if let Some(conversation_hint) = conversation_hint {
            attributes.insert("conversation_hint".to_owned(), json!(conversation_hint));
        }
        if let Some(delivery_scope) = delivery_scope {
            attributes.insert("delivery_scope".to_owned(), json!(delivery_scope));
        }
        if let Some(membership_target_kind) = membership_target_kind {
            attributes.insert(
                "membership_target_kind".to_owned(),
                json!(membership_target_kind),
            );
        }
        if let Some(permission_target_kind) = permission_target_kind {
            attributes.insert(
                "permission_target_kind".to_owned(),
                json!(permission_target_kind),
            );
        }
        if let Some(file_target_kind) = file_target_kind {
            attributes.insert("file_target_kind".to_owned(), json!(file_target_kind));
        }
        if let Some(attachment_count_hint) = attachment_count_hint {
            attributes.insert(
                "attachment_count_hint".to_owned(),
                json!(attachment_count_hint),
            );
        }
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope::new(
            event_id,
            EventType::NetworkConnect,
            SessionRef {
                session_id: "sess_messaging_mod".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_messaging_mod".to_owned()),
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Browser,
                verb: Some(action_key.to_owned()),
                target: Some(target.to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd messaging mod fixture".to_owned()),
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
        )
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("agent-auditor-hostd-messaging-mod-test-{nonce}"))
    }
}
