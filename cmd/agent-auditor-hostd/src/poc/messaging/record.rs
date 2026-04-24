use agenta_core::{
    ApprovalRequest, EnforcementDirective, EnforcementInfo, EnforcementStatus, EventEnvelope,
    PolicyDecision, PolicyDecisionKind,
};
use agenta_policy::{
    apply_decision_to_event, apply_enforcement_to_approval_request, apply_enforcement_to_event,
};
use thiserror::Error;

use super::contract::{PolicyBoundary, RecordBoundary};
use crate::poc::live_proxy::session_correlation::ObservedRuntimePath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(policy: PolicyBoundary) -> Self {
        Self {
            providers: policy.providers,
            action_families: policy.action_families,
            input_fields: policy.decision_fields,
            record_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "append redaction-safe messaging audit records and approval requests without replaying provider taxonomy, generic REST normalization, or messaging-family inference",
                "reflect allow, hold, and deny outcomes into append-only storage and later publish fanout using the checked-in messaging contract",
                "avoid storing raw message bodies, participant rosters, uploaded bytes, invite links, and provider-specific opaque payloads in the shared messaging record seam",
            ],
            stages: vec!["persist", "publish"],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            redaction_contract: policy.redaction_contract,
        }
    }

    pub fn reflect_allow(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Allow {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Allow,
                actual: decision.decision,
            });
        }

        let mut reflected = apply_decision_to_event(event, decision);
        annotate_hermes_discord_validated_event(&mut reflected);
        Ok(reflected)
    }

    pub fn reflect_hold(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
        approval_request: &ApprovalRequest,
    ) -> Result<(EventEnvelope, ApprovalRequest), RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::RequireApproval {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::RequireApproval,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Hold,
            status: EnforcementStatus::Held,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: Some(approval_request.approval_id.clone()),
            expires_at: approval_request.expires_at,
        };

        let mut reflected_event = apply_enforcement_to_event(&decision_applied, &enforcement);
        annotate_hermes_discord_validated_event(&mut reflected_event);
        let mut reflected_request =
            apply_enforcement_to_approval_request(approval_request, &enforcement);
        annotate_hermes_discord_validated_request(&mut reflected_request);

        Ok((reflected_event, reflected_request))
    }

    pub fn reflect_deny(
        &self,
        event: &EventEnvelope,
        decision: &PolicyDecision,
    ) -> Result<EventEnvelope, RecordReflectionError> {
        if decision.decision != PolicyDecisionKind::Deny {
            return Err(RecordReflectionError::UnexpectedDecision {
                event_id: event.event_id.clone(),
                expected: PolicyDecisionKind::Deny,
                actual: decision.decision,
            });
        }

        let decision_applied = apply_decision_to_event(event, decision);
        let enforcement = EnforcementInfo {
            directive: EnforcementDirective::Deny,
            status: EnforcementStatus::Denied,
            status_reason: decision.reason.clone(),
            enforced: true,
            coverage_gap: None,
            approval_id: None,
            expires_at: None,
        };

        let mut reflected = apply_enforcement_to_event(&decision_applied, &enforcement);
        annotate_hermes_discord_validated_event(&mut reflected);
        Ok(reflected)
    }

    pub fn handoff(&self) -> RecordBoundary {
        RecordBoundary {
            providers: self.providers.clone(),
            action_families: self.action_families.clone(),
            input_fields: self.input_fields.clone(),
            record_fields: self.record_fields.clone(),
            redaction_contract: self.redaction_contract,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} action_families={} input_fields={} record_fields={} stages={} sinks={}",
            self.providers.join(","),
            self.action_families.join(","),
            self.input_fields.join(","),
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordReflectionError {
    #[error(
        "messaging record reflection expected `{expected:?}` for event `{event_id}`, got `{actual:?}`"
    )]
    UnexpectedDecision {
        event_id: String,
        expected: PolicyDecisionKind,
        actual: PolicyDecisionKind,
    },
}

fn annotate_hermes_discord_validated_event(event: &mut EventEnvelope) {
    if !is_hermes_discord_validated_attributes(&event.action.attributes) {
        return;
    }

    event
        .action
        .attributes
        .entry("validation_status".to_owned())
        .or_insert_with(|| serde_json::json!("validated_observation"));
    event
        .action
        .attributes
        .entry("validation_capture_source".to_owned())
        .or_insert_with(|| serde_json::json!(ObservedRuntimePath::SOURCE_LABEL));
}

fn annotate_hermes_discord_validated_request(request: &mut ApprovalRequest) {
    if !is_hermes_discord_validated_attributes(&request.request.attributes) {
        return;
    }

    request
        .request
        .attributes
        .entry("validation_status".to_owned())
        .or_insert_with(|| serde_json::json!("validated_observation"));
    request
        .request
        .attributes
        .entry("validation_capture_source".to_owned())
        .or_insert_with(|| serde_json::json!(ObservedRuntimePath::SOURCE_LABEL));
}

fn is_hermes_discord_validated_attributes(attributes: &agenta_core::JsonMap) -> bool {
    let provider_id = string_attribute(attributes, "provider_id");
    let action_key = string_attribute(attributes, "action_key");

    matches!(
        provider_id.as_deref().zip(action_key.as_deref()),
        Some(("discord", action_key))
            if super::contract::MessagingActionKind::from_label("discord", action_key).is_some()
    ) && string_attribute(attributes, "live_request_source_kind").as_deref()
        == Some("live_proxy_observed")
        && string_attribute(attributes, "session_correlation_status").as_deref()
            == Some("runtime_path_confirmed")
        && string_attribute(attributes, "request_id").is_some()
        && string_attribute(attributes, "correlation_id").is_some()
}

fn string_attribute(attributes: &agenta_core::JsonMap, key: &str) -> Option<String> {
    attributes
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalStatus, CollectorKind, EventEnvelope,
        EventType, JsonMap, PolicyDecisionKind, ResultInfo, ResultStatus, SessionRef, SourceInfo,
    };
    use agenta_policy::{
        PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, approval_request_from_decision,
    };
    use serde_json::json;

    use super::{RecordPlan, RecordReflectionError};
    use crate::poc::messaging::{policy::PolicyPlan, taxonomy::TaxonomyPlan};

    #[test]
    fn record_plan_preserves_redaction_contract_and_storage_sinks() {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        assert_eq!(plan.stages, vec!["persist", "publish"]);
        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
        assert_eq!(
            plan.redaction_contract,
            "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam"
        );
    }

    #[test]
    fn record_plan_reflects_allow_hold_and_deny_without_re_evaluating_policy() {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

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
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");

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
        .expect("hold decision should yield approval request");
        let (hold_enriched, hold_request) = plan
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");

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
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");

        assert_eq!(allow_enriched.result.status, ResultStatus::Allowed);
        assert!(allow_enriched.enforcement.is_none());
        assert_eq!(hold_enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            hold_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(hold_request.status, ApprovalStatus::Pending);
        assert_eq!(
            hold_request.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Held)
        );
        assert_eq!(deny_enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            deny_enriched.enforcement.as_ref().map(|info| info.status),
            Some(agenta_core::EnforcementStatus::Denied)
        );
    }

    #[test]
    fn record_plan_promotes_live_discord_records_to_validated_observation() {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        let mut allow_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_discord_send_validated",
            provider_id: "discord",
            action_key: "channels.messages.create",
            target: "discord.channels/123456789012345678/messages",
            semantic_surface: "discord.channels",
            method: "POST",
            host: "discord.com",
            path_template: "/api/v10/channels/123456789012345678/messages",
            query_class: "action_arguments",
            primary_scope: "discord.permission:send_messages",
            documented_scopes: &["discord.permission:send_messages"],
            side_effect: "sends a message into a Discord channel",
            privilege_class: "outbound_send",
            action_family: "message.send",
            channel_hint: Some("discord.channels/123456789012345678"),
            conversation_hint: None,
            delivery_scope: Some("public_channel"),
            membership_target_kind: None,
            permission_target_kind: None,
            file_target_kind: None,
            attachment_count_hint: None,
        });
        annotate_live_discord_observation(&mut allow_observed);
        let allow_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&allow_observed))
            .expect("allow decision should evaluate");
        let allow_reflected = plan
            .reflect_allow(&allow_observed, &allow_decision)
            .expect("allow reflection should succeed");
        assert_eq!(
            allow_reflected.action.attributes.get("validation_status"),
            Some(&json!("validated_observation"))
        );
        assert_eq!(
            allow_reflected
                .action
                .attributes
                .get("validation_capture_source"),
            Some(&json!("forward_proxy_observed_runtime_path"))
        );

        let mut hold_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_discord_invite_validated",
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
        annotate_live_discord_observation(&mut hold_observed);
        let hold_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&hold_observed))
            .expect("hold decision should evaluate");
        let hold_request = approval_request_from_decision(
            &agenta_policy::apply_decision_to_event(&hold_observed, &hold_decision),
            &hold_decision,
        )
        .expect("hold decision should yield approval request");
        let (hold_reflected, hold_request) = plan
            .reflect_hold(&hold_observed, &hold_decision, &hold_request)
            .expect("hold reflection should succeed");
        assert_eq!(
            hold_reflected.action.attributes.get("validation_status"),
            Some(&json!("validated_observation"))
        );
        assert_eq!(
            hold_request.request.attributes.get("validation_status"),
            Some(&json!("validated_observation"))
        );

        let mut deny_observed = fixture_event(MessagingFixture {
            event_id: "evt_msg_discord_permission_validated",
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
        annotate_live_discord_observation(&mut deny_observed);
        let deny_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&deny_observed))
            .expect("deny decision should evaluate");
        let deny_reflected = plan
            .reflect_deny(&deny_observed, &deny_decision)
            .expect("deny reflection should succeed");
        assert_eq!(
            deny_reflected.action.attributes.get("validation_status"),
            Some(&json!("validated_observation"))
        );
    }

    #[test]
    fn record_plan_rejects_unexpected_decision_kind() {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());
        let event = fixture_event(MessagingFixture {
            event_id: "evt_msg_reject_wrong_decision",
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
        let deny_decision = RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&PolicyInput::from_event(&fixture_event(MessagingFixture {
                event_id: "evt_msg_discord_permission_for_reject",
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
            })))
            .expect("deny decision should evaluate");

        assert_eq!(
            plan.reflect_allow(&event, &deny_decision),
            Err(RecordReflectionError::UnexpectedDecision {
                event_id: "evt_msg_reject_wrong_decision".to_owned(),
                expected: PolicyDecisionKind::Allow,
                actual: PolicyDecisionKind::Deny,
            })
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
                session_id: "sess_messaging_record".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_messaging_record".to_owned()),
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
                reason: Some("observed by hostd messaging record fixture".to_owned()),
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

    fn annotate_live_discord_observation(event: &mut EventEnvelope) {
        event.action.attributes.insert(
            "observation_provenance".to_owned(),
            json!("observed_request"),
        );
        event.action.attributes.insert(
            "live_request_source_kind".to_owned(),
            json!("live_proxy_observed"),
        );
        event.action.attributes.insert(
            "session_correlation_status".to_owned(),
            json!("runtime_path_confirmed"),
        );
        event.action.attributes.insert(
            "correlation_id".to_owned(),
            json!(format!("corr_{}", event.event_id)),
        );
    }
}
