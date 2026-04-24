use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{
    ClassifiedMessagingAction, MessagingActionKind, MessagingContractBoundary,
    MessagingSignalSource, PolicyBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: PolicyBoundary,
}

impl PolicyPlan {
    pub fn from_contract_boundary(contract: MessagingContractBoundary) -> Self {
        Self {
            providers: contract.providers.clone(),
            action_families: contract.action_families.clone(),
            input_fields: contract.contract_fields.clone(),
            decision_fields: vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ],
            responsibilities: vec![
                "bridge the messaging / collaboration contract into agenta-policy without re-running provider-specific route heuristics",
                "evaluate shared collaboration action families such as message.send, channel.invite, permission.update, and file.upload using redaction-safe collaboration hints and preserved lineage",
                "project allow, deny, and require_approval outcomes plus approval-request candidates while carrying the messaging redaction contract forward",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: PolicyBoundary {
                providers: contract.providers,
                action_families: contract.action_families,
                input_fields: contract.contract_fields,
                decision_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: contract.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> PolicyBoundary {
        self.handoff.clone()
    }

    pub fn normalize_classified_action(
        &self,
        action: &ClassifiedMessagingAction,
        session: &SessionRecord,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(action.source.to_string()));
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
            json!(action.provider_action.id().to_string()),
        );
        attributes.insert(
            "semantic_surface".to_owned(),
            json!(action.semantic_surface.to_string()),
        );
        attributes.insert(
            "semantic_action_label".to_owned(),
            json!(action.semantic_action.to_string()),
        );
        attributes.insert(
            "action_family".to_owned(),
            json!(action.action_family.to_string()),
        );
        attributes.insert("target_hint".to_owned(), json!(action.target_hint));
        attributes.insert("method".to_owned(), json!(action.method.to_string()));
        attributes.insert("host".to_owned(), json!(action.host.as_str()));
        attributes.insert(
            "path_template".to_owned(),
            json!(action.path_template.as_str()),
        );
        attributes.insert(
            "query_class".to_owned(),
            json!(action.query_class.to_string()),
        );
        let (primary_scope, documented_scopes) = oauth_scope_labels(action.semantic_action);
        attributes.insert(
            "oauth_scope_labels".to_owned(),
            json!({
                "primary": primary_scope,
                "documented": documented_scopes,
            }),
        );
        attributes.insert("side_effect".to_owned(), json!(action.side_effect.as_str()));
        attributes.insert(
            "privilege_class".to_owned(),
            json!(action.privilege_class.to_string()),
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

        if let Some(channel_hint) = &action.channel_hint {
            attributes.insert("channel_hint".to_owned(), json!(channel_hint));
        }
        if let Some(conversation_hint) = &action.conversation_hint {
            attributes.insert("conversation_hint".to_owned(), json!(conversation_hint));
        }
        if let Some(delivery_scope) = action.delivery_scope {
            attributes.insert(
                "delivery_scope".to_owned(),
                json!(delivery_scope.to_string()),
            );
        }
        if let Some(target_kind) = action.membership_target_kind {
            attributes.insert(
                "membership_target_kind".to_owned(),
                json!(target_kind.to_string()),
            );
        }
        if let Some(target_kind) = action.permission_target_kind {
            attributes.insert(
                "permission_target_kind".to_owned(),
                json!(target_kind.to_string()),
            );
        }
        if let Some(target_kind) = action.file_target_kind {
            attributes.insert(
                "file_target_kind".to_owned(),
                json!(target_kind.to_string()),
            );
        }
        if let Some(attachment_count_hint) = action.attachment_count_hint {
            attributes.insert(
                "attachment_count_hint".to_owned(),
                json!(attachment_count_hint),
            );
        }

        EventEnvelope::new(
            format!(
                "poc_messaging_action_{}_{}_{}",
                action.source,
                action.semantic_action,
                sanitize_id_segment(&action.target_hint)
            ),
            EventType::NetworkConnect,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Browser,
                verb: Some(action.provider_action.action_key.to_string()),
                target: Some(action.target_hint.clone()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd messaging collaboration PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(action.source),
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} action_families={} input_fields={} decision_fields={} stages={}",
            self.providers.join(","),
            self.action_families.join(","),
            self.input_fields.join(","),
            self.decision_fields.join(","),
            self.stages.join("->")
        )
    }
}

fn oauth_scope_labels(action: MessagingActionKind) -> (&'static str, Vec<&'static str>) {
    match action {
        MessagingActionKind::SlackChatPostMessage => {
            ("slack.scope:chat:write", vec!["slack.scope:chat:write"])
        }
        MessagingActionKind::SlackConversationsInvite => (
            "slack.scope:conversations:write",
            vec!["slack.scope:conversations:write"],
        ),
        MessagingActionKind::SlackFilesUploadV2 => {
            ("slack.scope:files:write", vec!["slack.scope:files:write"])
        }
        MessagingActionKind::DiscordChannelsMessagesCreate => (
            "discord.permission:send_messages",
            vec!["discord.permission:send_messages"],
        ),
        MessagingActionKind::DiscordChannelsMessagesUpdate => (
            "discord.permission:send_messages",
            vec!["discord.permission:send_messages"],
        ),
        MessagingActionKind::DiscordChannelsMessagesReactionsCreate => (
            "discord.permission:add_reactions",
            vec![
                "discord.permission:add_reactions",
                "discord.permission:read_message_history",
            ],
        ),
        MessagingActionKind::DiscordChannelsTypingTrigger => (
            "discord.permission:send_messages",
            vec!["discord.permission:send_messages"],
        ),
        MessagingActionKind::DiscordChannelsThreadMembersPut => (
            "discord.permission:create_public_threads",
            vec![
                "discord.permission:create_public_threads",
                "discord.permission:send_messages_in_threads",
            ],
        ),
        MessagingActionKind::DiscordChannelsPermissionsPut => (
            "discord.permission:manage_roles",
            vec!["discord.permission:manage_channels"],
        ),
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

fn source_info(source: MessagingSignalSource) -> SourceInfo {
    SourceInfo {
        collector: collector_for_source(source),
        host_id: Some("hostd-poc".to_owned()),
        container_id: None,
        pod_uid: None,
        pid: None,
        ppid: None,
    }
}

fn collector_for_source(_source: MessagingSignalSource) -> CollectorKind {
    CollectorKind::RuntimeHint
}

fn sanitize_id_segment(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use agenta_core::{ActionClass, EventType, SessionRecord};
    use serde_json::json;

    use super::PolicyPlan;
    use crate::poc::messaging::{
        contract::{MessagingActionFamily, MessagingActionKind},
        taxonomy::TaxonomyPlan,
    };

    #[test]
    fn policy_plan_keeps_existing_contract_summary() {
        let plan = PolicyPlan::from_contract_boundary(TaxonomyPlan::default().handoff());

        assert!(
            plan.summary()
                .contains("stages=normalize->policy->approval_projection")
        );
        assert_eq!(
            plan.decision_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
    }

    #[test]
    fn policy_plan_normalizes_classified_messaging_action_into_policy_input_event() {
        let plan = PolicyPlan::from_contract_boundary(TaxonomyPlan::default().handoff());
        let action = TaxonomyPlan::default()
            .classify_action(&crate::poc::messaging::contract::MessagingProviderActionCandidate::preview_discord_channels_permissions_put())
            .expect("preview Discord permission overwrite should classify");
        let event = plan.normalize_classified_action(
            &action,
            &SessionRecord::placeholder("openclaw-main", "sess_messaging_policy_preview"),
        );

        assert_eq!(event.event_type, EventType::NetworkConnect);
        assert_eq!(event.action.class, ActionClass::Browser);
        assert_eq!(
            event.action.verb.as_deref(),
            Some("channels.permissions.put")
        );
        assert_eq!(
            event.action.attributes.get("action_family"),
            Some(&json!(MessagingActionFamily::PermissionUpdate.to_string()))
        );
        assert_eq!(
            event.action.attributes.get("semantic_action_label"),
            Some(&json!(
                MessagingActionKind::DiscordChannelsPermissionsPut.to_string()
            ))
        );
        assert_eq!(
            event.action.attributes.get("permission_target_kind"),
            Some(&json!("channel_permission_overwrite"))
        );
    }
}
