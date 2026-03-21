use super::contract::{
    ClassifiedMessagingAction, MESSAGING_GOVERNANCE_REDACTION_RULE, MessagingActionKind,
    MessagingContractBoundary, MessagingProviderActionCandidate, MessagingSemanticSurface,
    ProviderMessagingInputBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyPlan {
    pub providers: Vec<&'static str>,
    pub semantic_surfaces: Vec<MessagingSemanticSurface>,
    pub action_families: Vec<&'static str>,
    pub provider_actions: Vec<MessagingActionKind>,
    pub upstream_provider_contract_fields: Vec<&'static str>,
    pub upstream_generic_rest_fields: Vec<&'static str>,
    pub upstream_provider_taxonomy_fields: Vec<&'static str>,
    pub classification_fields: Vec<&'static str>,
    pub messaging_contract_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    provider_input: ProviderMessagingInputBoundary,
    handoff: MessagingContractBoundary,
}

impl Default for TaxonomyPlan {
    fn default() -> Self {
        Self {
            providers: vec!["slack", "discord"],
            semantic_surfaces: vec![
                MessagingSemanticSurface::SlackChat,
                MessagingSemanticSurface::SlackConversations,
                MessagingSemanticSurface::SlackFiles,
                MessagingSemanticSurface::DiscordChannels,
                MessagingSemanticSurface::DiscordThreads,
                MessagingSemanticSurface::DiscordPermissions,
            ],
            action_families: vec![
                "message.send",
                "channel.invite",
                "permission.update",
                "file.upload",
            ],
            provider_actions: vec![
                MessagingActionKind::SlackChatPostMessage,
                MessagingActionKind::SlackConversationsInvite,
                MessagingActionKind::SlackFilesUploadV2,
                MessagingActionKind::DiscordChannelsMessagesCreate,
                MessagingActionKind::DiscordChannelsThreadMembersPut,
                MessagingActionKind::DiscordChannelsPermissionsPut,
            ],
            upstream_provider_contract_fields: vec!["provider_id", "action_key", "target_hint"],
            upstream_generic_rest_fields: vec![
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ],
            upstream_provider_taxonomy_fields: vec![
                "semantic_surface",
                "classifier_labels",
                "classifier_reasons",
            ],
            classification_fields: vec![
                "semantic_surface",
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
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ],
            messaging_contract_fields: vec![
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
            ],
            responsibilities: vec![
                "join provider action identity, provider-local semantic hints, and generic REST lineage into a shared collaboration action family without re-running provider-specific route matching downstream",
                "define a minimal shared taxonomy for Slack and Discord style collaboration actions covering message delivery, channel or thread invite flows, permission mutations, and file publication",
                "preserve only redaction-safe collaboration hints for downstream policy and audit explainability without carrying raw message bodies, participant rosters, or uploaded bytes",
            ],
            stages: vec!["provider_join", "family_inference", "label", "handoff"],
            provider_input: ProviderMessagingInputBoundary {
                providers: vec!["slack", "discord"],
                provider_contract_fields: vec!["provider_id", "action_key", "target_hint"],
                generic_rest_fields: vec![
                    "method",
                    "host",
                    "path_template",
                    "query_class",
                    "oauth_scope_labels",
                    "side_effect",
                    "privilege_class",
                ],
                provider_taxonomy_fields: vec![
                    "semantic_surface",
                    "classifier_labels",
                    "classifier_reasons",
                ],
                redaction_contract: MESSAGING_GOVERNANCE_REDACTION_RULE,
            },
            handoff: MessagingContractBoundary {
                providers: vec!["slack", "discord"],
                action_families: vec![
                    "message.send",
                    "channel.invite",
                    "permission.update",
                    "file.upload",
                ],
                input_fields: vec![
                    "provider_id",
                    "action_key",
                    "target_hint",
                    "method",
                    "host",
                    "path_template",
                    "query_class",
                    "oauth_scope_labels",
                    "side_effect",
                    "privilege_class",
                    "semantic_surface",
                    "classifier_labels",
                    "classifier_reasons",
                ],
                contract_fields: vec![
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
                ],
                redaction_contract: MESSAGING_GOVERNANCE_REDACTION_RULE,
            },
        }
    }
}

impl TaxonomyPlan {
    pub fn provider_input(&self) -> ProviderMessagingInputBoundary {
        self.provider_input.clone()
    }

    pub fn handoff(&self) -> MessagingContractBoundary {
        self.handoff.clone()
    }

    pub fn preview_candidates(&self) -> Vec<MessagingProviderActionCandidate> {
        vec![
            MessagingProviderActionCandidate::preview_slack_chat_post_message(),
            MessagingProviderActionCandidate::preview_slack_conversations_invite(),
            MessagingProviderActionCandidate::preview_slack_files_upload_v2(),
            MessagingProviderActionCandidate::preview_discord_channels_messages_create(),
            MessagingProviderActionCandidate::preview_discord_channels_thread_members_put(),
            MessagingProviderActionCandidate::preview_discord_channels_permissions_put(),
        ]
    }

    pub fn classify_action(
        &self,
        action: &MessagingProviderActionCandidate,
    ) -> Option<ClassifiedMessagingAction> {
        let semantic_action =
            MessagingActionKind::from_provider_action_id(&action.provider_action.id())?;
        if action.semantic_surface != semantic_action.surface() {
            return None;
        }

        let channel_hint = channel_hint(semantic_action, action.provider_action.target_hint());
        let conversation_hint =
            conversation_hint(semantic_action, action.provider_action.target_hint());
        let mut classifier_labels = action.classifier_labels.clone();
        for label in semantic_action.classifier_labels() {
            if !classifier_labels.iter().any(|existing| existing == label) {
                classifier_labels.push(label.to_owned());
            }
        }
        let mut classifier_reasons = action.classifier_reasons.clone();
        let reason = semantic_action.reason().to_owned();
        if !classifier_reasons
            .iter()
            .any(|existing| existing == &reason)
        {
            classifier_reasons.push(reason);
        }

        Some(ClassifiedMessagingAction {
            source: action.source,
            semantic_surface: action.semantic_surface,
            semantic_action,
            provider_action: action.provider_action.clone(),
            action_family: semantic_action.family(),
            method: action.method,
            host: action.host.clone(),
            path_template: action.path_template.clone(),
            query_class: action.query_class,
            side_effect: action.side_effect.clone(),
            privilege_class: action.privilege_class,
            target_hint: action.provider_action.target_hint().to_owned(),
            channel_hint,
            conversation_hint,
            delivery_scope: semantic_action.delivery_scope(),
            membership_target_kind: semantic_action.membership_target_kind(),
            permission_target_kind: semantic_action.permission_target_kind(),
            file_target_kind: semantic_action.file_target_kind(),
            attachment_count_hint: action
                .attachment_count_hint
                .or_else(|| semantic_action.default_attachment_count_hint()),
            classifier_labels,
            classifier_reasons,
            content_retained: false,
        })
    }

    pub fn summary(&self) -> String {
        let surfaces = self
            .semantic_surfaces
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let actions = self
            .provider_actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "providers={} surfaces={} action_families={} upstream_provider_contract={} upstream_generic_rest={} upstream_provider_taxonomy={} classification_fields={} actions={} messaging_fields={} stages={}",
            self.providers.join(","),
            surfaces,
            self.action_families.join(","),
            self.upstream_provider_contract_fields.join(","),
            self.upstream_generic_rest_fields.join(","),
            self.upstream_provider_taxonomy_fields.join(","),
            self.classification_fields.join(","),
            actions,
            self.messaging_contract_fields.join(","),
            self.stages.join("->")
        )
    }
}

fn channel_hint(action: MessagingActionKind, target_hint: &str) -> Option<String> {
    match action {
        MessagingActionKind::SlackChatPostMessage => Some(target_hint.to_owned()),
        MessagingActionKind::SlackConversationsInvite => target_hint
            .split_once("/members/")
            .map(|(channel, _)| channel.to_owned()),
        MessagingActionKind::SlackFilesUploadV2 => target_hint
            .split_once("/files/")
            .map(|(channel, _)| channel.to_owned()),
        MessagingActionKind::DiscordChannelsMessagesCreate => {
            target_hint.strip_suffix("/messages").map(str::to_owned)
        }
        MessagingActionKind::DiscordChannelsPermissionsPut => target_hint
            .split_once("/permissions/")
            .map(|(channel, _)| channel.to_owned()),
        MessagingActionKind::DiscordChannelsThreadMembersPut => None,
    }
}

fn conversation_hint(action: MessagingActionKind, target_hint: &str) -> Option<String> {
    match action {
        MessagingActionKind::DiscordChannelsThreadMembersPut => target_hint
            .split_once("/members/")
            .map(|(thread, _)| thread.to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::provider::{ActionKey, ProviderId, ProviderSemanticAction};

    use super::TaxonomyPlan;
    use crate::poc::messaging::contract::{
        DeliveryScope, MembershipTargetKind, MessagingActionFamily, MessagingActionKind,
        MessagingProviderActionCandidate, MessagingSemanticSurface, PermissionTargetKind,
    };

    #[test]
    fn taxonomy_plan_exposes_minimal_slack_and_discord_actions_without_policy_or_record_logic() {
        let plan = TaxonomyPlan::default();

        assert_eq!(plan.providers, vec!["slack", "discord"]);
        assert_eq!(
            plan.provider_actions,
            vec![
                MessagingActionKind::SlackChatPostMessage,
                MessagingActionKind::SlackConversationsInvite,
                MessagingActionKind::SlackFilesUploadV2,
                MessagingActionKind::DiscordChannelsMessagesCreate,
                MessagingActionKind::DiscordChannelsThreadMembersPut,
                MessagingActionKind::DiscordChannelsPermissionsPut,
            ]
        );
        assert_eq!(
            plan.classification_fields,
            vec![
                "semantic_surface",
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
                "classifier_labels",
                "classifier_reasons",
                "content_retained",
            ]
        );
    }

    #[test]
    fn classify_slack_message_send_channel_invite_and_file_upload() {
        let plan = TaxonomyPlan::default();

        let message_send = plan
            .classify_action(&MessagingProviderActionCandidate::preview_slack_chat_post_message())
            .expect("slack message send should classify");
        let channel_invite = plan
            .classify_action(
                &MessagingProviderActionCandidate::preview_slack_conversations_invite(),
            )
            .expect("slack channel invite should classify");
        let file_upload = plan
            .classify_action(&MessagingProviderActionCandidate::preview_slack_files_upload_v2())
            .expect("slack file upload should classify");

        assert_eq!(
            message_send.semantic_action,
            MessagingActionKind::SlackChatPostMessage
        );
        assert_eq!(
            message_send.action_family,
            MessagingActionFamily::MessageSend
        );
        assert_eq!(
            message_send.channel_hint.as_deref(),
            Some("slack.channels/C12345678")
        );
        assert_eq!(
            message_send.delivery_scope,
            Some(DeliveryScope::PublicChannel)
        );

        assert_eq!(
            channel_invite.semantic_action,
            MessagingActionKind::SlackConversationsInvite
        );
        assert_eq!(
            channel_invite.action_family,
            MessagingActionFamily::ChannelInvite
        );
        assert_eq!(
            channel_invite.channel_hint.as_deref(),
            Some("slack.channels/C12345678")
        );
        assert_eq!(
            channel_invite.membership_target_kind,
            Some(MembershipTargetKind::ChannelMember)
        );

        assert_eq!(
            file_upload.semantic_action,
            MessagingActionKind::SlackFilesUploadV2
        );
        assert_eq!(file_upload.action_family, MessagingActionFamily::FileUpload);
        assert_eq!(file_upload.attachment_count_hint, Some(1));
        assert!(
            file_upload
                .classifier_labels
                .iter()
                .any(|label| label == "file.upload")
        );
    }

    #[test]
    fn classify_discord_message_invite_and_permission_updates() {
        let plan = TaxonomyPlan::default();

        let message_send = plan
            .classify_action(
                &MessagingProviderActionCandidate::preview_discord_channels_messages_create(),
            )
            .expect("discord message send should classify");
        let thread_invite = plan
            .classify_action(
                &MessagingProviderActionCandidate::preview_discord_channels_thread_members_put(),
            )
            .expect("discord thread invite should classify");
        let permission_update = plan
            .classify_action(
                &MessagingProviderActionCandidate::preview_discord_channels_permissions_put(),
            )
            .expect("discord permission update should classify");

        assert_eq!(
            message_send.semantic_action,
            MessagingActionKind::DiscordChannelsMessagesCreate
        );
        assert_eq!(
            message_send.action_family,
            MessagingActionFamily::MessageSend
        );
        assert_eq!(
            message_send.channel_hint.as_deref(),
            Some("discord.channels/123456789012345678")
        );

        assert_eq!(
            thread_invite.semantic_action,
            MessagingActionKind::DiscordChannelsThreadMembersPut
        );
        assert_eq!(
            thread_invite.action_family,
            MessagingActionFamily::ChannelInvite
        );
        assert_eq!(thread_invite.delivery_scope, Some(DeliveryScope::Thread));
        assert_eq!(
            thread_invite.conversation_hint.as_deref(),
            Some("discord.threads/123456789012345678")
        );
        assert_eq!(
            thread_invite.membership_target_kind,
            Some(MembershipTargetKind::ThreadMember)
        );

        assert_eq!(
            permission_update.semantic_action,
            MessagingActionKind::DiscordChannelsPermissionsPut
        );
        assert_eq!(
            permission_update.action_family,
            MessagingActionFamily::PermissionUpdate
        );
        assert_eq!(
            permission_update.permission_target_kind,
            Some(PermissionTargetKind::ChannelPermissionOverwrite)
        );
        assert_eq!(
            permission_update.channel_hint.as_deref(),
            Some("discord.channels/123456789012345678")
        );
    }

    #[test]
    fn classify_returns_none_for_unsupported_action_or_surface_mismatch() {
        let plan = TaxonomyPlan::default();
        let mut unsupported = MessagingProviderActionCandidate::preview_slack_chat_post_message();
        unsupported.provider_action = ProviderSemanticAction::new(
            ProviderId::new("slack").unwrap(),
            ActionKey::new("chat.delete").unwrap(),
            "slack.channels/C12345678",
        );
        assert!(plan.classify_action(&unsupported).is_none());

        let mut mismatched_surface =
            MessagingProviderActionCandidate::preview_discord_channels_permissions_put();
        mismatched_surface.semantic_surface = MessagingSemanticSurface::DiscordChannels;
        assert!(plan.classify_action(&mismatched_surface).is_none());
    }

    #[test]
    fn taxonomy_summary_mentions_surfaces_actions_and_stages() {
        let summary = TaxonomyPlan::default().summary();

        assert!(summary.contains("surfaces=slack.chat,slack.conversations,slack.files,discord.channels,discord.threads,discord.permissions"));
        assert!(
            summary.contains(
                "action_families=message.send,channel.invite,permission.update,file.upload"
            )
        );
        assert!(summary.contains("actions=chat.post_message,conversations.invite,files.upload_v2,channels.messages.create,channels.thread_members.put,channels.permissions.put"));
        assert!(summary.contains("stages=provider_join->family_inference->label->handoff"));
    }
}
