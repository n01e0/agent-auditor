use std::fmt;

use agenta_core::{
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
        LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{PrivilegeClass, ProviderId, ProviderMethod, SideEffect},
    rest::{PathTemplate, QueryClass, RestHost},
};

use crate::poc::messaging::{
    contract::{
        ClassifiedMessagingAction, MessagingActionKind, MessagingProviderActionCandidate,
        MessagingSignalSource,
    },
    taxonomy::TaxonomyPlan,
};

use super::contract::LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

pub const LIVE_PROXY_MESSAGING_REDACTION_RULE: &str = LIVE_PROXY_INTERCEPTION_REDACTION_RULE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingLivePreviewAdapterPlan {
    pub upstream_fields: Vec<&'static str>,
    pub provider_fields: Vec<&'static str>,
    pub messaging_fields: Vec<&'static str>,
    pub provider_actions: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
    taxonomy: TaxonomyPlan,
}

impl Default for MessagingLivePreviewAdapterPlan {
    fn default() -> Self {
        let taxonomy = TaxonomyPlan::default();
        Self {
            upstream_fields: GenericLiveActionEnvelope::field_names().to_vec(),
            provider_fields: vec![
                "provider_id",
                "action_key",
                "target_hint",
                "method",
                "host",
                "path_template",
                "query_class",
                "side_effect",
                "privilege_class",
                "semantic_surface",
                "classifier_labels",
                "classifier_reasons",
                "attachment_count_hint",
            ],
            messaging_fields: taxonomy.handoff().contract_fields,
            provider_actions: vec![
                "slack:chat.post_message",
                "slack:conversations.invite",
                "slack:files.upload_v2",
                "discord:channels.messages.create",
                "discord:channels.messages.update",
                "discord:channels.messages.reactions.create",
                "discord:channels.typing.trigger",
                "discord:channels.thread_members.put",
                "discord:channels.permissions.put",
            ],
            responsibilities: vec![
                "consume the shared live proxy envelope and derive one provider-scoped messaging candidate without reopening message bodies, participant rosters, or file bytes",
                "map Slack and Discord live preview routes into the checked-in provider semantic actions and then reuse the shared messaging taxonomy boundary",
                "require explicit target hints where the proxy contract intentionally omits body content, such as Slack channel IDs or uploaded file identifiers",
            ],
            stages: vec!["route_match", "provider_candidate", "messaging_taxonomy"],
            redaction_contract: LIVE_PROXY_MESSAGING_REDACTION_RULE,
            taxonomy,
        }
    }
}

impl MessagingLivePreviewAdapterPlan {
    pub fn classify_live_preview(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<ClassifiedMessagingAction, LiveMessagingPreviewError> {
        let candidate = provider_candidate_from_live_envelope(envelope)?;
        self.taxonomy.classify_action(&candidate).ok_or_else(|| {
            LiveMessagingPreviewError::SurfaceMismatch(candidate.provider_action.id().to_string())
        })
    }

    pub fn preview_slack_chat_post_message(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_slack_chat_post_message())
            .expect("Slack message send preview should classify")
    }

    pub fn preview_slack_conversations_invite(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_slack_conversations_invite())
            .expect("Slack channel invite preview should classify")
    }

    pub fn preview_slack_files_upload_v2(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_slack_files_upload_v2())
            .expect("Slack file upload preview should classify")
    }

    pub fn preview_discord_channels_messages_create(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_messages_create())
            .expect("Discord message create preview should classify")
    }

    pub fn preview_discord_channels_messages_update(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_messages_update())
            .expect("Discord message update preview should classify")
    }

    pub fn preview_discord_channels_messages_reactions_create(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_messages_reactions_create())
            .expect("Discord reaction add preview should classify")
    }

    pub fn preview_discord_channels_typing_trigger(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_typing_trigger())
            .expect("Discord typing preview should classify")
    }

    pub fn preview_discord_channels_thread_members_put(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_thread_members_put())
            .expect("Discord thread member add preview should classify")
    }

    pub fn preview_discord_channels_permissions_put(&self) -> ClassifiedMessagingAction {
        self.classify_live_preview(&preview_discord_channels_permissions_put())
            .expect("Discord permission overwrite preview should classify")
    }

    pub fn summary(&self) -> String {
        format!(
            "provider_actions={} messaging_fields={} stages={}",
            self.provider_actions.join(","),
            self.messaging_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchedMessagingRoute {
    SlackChatPostMessage { target_hint: String },
    SlackConversationsInvite { target_hint: String },
    SlackFilesUploadV2 { target_hint: String },
    DiscordChannelsMessagesCreate { target_hint: String },
    DiscordChannelsMessagesUpdate { target_hint: String },
    DiscordChannelsMessagesReactionsCreate { target_hint: String },
    DiscordChannelsTypingTrigger { target_hint: String },
    DiscordChannelsThreadMembersPut { target_hint: String },
    DiscordChannelsPermissionsPut { target_hint: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveMessagingPreviewError {
    MissingProviderHint,
    MissingTargetHint(&'static str),
    UnsupportedProviderHint(ProviderId),
    UnsupportedPreviewRoute {
        provider_hint: ProviderId,
        method: ProviderMethod,
        authority: String,
        path: String,
        target_hint: Option<String>,
    },
    SurfaceMismatch(String),
}

impl fmt::Display for LiveMessagingPreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProviderHint => {
                write!(f, "messaging live preview adapter requires a provider_hint")
            }
            Self::MissingTargetHint(route) => write!(
                f,
                "messaging live preview adapter requires a redaction-safe target_hint for {}",
                route
            ),
            Self::UnsupportedProviderHint(provider) => write!(
                f,
                "messaging live preview adapter only supports provider_hint=slack or provider_hint=discord, received {}",
                provider
            ),
            Self::UnsupportedPreviewRoute {
                provider_hint,
                method,
                authority,
                path,
                target_hint,
            } => write!(
                f,
                "no messaging live preview route matches provider_hint={} method={} authority={} path={} target_hint={}",
                provider_hint,
                method,
                authority,
                path,
                target_hint.as_deref().unwrap_or("none")
            ),
            Self::SurfaceMismatch(provider_action) => write!(
                f,
                "messaging taxonomy rejected live preview provider action {} due to a surface mismatch",
                provider_action
            ),
        }
    }
}

fn provider_candidate_from_live_envelope(
    envelope: &GenericLiveActionEnvelope,
) -> Result<MessagingProviderActionCandidate, LiveMessagingPreviewError> {
    let provider_hint = envelope
        .provider_hint
        .clone()
        .ok_or(LiveMessagingPreviewError::MissingProviderHint)?;
    let route = match_messaging_route(envelope, &provider_hint)?;

    Ok(match route {
        MatchedMessagingRoute::SlackChatPostMessage { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::SlackChatPostMessage,
            target_hint,
            ProviderMethod::Post,
            "slack.com",
            "/api/chat.postMessage",
            QueryClass::ActionArguments,
            "sends a message into a Slack conversation",
            PrivilegeClass::OutboundSend,
            None,
        ),
        MatchedMessagingRoute::SlackConversationsInvite { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::SlackConversationsInvite,
            target_hint,
            ProviderMethod::Post,
            "slack.com",
            "/api/conversations.invite",
            QueryClass::ActionArguments,
            "invites one or more members into a Slack channel",
            PrivilegeClass::SharingWrite,
            None,
        ),
        MatchedMessagingRoute::SlackFilesUploadV2 { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::SlackFilesUploadV2,
            target_hint,
            ProviderMethod::Post,
            "slack.com",
            "/api/files.uploadV2",
            QueryClass::ActionArguments,
            "uploads a file into a Slack conversation",
            PrivilegeClass::ContentWrite,
            Some(1),
        ),
        MatchedMessagingRoute::DiscordChannelsMessagesCreate { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsMessagesCreate,
            target_hint,
            ProviderMethod::Post,
            "discord.com",
            "/api/v10/channels/{channel_id}/messages",
            QueryClass::ActionArguments,
            "creates a message in a Discord channel",
            PrivilegeClass::OutboundSend,
            None,
        ),
        MatchedMessagingRoute::DiscordChannelsMessagesUpdate { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsMessagesUpdate,
            target_hint,
            ProviderMethod::Patch,
            "discord.com",
            "/api/v10/channels/{channel_id}/messages/{message_id}",
            QueryClass::None,
            "edits a message in a Discord channel",
            PrivilegeClass::ContentWrite,
            None,
        ),
        MatchedMessagingRoute::DiscordChannelsMessagesReactionsCreate { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsMessagesReactionsCreate,
            target_hint,
            ProviderMethod::Put,
            "discord.com",
            "/api/v10/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me",
            QueryClass::None,
            "adds a reaction to a Discord message",
            PrivilegeClass::ContentWrite,
            None,
        ),
        MatchedMessagingRoute::DiscordChannelsTypingTrigger { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsTypingTrigger,
            target_hint,
            ProviderMethod::Post,
            "discord.com",
            "/api/v10/channels/{channel_id}/typing",
            QueryClass::None,
            "triggers a typing indicator in a Discord channel",
            PrivilegeClass::OutboundSend,
            None,
        ),
        MatchedMessagingRoute::DiscordChannelsThreadMembersPut { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsThreadMembersPut,
            target_hint,
            ProviderMethod::Put,
            "discord.com",
            "/api/v10/channels/{thread_id}/thread-members/{user_id}",
            QueryClass::None,
            "adds a member into a Discord thread",
            PrivilegeClass::SharingWrite,
            None,
        ),
        MatchedMessagingRoute::DiscordChannelsPermissionsPut { target_hint } => candidate(
            envelope.source,
            MessagingActionKind::DiscordChannelsPermissionsPut,
            target_hint,
            ProviderMethod::Put,
            "discord.com",
            "/api/v10/channels/{channel_id}/permissions/{overwrite_id}",
            QueryClass::None,
            "updates a Discord channel permission overwrite",
            PrivilegeClass::SharingWrite,
            None,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn candidate(
    source: LiveCaptureSource,
    action: MessagingActionKind,
    target_hint: String,
    method: ProviderMethod,
    host: &str,
    path_template: &str,
    query_class: QueryClass,
    side_effect: &str,
    privilege_class: PrivilegeClass,
    attachment_count_hint: Option<u16>,
) -> MessagingProviderActionCandidate {
    MessagingProviderActionCandidate {
        source: map_live_source(source),
        semantic_surface: action.surface(),
        provider_action: action.provider_semantic_action(target_hint),
        method,
        host: RestHost::new(host).unwrap(),
        path_template: PathTemplate::new(path_template).unwrap(),
        query_class,
        side_effect: SideEffect::new(side_effect).unwrap(),
        privilege_class,
        classifier_labels: action
            .classifier_labels()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        classifier_reasons: vec![action.reason().to_owned()],
        attachment_count_hint,
    }
}

fn match_messaging_route(
    envelope: &GenericLiveActionEnvelope,
    provider_hint: &ProviderId,
) -> Result<MatchedMessagingRoute, LiveMessagingPreviewError> {
    let method = envelope.method;
    let authority = envelope.authority.as_str();
    let path = envelope.path.as_str();
    let target_hint = envelope.target_hint.clone();

    match provider_hint.as_str() {
        "slack" => match (method, normalize_authority(authority), path) {
            (ProviderMethod::Post, "slack.com", "/api/chat.postMessage") => {
                Ok(MatchedMessagingRoute::SlackChatPostMessage {
                    target_hint: target_hint.ok_or(
                        LiveMessagingPreviewError::MissingTargetHint("slack chat.postMessage"),
                    )?,
                })
            }
            (ProviderMethod::Post, "slack.com", "/api/conversations.invite") => {
                Ok(MatchedMessagingRoute::SlackConversationsInvite {
                    target_hint: target_hint.ok_or(
                        LiveMessagingPreviewError::MissingTargetHint("slack conversations.invite"),
                    )?,
                })
            }
            (ProviderMethod::Post, "slack.com", "/api/files.uploadV2") => {
                Ok(MatchedMessagingRoute::SlackFilesUploadV2 {
                    target_hint: target_hint.ok_or(
                        LiveMessagingPreviewError::MissingTargetHint("slack files.uploadV2"),
                    )?,
                })
            }
            _ => Err(LiveMessagingPreviewError::UnsupportedPreviewRoute {
                provider_hint: provider_hint.clone(),
                method,
                authority: authority.to_owned(),
                path: path.to_owned(),
                target_hint,
            }),
        },
        "discord" => {
            let segments = path_segments(path);
            match (method, normalize_authority(authority), segments.as_slice()) {
                (
                    ProviderMethod::Post,
                    "discord.com",
                    ["api", "v10", "channels", channel_id, "messages"],
                ) => Ok(MatchedMessagingRoute::DiscordChannelsMessagesCreate {
                    target_hint: format!("discord.channels/{}/messages", channel_id),
                }),
                (
                    ProviderMethod::Patch,
                    "discord.com",
                    ["api", "v10", "channels", channel_id, "messages", message_id],
                ) => Ok(MatchedMessagingRoute::DiscordChannelsMessagesUpdate {
                    target_hint: format!("discord.channels/{}/messages/{}", channel_id, message_id),
                }),
                (
                    ProviderMethod::Put,
                    "discord.com",
                    [
                        "api",
                        "v10",
                        "channels",
                        channel_id,
                        "messages",
                        message_id,
                        "reactions",
                        emoji,
                        me,
                    ],
                ) if *me == "@me" || *me == "%40me" => Ok(
                    MatchedMessagingRoute::DiscordChannelsMessagesReactionsCreate {
                        target_hint: format!(
                            "discord.channels/{}/messages/{}/reactions/{}/@me",
                            channel_id, message_id, emoji
                        ),
                    },
                ),
                (
                    ProviderMethod::Post,
                    "discord.com",
                    ["api", "v10", "channels", channel_id, "typing"],
                ) => Ok(MatchedMessagingRoute::DiscordChannelsTypingTrigger {
                    target_hint: format!("discord.channels/{}/typing", channel_id),
                }),
                (
                    ProviderMethod::Put,
                    "discord.com",
                    [
                        "api",
                        "v10",
                        "channels",
                        thread_id,
                        "thread-members",
                        user_id,
                    ],
                ) => Ok(MatchedMessagingRoute::DiscordChannelsThreadMembersPut {
                    target_hint: format!("discord.threads/{}/members/{}", thread_id, user_id),
                }),
                (
                    ProviderMethod::Put,
                    "discord.com",
                    [
                        "api",
                        "v10",
                        "channels",
                        channel_id,
                        "permissions",
                        overwrite_id,
                    ],
                ) => Ok(MatchedMessagingRoute::DiscordChannelsPermissionsPut {
                    target_hint: format!(
                        "discord.channels/{}/permissions/{}",
                        channel_id, overwrite_id
                    ),
                }),
                _ => Err(LiveMessagingPreviewError::UnsupportedPreviewRoute {
                    provider_hint: provider_hint.clone(),
                    method,
                    authority: authority.to_owned(),
                    path: path.to_owned(),
                    target_hint,
                }),
            }
        }
        _ => Err(LiveMessagingPreviewError::UnsupportedProviderHint(
            provider_hint.clone(),
        )),
    }
}

fn map_live_source(source: LiveCaptureSource) -> MessagingSignalSource {
    match source {
        LiveCaptureSource::BrowserRelay => MessagingSignalSource::BrowserObservation,
        LiveCaptureSource::ForwardProxy | LiveCaptureSource::SidecarProxy => {
            MessagingSignalSource::ApiObservation
        }
    }
}

fn normalize_authority(authority: &str) -> &str {
    authority.trim()
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn slack_provider_id() -> ProviderId {
    ProviderId::new("slack").unwrap()
}

fn discord_provider_id() -> ProviderId {
    ProviderId::new("discord").unwrap()
}

fn preview_slack_chat_post_message() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        LiveRequestId::new("req_live_proxy_slack_chat_post_message_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_slack_chat_post_message_preview").unwrap(),
        "sess_live_proxy_slack_chat_post_message_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(slack_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("slack.com").unwrap(),
        LivePath::new("/api/chat.postMessage").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentForm,
            LiveHeaderClass::MessageMetadata,
        ]),
        LiveBodyClass::FormUrlencoded,
        LiveAuthHint::Bearer,
        Some("slack.channels/C12345678".to_owned()),
        LiveInterceptionMode::Shadow,
    )
}

fn preview_slack_conversations_invite() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        LiveRequestId::new("req_live_proxy_slack_conversations_invite_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_slack_conversations_invite_preview").unwrap(),
        "sess_live_proxy_slack_conversations_invite_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(slack_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("slack.com").unwrap(),
        LivePath::new("/api/conversations.invite").unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentForm]),
        LiveBodyClass::FormUrlencoded,
        LiveAuthHint::Bearer,
        Some("slack.channels/C12345678/members/U23456789".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_slack_files_upload_v2() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_slack_files_upload_v2_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_slack_files_upload_v2_preview").unwrap(),
        "sess_live_proxy_slack_files_upload_v2_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(slack_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("slack.com").unwrap(),
        LivePath::new("/api/files.uploadV2").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentForm,
            LiveHeaderClass::FileUploadMetadata,
        ]),
        LiveBodyClass::MultipartFormData,
        LiveAuthHint::Bearer,
        Some("slack.channels/C12345678/files/F12345678".to_owned()),
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_discord_channels_messages_create() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_discord_channels_messages_create_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_discord_channels_messages_create_preview").unwrap(),
        "sess_live_proxy_discord_channels_messages_create_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/messages").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentJson,
            LiveHeaderClass::MessageMetadata,
        ]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::Shadow,
    )
}

fn preview_discord_channels_thread_members_put() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::BrowserRelay,
        LiveRequestId::new("req_live_proxy_discord_channels_thread_members_put_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_discord_channels_thread_members_put_preview")
            .unwrap(),
        "sess_live_proxy_discord_channels_thread_members_put_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/thread-members/234567890123456789")
            .unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::BrowserFetch,
        ]),
        LiveBodyClass::None,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

fn preview_discord_channels_messages_update() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_discord_channels_messages_update_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_discord_channels_messages_update_preview").unwrap(),
        "sess_live_proxy_discord_channels_messages_update_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Patch,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/messages/234567890123456789").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentJson,
            LiveHeaderClass::MessageMetadata,
        ]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::Shadow,
    )
}

fn preview_discord_channels_messages_reactions_create() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new(
            "req_live_proxy_discord_channels_messages_reactions_create_preview",
        )
        .unwrap(),
        LiveCorrelationId::new(
            "corr_live_proxy_discord_channels_messages_reactions_create_preview",
        )
        .unwrap(),
        "sess_live_proxy_discord_channels_messages_reactions_create_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/messages/234567890123456789/reactions/%F0%9F%91%8D/@me")
            .unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::BrowserFetch]),
        LiveBodyClass::None,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::Shadow,
    )
}

fn preview_discord_channels_typing_trigger() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_discord_channels_typing_trigger_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_discord_channels_typing_trigger_preview").unwrap(),
        "sess_live_proxy_discord_channels_typing_trigger_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Post,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/typing").unwrap(),
        LiveHeaders::new([
            LiveHeaderClass::Authorization,
            LiveHeaderClass::BrowserFetch,
        ]),
        LiveBodyClass::None,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::Shadow,
    )
}

fn preview_discord_channels_permissions_put() -> GenericLiveActionEnvelope {
    GenericLiveActionEnvelope::new(
        LiveCaptureSource::ForwardProxy,
        LiveRequestId::new("req_live_proxy_discord_channels_permissions_put_preview").unwrap(),
        LiveCorrelationId::new("corr_live_proxy_discord_channels_permissions_put_preview").unwrap(),
        "sess_live_proxy_discord_channels_permissions_put_preview",
        Some("openclaw-main".to_owned()),
        Some("agent-auditor".to_owned()),
        Some(discord_provider_id()),
        LiveCorrelationStatus::Confirmed,
        LiveSurface::http_request(),
        LiveTransport::new("https").unwrap(),
        ProviderMethod::Put,
        RestHost::new("discord.com").unwrap(),
        LivePath::new("/api/v10/channels/123456789012345678/permissions/role:345678901234567890")
            .unwrap(),
        LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
        LiveBodyClass::Json,
        LiveAuthHint::Bearer,
        None,
        LiveInterceptionMode::EnforcePreview,
    )
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        live::{
            GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
            LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
            LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
        },
        provider::{ProviderId, ProviderMethod},
        rest::RestHost,
    };

    use super::{LiveMessagingPreviewError, MessagingLivePreviewAdapterPlan};

    #[test]
    fn messaging_live_preview_plan_uses_the_shared_live_envelope_contract() {
        let plan = MessagingLivePreviewAdapterPlan::default();

        assert_eq!(
            plan.upstream_fields,
            GenericLiveActionEnvelope::field_names().to_vec()
        );
        assert_eq!(
            plan.provider_actions,
            vec![
                "slack:chat.post_message",
                "slack:conversations.invite",
                "slack:files.upload_v2",
                "discord:channels.messages.create",
                "discord:channels.messages.update",
                "discord:channels.messages.reactions.create",
                "discord:channels.typing.trigger",
                "discord:channels.thread_members.put",
                "discord:channels.permissions.put",
            ]
        );
        assert!(
            plan.summary()
                .contains("stages=route_match->provider_candidate->messaging_taxonomy")
        );
    }

    #[test]
    fn messaging_live_preview_classifies_all_checked_in_provider_actions() {
        let plan = MessagingLivePreviewAdapterPlan::default();

        assert_eq!(
            plan.preview_slack_chat_post_message()
                .semantic_action
                .to_string(),
            "chat.post_message"
        );
        assert_eq!(
            plan.preview_slack_conversations_invite()
                .action_family
                .to_string(),
            "channel.invite"
        );
        let slack_upload = plan.preview_slack_files_upload_v2();
        assert_eq!(slack_upload.semantic_action.to_string(), "files.upload_v2");
        assert_eq!(slack_upload.attachment_count_hint, Some(1));
        assert_eq!(
            plan.preview_discord_channels_messages_create()
                .action_family
                .to_string(),
            "message.send"
        );
        assert_eq!(
            plan.preview_discord_channels_messages_update()
                .action_family
                .to_string(),
            "message.edit"
        );
        assert_eq!(
            plan.preview_discord_channels_messages_reactions_create()
                .action_family
                .to_string(),
            "reaction.add"
        );
        assert_eq!(
            plan.preview_discord_channels_typing_trigger()
                .action_family
                .to_string(),
            "typing.indicate"
        );
        assert_eq!(
            plan.preview_discord_channels_thread_members_put()
                .action_family
                .to_string(),
            "channel.invite"
        );
        let discord_permissions = plan.preview_discord_channels_permissions_put();
        assert_eq!(
            discord_permissions.semantic_action.to_string(),
            "channels.permissions.put"
        );
        assert_eq!(
            discord_permissions
                .permission_target_kind
                .map(|kind| kind.to_string()),
            Some("channel_permission_overwrite".to_owned())
        );

        let discord_reaction = plan.preview_discord_channels_messages_reactions_create();
        assert_eq!(
            discord_reaction.channel_hint.as_deref(),
            Some("discord.channels/123456789012345678")
        );
    }

    #[test]
    fn messaging_live_preview_rejects_missing_target_hint_and_unsupported_routes() {
        let plan = MessagingLivePreviewAdapterPlan::default();
        let missing_target = GenericLiveActionEnvelope::new(
            LiveCaptureSource::BrowserRelay,
            LiveRequestId::new("req_messaging_live_preview_missing_target").unwrap(),
            LiveCorrelationId::new("corr_messaging_live_preview_missing_target").unwrap(),
            "sess_messaging_live_preview_missing_target",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::new("slack").unwrap()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Post,
            RestHost::new("slack.com").unwrap(),
            LivePath::new("/api/chat.postMessage").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::FormUrlencoded,
            LiveAuthHint::Bearer,
            None,
            LiveInterceptionMode::Shadow,
        );
        let unsupported = GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_messaging_live_preview_unsupported").unwrap(),
            LiveCorrelationId::new("corr_messaging_live_preview_unsupported").unwrap(),
            "sess_messaging_live_preview_unsupported",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::new("discord").unwrap()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").unwrap(),
            ProviderMethod::Delete,
            RestHost::new("discord.com").unwrap(),
            LivePath::new("/api/v10/channels/123456789012345678/messages/1").unwrap(),
            LiveHeaders::new([LiveHeaderClass::Authorization]),
            LiveBodyClass::None,
            LiveAuthHint::Bearer,
            None,
            LiveInterceptionMode::Shadow,
        );

        assert!(matches!(
            plan.classify_live_preview(&missing_target),
            Err(LiveMessagingPreviewError::MissingTargetHint(_))
        ));
        assert!(matches!(
            plan.classify_live_preview(&unsupported),
            Err(LiveMessagingPreviewError::UnsupportedPreviewRoute { .. })
        ));
    }
}
