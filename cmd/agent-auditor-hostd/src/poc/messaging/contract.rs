use std::fmt;

use agenta_core::{
    provider::{
        ActionKey, PrivilegeClass, ProviderActionId, ProviderId, ProviderMethod,
        ProviderSemanticAction, SideEffect,
    },
    rest::{PathTemplate, QueryClass, RestHost},
};

pub const MESSAGING_GOVERNANCE_REDACTION_RULE: &str = "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingSignalSource {
    ApiObservation,
    BrowserObservation,
}

impl fmt::Display for MessagingSignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ApiObservation => "api_observation",
            Self::BrowserObservation => "browser_observation",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingSemanticSurface {
    SlackChat,
    SlackConversations,
    SlackFiles,
    DiscordChannels,
    DiscordThreads,
    DiscordPermissions,
}

impl MessagingSemanticSurface {
    pub fn label(self) -> &'static str {
        match self {
            Self::SlackChat => "slack.chat",
            Self::SlackConversations => "slack.conversations",
            Self::SlackFiles => "slack.files",
            Self::DiscordChannels => "discord.channels",
            Self::DiscordThreads => "discord.threads",
            Self::DiscordPermissions => "discord.permissions",
        }
    }
}

impl fmt::Display for MessagingSemanticSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingActionFamily {
    MessageSend,
    ChannelInvite,
    PermissionUpdate,
    FileUpload,
}

impl MessagingActionFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::MessageSend => "message.send",
            Self::ChannelInvite => "channel.invite",
            Self::PermissionUpdate => "permission.update",
            Self::FileUpload => "file.upload",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "message.send" => Some(Self::MessageSend),
            "channel.invite" => Some(Self::ChannelInvite),
            "permission.update" => Some(Self::PermissionUpdate),
            "file.upload" => Some(Self::FileUpload),
            _ => None,
        }
    }
}

impl fmt::Display for MessagingActionFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryScope {
    PublicChannel,
    PrivateChannel,
    Thread,
}

impl DeliveryScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::PublicChannel => "public_channel",
            Self::PrivateChannel => "private_channel",
            Self::Thread => "thread",
        }
    }
}

impl fmt::Display for DeliveryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipTargetKind {
    ChannelMember,
    ThreadMember,
}

impl MembershipTargetKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ChannelMember => "channel_member",
            Self::ThreadMember => "thread_member",
        }
    }
}

impl fmt::Display for MembershipTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionTargetKind {
    ChannelPermissionOverwrite,
}

impl PermissionTargetKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ChannelPermissionOverwrite => "channel_permission_overwrite",
        }
    }
}

impl fmt::Display for PermissionTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTargetKind {
    ChannelAttachment,
}

impl FileTargetKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ChannelAttachment => "channel_attachment",
        }
    }
}

impl fmt::Display for FileTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingActionKind {
    SlackChatPostMessage,
    SlackConversationsInvite,
    SlackFilesUploadV2,
    DiscordChannelsMessagesCreate,
    DiscordChannelsThreadMembersPut,
    DiscordChannelsPermissionsPut,
}

impl MessagingActionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::SlackChatPostMessage => "chat.post_message",
            Self::SlackConversationsInvite => "conversations.invite",
            Self::SlackFilesUploadV2 => "files.upload_v2",
            Self::DiscordChannelsMessagesCreate => "channels.messages.create",
            Self::DiscordChannelsThreadMembersPut => "channels.thread_members.put",
            Self::DiscordChannelsPermissionsPut => "channels.permissions.put",
        }
    }

    pub fn from_label(provider: &str, label: &str) -> Option<Self> {
        match (provider, label) {
            ("slack", "chat.post_message") => Some(Self::SlackChatPostMessage),
            ("slack", "conversations.invite") => Some(Self::SlackConversationsInvite),
            ("slack", "files.upload_v2") => Some(Self::SlackFilesUploadV2),
            ("discord", "channels.messages.create") => Some(Self::DiscordChannelsMessagesCreate),
            ("discord", "channels.thread_members.put") => {
                Some(Self::DiscordChannelsThreadMembersPut)
            }
            ("discord", "channels.permissions.put") => Some(Self::DiscordChannelsPermissionsPut),
            _ => None,
        }
    }

    pub fn family(self) -> MessagingActionFamily {
        match self {
            Self::SlackChatPostMessage | Self::DiscordChannelsMessagesCreate => {
                MessagingActionFamily::MessageSend
            }
            Self::SlackConversationsInvite | Self::DiscordChannelsThreadMembersPut => {
                MessagingActionFamily::ChannelInvite
            }
            Self::DiscordChannelsPermissionsPut => MessagingActionFamily::PermissionUpdate,
            Self::SlackFilesUploadV2 => MessagingActionFamily::FileUpload,
        }
    }

    pub fn surface(self) -> MessagingSemanticSurface {
        match self {
            Self::SlackChatPostMessage => MessagingSemanticSurface::SlackChat,
            Self::SlackConversationsInvite => MessagingSemanticSurface::SlackConversations,
            Self::SlackFilesUploadV2 => MessagingSemanticSurface::SlackFiles,
            Self::DiscordChannelsMessagesCreate => MessagingSemanticSurface::DiscordChannels,
            Self::DiscordChannelsThreadMembersPut => MessagingSemanticSurface::DiscordThreads,
            Self::DiscordChannelsPermissionsPut => MessagingSemanticSurface::DiscordPermissions,
        }
    }

    pub fn provider_id(self) -> ProviderId {
        match self {
            Self::SlackChatPostMessage
            | Self::SlackConversationsInvite
            | Self::SlackFilesUploadV2 => {
                ProviderId::new("slack").expect("slack provider id should be valid")
            }
            Self::DiscordChannelsMessagesCreate
            | Self::DiscordChannelsThreadMembersPut
            | Self::DiscordChannelsPermissionsPut => {
                ProviderId::new("discord").expect("discord provider id should be valid")
            }
        }
    }

    pub fn action_key(self) -> ActionKey {
        ActionKey::new(self.label())
            .expect("messaging action labels must be valid provider action keys")
    }

    pub fn provider_action_id(self) -> ProviderActionId {
        ProviderActionId::new(self.provider_id(), self.action_key())
    }

    pub fn provider_semantic_action(
        self,
        target_hint: impl Into<String>,
    ) -> ProviderSemanticAction {
        ProviderSemanticAction::from_id(self.provider_action_id(), target_hint)
    }

    pub fn from_provider_action_id(action: &ProviderActionId) -> Option<Self> {
        Self::from_label(action.provider_id.as_str(), action.action_key.as_str())
    }

    pub fn classifier_labels(self) -> Vec<&'static str> {
        vec![self.surface().label(), self.family().label(), self.label()]
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::SlackChatPostMessage => {
                "Slack chat.postMessage maps to the shared message.send collaboration family"
            }
            Self::SlackConversationsInvite => {
                "Slack conversations.invite maps to the shared channel.invite collaboration family"
            }
            Self::SlackFilesUploadV2 => {
                "Slack files.uploadV2 maps to the shared file.upload collaboration family"
            }
            Self::DiscordChannelsMessagesCreate => {
                "Discord channel message creation maps to the shared message.send collaboration family"
            }
            Self::DiscordChannelsThreadMembersPut => {
                "Discord thread member add maps to the shared channel.invite collaboration family"
            }
            Self::DiscordChannelsPermissionsPut => {
                "Discord channel permission overwrite updates map to the shared permission.update collaboration family"
            }
        }
    }

    pub fn delivery_scope(self) -> Option<DeliveryScope> {
        match self {
            Self::SlackChatPostMessage
            | Self::SlackConversationsInvite
            | Self::SlackFilesUploadV2
            | Self::DiscordChannelsMessagesCreate => Some(DeliveryScope::PublicChannel),
            Self::DiscordChannelsThreadMembersPut => Some(DeliveryScope::Thread),
            Self::DiscordChannelsPermissionsPut => None,
        }
    }

    pub fn membership_target_kind(self) -> Option<MembershipTargetKind> {
        match self {
            Self::SlackConversationsInvite => Some(MembershipTargetKind::ChannelMember),
            Self::DiscordChannelsThreadMembersPut => Some(MembershipTargetKind::ThreadMember),
            _ => None,
        }
    }

    pub fn permission_target_kind(self) -> Option<PermissionTargetKind> {
        match self {
            Self::DiscordChannelsPermissionsPut => {
                Some(PermissionTargetKind::ChannelPermissionOverwrite)
            }
            _ => None,
        }
    }

    pub fn file_target_kind(self) -> Option<FileTargetKind> {
        match self {
            Self::SlackFilesUploadV2 => Some(FileTargetKind::ChannelAttachment),
            _ => None,
        }
    }

    pub fn default_attachment_count_hint(self) -> Option<u16> {
        match self {
            Self::SlackFilesUploadV2 => Some(1),
            _ => None,
        }
    }
}

impl fmt::Display for MessagingActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingProviderActionCandidate {
    pub source: MessagingSignalSource,
    pub semantic_surface: MessagingSemanticSurface,
    pub provider_action: ProviderSemanticAction,
    pub method: ProviderMethod,
    pub host: RestHost,
    pub path_template: PathTemplate,
    pub query_class: QueryClass,
    pub side_effect: SideEffect,
    pub privilege_class: PrivilegeClass,
    pub classifier_labels: Vec<String>,
    pub classifier_reasons: Vec<String>,
    pub attachment_count_hint: Option<u16>,
}

impl MessagingProviderActionCandidate {
    pub fn preview_slack_chat_post_message() -> Self {
        Self::preview(
            MessagingSignalSource::ApiObservation,
            MessagingActionKind::SlackChatPostMessage,
            "slack.channels/C12345678",
            ProviderMethod::Post,
            "slack.com",
            "/api/chat.postMessage",
            QueryClass::ActionArguments,
            "sends a message into a Slack conversation",
            PrivilegeClass::OutboundSend,
            None,
        )
    }

    pub fn preview_slack_conversations_invite() -> Self {
        Self::preview(
            MessagingSignalSource::ApiObservation,
            MessagingActionKind::SlackConversationsInvite,
            "slack.channels/C12345678/members/U23456789",
            ProviderMethod::Post,
            "slack.com",
            "/api/conversations.invite",
            QueryClass::ActionArguments,
            "invites one or more members into a Slack channel",
            PrivilegeClass::SharingWrite,
            None,
        )
    }

    pub fn preview_slack_files_upload_v2() -> Self {
        Self::preview(
            MessagingSignalSource::ApiObservation,
            MessagingActionKind::SlackFilesUploadV2,
            "slack.channels/C12345678/files/F12345678",
            ProviderMethod::Post,
            "slack.com",
            "/api/files.uploadV2",
            QueryClass::ActionArguments,
            "uploads a file into a Slack conversation",
            PrivilegeClass::ContentWrite,
            Some(1),
        )
    }

    pub fn preview_discord_channels_messages_create() -> Self {
        Self::preview(
            MessagingSignalSource::ApiObservation,
            MessagingActionKind::DiscordChannelsMessagesCreate,
            "discord.channels/123456789012345678/messages",
            ProviderMethod::Post,
            "discord.com",
            "/api/v10/channels/{channel_id}/messages",
            QueryClass::ActionArguments,
            "creates a message in a Discord channel",
            PrivilegeClass::OutboundSend,
            None,
        )
    }

    pub fn preview_discord_channels_thread_members_put() -> Self {
        Self::preview(
            MessagingSignalSource::BrowserObservation,
            MessagingActionKind::DiscordChannelsThreadMembersPut,
            "discord.threads/123456789012345678/members/234567890123456789",
            ProviderMethod::Put,
            "discord.com",
            "/api/v10/channels/{thread_id}/thread-members/{user_id}",
            QueryClass::None,
            "adds a member into a Discord thread",
            PrivilegeClass::SharingWrite,
            None,
        )
    }

    pub fn preview_discord_channels_permissions_put() -> Self {
        Self::preview(
            MessagingSignalSource::ApiObservation,
            MessagingActionKind::DiscordChannelsPermissionsPut,
            "discord.channels/123456789012345678/permissions/role:345678901234567890",
            ProviderMethod::Put,
            "discord.com",
            "/api/v10/channels/{channel_id}/permissions/{overwrite_id}",
            QueryClass::None,
            "updates a Discord channel permission overwrite",
            PrivilegeClass::SharingWrite,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn preview(
        source: MessagingSignalSource,
        action: MessagingActionKind,
        target_hint: &str,
        method: ProviderMethod,
        host: &str,
        path_template: &str,
        query_class: QueryClass,
        side_effect: &str,
        privilege_class: PrivilegeClass,
        attachment_count_hint: Option<u16>,
    ) -> Self {
        Self {
            source,
            semantic_surface: action.surface(),
            provider_action: action.provider_semantic_action(target_hint),
            method,
            host: RestHost::new(host).expect("preview messaging host should be valid"),
            path_template: PathTemplate::new(path_template)
                .expect("preview messaging path template should be valid"),
            query_class,
            side_effect: SideEffect::new(side_effect)
                .expect("preview messaging side effect should be valid"),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedMessagingAction {
    pub source: MessagingSignalSource,
    pub semantic_surface: MessagingSemanticSurface,
    pub semantic_action: MessagingActionKind,
    pub provider_action: ProviderSemanticAction,
    pub action_family: MessagingActionFamily,
    pub method: ProviderMethod,
    pub host: RestHost,
    pub path_template: PathTemplate,
    pub query_class: QueryClass,
    pub side_effect: SideEffect,
    pub privilege_class: PrivilegeClass,
    pub target_hint: String,
    pub channel_hint: Option<String>,
    pub conversation_hint: Option<String>,
    pub delivery_scope: Option<DeliveryScope>,
    pub membership_target_kind: Option<MembershipTargetKind>,
    pub permission_target_kind: Option<PermissionTargetKind>,
    pub file_target_kind: Option<FileTargetKind>,
    pub attachment_count_hint: Option<u16>,
    pub classifier_labels: Vec<String>,
    pub classifier_reasons: Vec<String>,
    pub content_retained: bool,
}

impl ClassifiedMessagingAction {
    pub fn log_line(&self) -> String {
        format!(
            "event=messaging.action source={} provider={} action_key={} family={} target_hint={} channel_hint={} conversation_hint={} delivery_scope={} attachment_count_hint={} content_retained={}",
            self.source,
            self.provider_action.provider_id,
            self.provider_action.action_key,
            self.action_family,
            self.target_hint,
            self.channel_hint.as_deref().unwrap_or("-"),
            self.conversation_hint.as_deref().unwrap_or("-"),
            self.delivery_scope
                .map(|scope| scope.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            self.attachment_count_hint
                .map(|count| count.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            self.content_retained,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMessagingInputBoundary {
    pub providers: Vec<&'static str>,
    pub provider_contract_fields: Vec<&'static str>,
    pub generic_rest_fields: Vec<&'static str>,
    pub provider_taxonomy_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingContractBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[cfg(test)]
mod tests {
    use super::{
        MessagingActionFamily, MessagingActionKind, MessagingProviderActionCandidate,
        MessagingSemanticSurface, MessagingSignalSource,
    };

    #[test]
    fn messaging_action_kinds_map_back_to_expected_provider_actions_and_families() {
        assert_eq!(
            MessagingActionKind::from_provider_action_id(
                &MessagingActionKind::SlackChatPostMessage.provider_action_id()
            ),
            Some(MessagingActionKind::SlackChatPostMessage)
        );
        assert_eq!(
            MessagingActionKind::SlackConversationsInvite.family(),
            MessagingActionFamily::ChannelInvite
        );
        assert_eq!(
            MessagingActionKind::SlackFilesUploadV2.family(),
            MessagingActionFamily::FileUpload
        );
        assert_eq!(
            MessagingActionKind::DiscordChannelsPermissionsPut.family(),
            MessagingActionFamily::PermissionUpdate
        );
        assert_eq!(
            MessagingActionKind::DiscordChannelsMessagesCreate.surface(),
            MessagingSemanticSurface::DiscordChannels
        );
        assert!(MessagingActionKind::from_label("slack", "chat.delete").is_none());
    }

    #[test]
    fn preview_candidates_cover_slack_and_discord_with_redaction_safe_hints() {
        let slack_send = MessagingProviderActionCandidate::preview_slack_chat_post_message();
        let discord_permission =
            MessagingProviderActionCandidate::preview_discord_channels_permissions_put();

        assert_eq!(slack_send.source, MessagingSignalSource::ApiObservation);
        assert_eq!(slack_send.provider_action.provider_id.as_str(), "slack");
        assert_eq!(
            slack_send.provider_action.target_hint(),
            "slack.channels/C12345678"
        );
        assert_eq!(
            discord_permission.source,
            MessagingSignalSource::ApiObservation
        );
        assert_eq!(
            discord_permission.provider_action.provider_id.as_str(),
            "discord"
        );
        assert_eq!(
            discord_permission.provider_action.target_hint(),
            "discord.channels/123456789012345678/permissions/role:345678901234567890"
        );
        assert_eq!(
            MessagingProviderActionCandidate::preview_slack_files_upload_v2().attachment_count_hint,
            Some(1)
        );
    }
}
