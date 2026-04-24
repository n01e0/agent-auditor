use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    provider::{ActionKey, ProviderActionId, ProviderId, ProviderSemanticAction},
    rest::GenericRestAction,
};

pub const MESSAGING_COLLABORATION_REDACTION_RULE: &str = "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MessagingActionFamily(String);

impl MessagingActionFamily {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseMessagingActionFamilyError> {
        let value = value.into();
        if is_valid_messaging_action_family(&value) {
            Ok(Self(value))
        } else {
            Err(ParseMessagingActionFamilyError { value })
        }
    }

    pub fn message_send() -> Self {
        Self("message.send".to_owned())
    }

    pub fn message_edit() -> Self {
        Self("message.edit".to_owned())
    }

    pub fn reaction_add() -> Self {
        Self("reaction.add".to_owned())
    }

    pub fn typing_indicate() -> Self {
        Self("typing.indicate".to_owned())
    }

    pub fn channel_invite() -> Self {
        Self("channel.invite".to_owned())
    }

    pub fn permission_update() -> Self {
        Self("permission.update".to_owned())
    }

    pub fn file_upload() -> Self {
        Self("file.upload".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessagingActionFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MessagingActionFamily {
    type Err = ParseMessagingActionFamilyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for MessagingActionFamily {
    type Error = ParseMessagingActionFamilyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<MessagingActionFamily> for String {
    fn from(value: MessagingActionFamily) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMessagingActionFamilyError {
    value: String,
}

impl fmt::Display for ParseMessagingActionFamilyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid messaging action family `{}`: expected a shared collaboration family label like `message.send`",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryScope {
    PublicChannel,
    PrivateChannel,
    Thread,
}

impl DeliveryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicChannel => "public_channel",
            Self::PrivateChannel => "private_channel",
            Self::Thread => "thread",
        }
    }
}

impl fmt::Display for DeliveryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeliveryScope {
    type Err = ParseDeliveryScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public_channel" => Ok(Self::PublicChannel),
            "private_channel" => Ok(Self::PrivateChannel),
            "thread" => Ok(Self::Thread),
            _ => Err(ParseDeliveryScopeError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDeliveryScopeError {
    value: String,
}

impl fmt::Display for ParseDeliveryScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid delivery scope `{}`: expected a supported messaging delivery scope",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipTargetKind {
    ChannelMember,
    ThreadMember,
}

impl MembershipTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelMember => "channel_member",
            Self::ThreadMember => "thread_member",
        }
    }
}

impl fmt::Display for MembershipTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MembershipTargetKind {
    type Err = ParseMembershipTargetKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "channel_member" => Ok(Self::ChannelMember),
            "thread_member" => Ok(Self::ThreadMember),
            _ => Err(ParseMembershipTargetKindError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMembershipTargetKindError {
    value: String,
}

impl fmt::Display for ParseMembershipTargetKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid membership target kind `{}`: expected a supported messaging membership target label",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionTargetKind {
    ChannelPermissionOverwrite,
}

impl PermissionTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelPermissionOverwrite => "channel_permission_overwrite",
        }
    }
}

impl fmt::Display for PermissionTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PermissionTargetKind {
    type Err = ParsePermissionTargetKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "channel_permission_overwrite" => Ok(Self::ChannelPermissionOverwrite),
            _ => Err(ParsePermissionTargetKindError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePermissionTargetKindError {
    value: String,
}

impl fmt::Display for ParsePermissionTargetKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid permission target kind `{}`: expected a supported messaging permission target label",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTargetKind {
    ChannelAttachment,
}

impl FileTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelAttachment => "channel_attachment",
        }
    }
}

impl fmt::Display for FileTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FileTargetKind {
    type Err = ParseFileTargetKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "channel_attachment" => Ok(Self::ChannelAttachment),
            _ => Err(ParseFileTargetKindError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFileTargetKindError {
    value: String,
}

impl fmt::Display for ParseFileTargetKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid file target kind `{}`: expected a supported messaging file target label",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingAction {
    pub generic_rest_action: GenericRestAction,
    pub action_family: MessagingActionFamily,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_scope: Option<DeliveryScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_target_kind: Option<MembershipTargetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_target_kind: Option<PermissionTargetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_target_kind: Option<FileTargetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_count_hint: Option<u16>,
}

impl MessagingAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generic_rest_action: GenericRestAction,
        action_family: MessagingActionFamily,
        channel_hint: Option<String>,
        conversation_hint: Option<String>,
        delivery_scope: Option<DeliveryScope>,
        membership_target_kind: Option<MembershipTargetKind>,
        permission_target_kind: Option<PermissionTargetKind>,
        file_target_kind: Option<FileTargetKind>,
        attachment_count_hint: Option<u16>,
    ) -> Self {
        Self {
            generic_rest_action,
            action_family,
            channel_hint,
            conversation_hint,
            delivery_scope,
            membership_target_kind,
            permission_target_kind,
            file_target_kind,
            attachment_count_hint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_generic_rest_action(
        generic_rest_action: GenericRestAction,
        action_family: MessagingActionFamily,
        channel_hint: Option<String>,
        conversation_hint: Option<String>,
        delivery_scope: Option<DeliveryScope>,
        membership_target_kind: Option<MembershipTargetKind>,
        permission_target_kind: Option<PermissionTargetKind>,
        file_target_kind: Option<FileTargetKind>,
        attachment_count_hint: Option<u16>,
    ) -> Self {
        Self::new(
            generic_rest_action,
            action_family,
            channel_hint,
            conversation_hint,
            delivery_scope,
            membership_target_kind,
            permission_target_kind,
            file_target_kind,
            attachment_count_hint,
        )
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.generic_rest_action.provider_id
    }

    pub fn action_key(&self) -> &ActionKey {
        &self.generic_rest_action.action_key
    }

    pub fn target_hint(&self) -> &str {
        self.generic_rest_action.target_hint()
    }

    pub fn id(&self) -> ProviderActionId {
        self.generic_rest_action.id()
    }

    pub fn provider_action(&self) -> ProviderSemanticAction {
        self.generic_rest_action.provider_action()
    }

    pub fn redaction_contract(&self) -> &'static str {
        MESSAGING_COLLABORATION_REDACTION_RULE
    }
}

fn is_valid_messaging_action_family(value: &str) -> bool {
    matches!(
        value.trim(),
        "message.send"
            | "message.edit"
            | "reaction.add"
            | "typing.indicate"
            | "channel.invite"
            | "permission.update"
            | "file.upload"
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DeliveryScope, FileTargetKind, MESSAGING_COLLABORATION_REDACTION_RULE,
        MembershipTargetKind, MessagingAction, MessagingActionFamily, PermissionTargetKind,
    };
    use crate::{
        provider::{
            OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionId, ProviderId,
            ProviderMethod, SideEffect,
        },
        rest::{GenericRestAction, PathTemplate, QueryClass, RestHost},
    };

    #[test]
    fn messaging_action_family_parse_display_and_serde_round_trip() {
        let message_send = MessagingActionFamily::message_send();
        let reaction_add = MessagingActionFamily::reaction_add();
        let file_upload = MessagingActionFamily::file_upload();

        assert_eq!(message_send.as_str(), "message.send");
        assert_eq!(reaction_add.as_str(), "reaction.add");
        assert_eq!(file_upload.to_string(), "file.upload");
        assert_eq!(
            "channel.invite".parse::<MessagingActionFamily>().unwrap(),
            MessagingActionFamily::channel_invite()
        );
        assert_eq!(
            serde_json::to_value(&message_send).unwrap(),
            json!("message.send")
        );
        assert_eq!(
            serde_json::from_value::<MessagingActionFamily>(json!("typing.indicate")).unwrap(),
            MessagingActionFamily::typing_indicate()
        );
        assert!("message.delete".parse::<MessagingActionFamily>().is_err());
    }

    #[test]
    fn messaging_target_kinds_parse_display_and_serde_round_trip() {
        assert_eq!(DeliveryScope::Thread.to_string(), "thread");
        assert_eq!(
            "public_channel".parse::<DeliveryScope>().unwrap(),
            DeliveryScope::PublicChannel
        );
        assert_eq!(
            serde_json::to_value(MembershipTargetKind::ChannelMember).unwrap(),
            json!("channel_member")
        );
        assert_eq!(
            "thread_member".parse::<MembershipTargetKind>().unwrap(),
            MembershipTargetKind::ThreadMember
        );
        assert_eq!(
            serde_json::to_value(PermissionTargetKind::ChannelPermissionOverwrite).unwrap(),
            json!("channel_permission_overwrite")
        );
        assert_eq!(
            "channel_permission_overwrite"
                .parse::<PermissionTargetKind>()
                .unwrap(),
            PermissionTargetKind::ChannelPermissionOverwrite
        );
        assert_eq!(
            serde_json::to_value(FileTargetKind::ChannelAttachment).unwrap(),
            json!("channel_attachment")
        );
        assert_eq!(
            "channel_attachment".parse::<FileTargetKind>().unwrap(),
            FileTargetKind::ChannelAttachment
        );
        assert!("broadcast".parse::<DeliveryScope>().is_err());
    }

    #[test]
    fn messaging_action_can_be_built_from_slack_generic_rest_lineage() {
        let generic_rest_action = GenericRestAction::new(
            ProviderId::slack(),
            "chat.post_message".parse().unwrap(),
            "slack.channels/C12345678",
            ProviderMethod::Post,
            RestHost::new("slack.com").unwrap(),
            PathTemplate::new("/api/chat.postMessage").unwrap(),
            QueryClass::ActionArguments,
            OAuthScopeSet::new(
                OAuthScope::new("slack.scope:chat:write").unwrap(),
                vec![OAuthScope::new("slack.scope:chat:write").unwrap()],
            ),
            SideEffect::new("sends a message into a Slack conversation").unwrap(),
            PrivilegeClass::OutboundSend,
        );
        let action = MessagingAction::from_generic_rest_action(
            generic_rest_action,
            MessagingActionFamily::message_send(),
            Some("slack.channels/C12345678".to_owned()),
            None,
            Some(DeliveryScope::PublicChannel),
            None,
            None,
            None,
            None,
        );

        assert_eq!(action.provider_id(), &ProviderId::slack());
        assert_eq!(action.action_key().as_str(), "chat.post_message");
        assert_eq!(
            action.id(),
            ProviderActionId::from_parts("slack", "chat.post_message").unwrap()
        );
        assert_eq!(action.target_hint(), "slack.channels/C12345678");
        assert_eq!(action.action_family, MessagingActionFamily::message_send());
        assert_eq!(
            action.channel_hint.as_deref(),
            Some("slack.channels/C12345678")
        );
        assert_eq!(action.delivery_scope, Some(DeliveryScope::PublicChannel));
        assert_eq!(
            action.redaction_contract(),
            MESSAGING_COLLABORATION_REDACTION_RULE
        );
    }

    #[test]
    fn messaging_action_can_model_discord_invites_permissions_and_files() {
        let discord_thread_invite = MessagingAction::from_generic_rest_action(
            GenericRestAction::new(
                ProviderId::discord(),
                "channels.thread_members.put".parse().unwrap(),
                "discord.threads/123456789012345678/members/234567890123456789",
                ProviderMethod::Put,
                RestHost::new("discord.com").unwrap(),
                PathTemplate::new("/api/v10/channels/{thread_id}/thread-members/{user_id}")
                    .unwrap(),
                QueryClass::None,
                OAuthScopeSet::new(
                    OAuthScope::new("discord.permission:create_public_threads").unwrap(),
                    vec![OAuthScope::new("discord.permission:send_messages_in_threads").unwrap()],
                ),
                SideEffect::new("adds a member into a Discord thread").unwrap(),
                PrivilegeClass::SharingWrite,
            ),
            MessagingActionFamily::channel_invite(),
            None,
            Some("discord.threads/123456789012345678".to_owned()),
            Some(DeliveryScope::Thread),
            Some(MembershipTargetKind::ThreadMember),
            None,
            None,
            None,
        );
        let discord_permission_update = MessagingAction::from_generic_rest_action(
            GenericRestAction::new(
                ProviderId::discord(),
                "channels.permissions.put".parse().unwrap(),
                "discord.channels/123456789012345678/permissions/role:345678901234567890",
                ProviderMethod::Put,
                RestHost::new("discord.com").unwrap(),
                PathTemplate::new("/api/v10/channels/{channel_id}/permissions/{overwrite_id}")
                    .unwrap(),
                QueryClass::None,
                OAuthScopeSet::new(
                    OAuthScope::new("discord.permission:manage_roles").unwrap(),
                    vec![OAuthScope::new("discord.permission:manage_channels").unwrap()],
                ),
                SideEffect::new("updates a Discord channel permission overwrite").unwrap(),
                PrivilegeClass::SharingWrite,
            ),
            MessagingActionFamily::permission_update(),
            Some("discord.channels/123456789012345678".to_owned()),
            None,
            None,
            None,
            Some(PermissionTargetKind::ChannelPermissionOverwrite),
            None,
            None,
        );
        let slack_file_upload = MessagingAction::from_generic_rest_action(
            GenericRestAction::new(
                ProviderId::slack(),
                "files.upload_v2".parse().unwrap(),
                "slack.channels/C12345678/files/F12345678",
                ProviderMethod::Post,
                RestHost::new("slack.com").unwrap(),
                PathTemplate::new("/api/files.uploadV2").unwrap(),
                QueryClass::ActionArguments,
                OAuthScopeSet::new(
                    OAuthScope::new("slack.scope:files:write").unwrap(),
                    vec![OAuthScope::new("slack.scope:chat:write").unwrap()],
                ),
                SideEffect::new("uploads a file into a Slack conversation").unwrap(),
                PrivilegeClass::ContentWrite,
            ),
            MessagingActionFamily::file_upload(),
            Some("slack.channels/C12345678".to_owned()),
            None,
            Some(DeliveryScope::PublicChannel),
            None,
            None,
            Some(FileTargetKind::ChannelAttachment),
            Some(1),
        );

        assert_eq!(
            discord_thread_invite.conversation_hint.as_deref(),
            Some("discord.threads/123456789012345678")
        );
        assert_eq!(
            discord_thread_invite.membership_target_kind,
            Some(MembershipTargetKind::ThreadMember)
        );
        assert_eq!(
            discord_permission_update.permission_target_kind,
            Some(PermissionTargetKind::ChannelPermissionOverwrite)
        );
        assert_eq!(
            slack_file_upload.file_target_kind,
            Some(FileTargetKind::ChannelAttachment)
        );
        assert_eq!(slack_file_upload.attachment_count_hint, Some(1));
        assert_eq!(
            slack_file_upload.provider_action(),
            slack_file_upload.generic_rest_action.provider_action()
        );
    }
}
