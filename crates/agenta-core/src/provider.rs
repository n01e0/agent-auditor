use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

const PROVIDER_ABSTRACTION_REDACTION_RULE: &str = "provider abstraction seams carry action identity, target hints, and docs-backed descriptors only; raw provider payloads, message bodies, file contents, and diff bodies must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseProviderIdError> {
        let value = value.into();
        if is_valid_provider_id(&value) {
            Ok(Self(value))
        } else {
            Err(ParseProviderIdError { value })
        }
    }

    pub fn gws() -> Self {
        Self("gws".to_owned())
    }

    pub fn github() -> Self {
        Self("github".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_known_provider(&self) -> bool {
        matches!(self.as_str(), "gws" | "github")
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderId {
    type Err = ParseProviderIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ProviderId {
    type Error = ParseProviderIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderId> for String {
    fn from(value: ProviderId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProviderIdError {
    value: String,
}

impl fmt::Display for ParseProviderIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid provider id `{}`: expected lowercase ascii segments separated by `.` or `-`",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ActionKey(String);

impl ActionKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseActionKeyError> {
        let value = value.into();
        if is_valid_action_key(&value) {
            Ok(Self(value))
        } else {
            Err(ParseActionKeyError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionKey {
    type Err = ParseActionKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ActionKey {
    type Error = ParseActionKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ActionKey> for String {
    fn from(value: ActionKey) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseActionKeyError {
    value: String,
}

impl fmt::Display for ParseActionKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid action key `{}`: expected lowercase ascii segments separated by `.` or `_`",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProviderActionId {
    pub provider_id: ProviderId,
    pub action_key: ActionKey,
}

impl ProviderActionId {
    pub fn new(provider_id: ProviderId, action_key: ActionKey) -> Self {
        Self {
            provider_id,
            action_key,
        }
    }

    pub fn from_parts(
        provider_id: impl Into<String>,
        action_key: impl Into<String>,
    ) -> Result<Self, ParseProviderActionIdError> {
        Ok(Self::new(
            ProviderId::new(provider_id.into()).map_err(ParseProviderActionIdError::from)?,
            ActionKey::new(action_key.into()).map_err(ParseProviderActionIdError::from)?,
        ))
    }
}

impl fmt::Display for ProviderActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider_id, self.action_key)
    }
}

impl FromStr for ProviderActionId {
    type Err = ParseProviderActionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (provider_id, action_key) = value
            .split_once(':')
            .ok_or_else(|| ParseProviderActionIdError::invalid_format(value))?;

        Self::from_parts(provider_id, action_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProviderActionIdError {
    value: String,
}

impl ParseProviderActionIdError {
    fn invalid_format(value: &str) -> Self {
        Self {
            value: value.to_owned(),
        }
    }
}

impl From<ParseProviderIdError> for ParseProviderActionIdError {
    fn from(error: ParseProviderIdError) -> Self {
        Self { value: error.value }
    }
}

impl From<ParseActionKeyError> for ParseProviderActionIdError {
    fn from(error: ParseActionKeyError) -> Self {
        Self { value: error.value }
    }
}

impl fmt::Display for ParseProviderActionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid provider action id `{}`: expected `<provider_id>:<action_key>`",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSemanticAction {
    pub provider_id: ProviderId,
    pub action_key: ActionKey,
    pub target_hint: String,
}

impl ProviderSemanticAction {
    pub fn new(
        provider_id: ProviderId,
        action_key: ActionKey,
        target_hint: impl Into<String>,
    ) -> Self {
        Self {
            provider_id,
            action_key,
            target_hint: target_hint.into(),
        }
    }

    pub fn from_id(id: ProviderActionId, target_hint: impl Into<String>) -> Self {
        Self::new(id.provider_id, id.action_key, target_hint)
    }

    pub fn id(&self) -> ProviderActionId {
        ProviderActionId::new(self.provider_id.clone(), self.action_key.clone())
    }

    pub fn target_hint(&self) -> &str {
        &self.target_hint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl ProviderMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

impl fmt::Display for ProviderMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderMethod {
    type Err = ParseProviderMethodError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            "HEAD" => Ok(Self::Head),
            "OPTIONS" => Ok(Self::Options),
            _ => Err(ParseProviderMethodError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProviderMethodError {
    value: String,
}

impl fmt::Display for ParseProviderMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid provider method `{}`: expected a supported HTTP verb",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CanonicalResource(String);

impl CanonicalResource {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseCanonicalResourceError> {
        let value = value.into();
        if is_non_empty_descriptor(&value) {
            Ok(Self(value))
        } else {
            Err(ParseCanonicalResourceError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CanonicalResource {
    type Err = ParseCanonicalResourceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for CanonicalResource {
    type Error = ParseCanonicalResourceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CanonicalResource> for String {
    fn from(value: CanonicalResource) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCanonicalResourceError {
    value: String,
}

impl fmt::Display for ParseCanonicalResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid canonical resource `{}`: expected a non-empty redaction-safe resource string",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SideEffect(String);

impl SideEffect {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseSideEffectError> {
        let value = value.into();
        if is_non_empty_descriptor(&value) {
            Ok(Self(value))
        } else {
            Err(ParseSideEffectError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SideEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SideEffect {
    type Err = ParseSideEffectError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for SideEffect {
    type Error = ParseSideEffectError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SideEffect> for String {
    fn from(value: SideEffect) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSideEffectError {
    value: String,
}

impl fmt::Display for ParseSideEffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid side effect `{}`: expected a non-empty docs-backed descriptor",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OAuthScope(String);

impl OAuthScope {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseOAuthScopeError> {
        let value = value.into();
        if is_non_empty_descriptor(&value) {
            Ok(Self(value))
        } else {
            Err(ParseOAuthScopeError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OAuthScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OAuthScope {
    type Err = ParseOAuthScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for OAuthScope {
    type Error = ParseOAuthScopeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OAuthScope> for String {
    fn from(value: OAuthScope) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOAuthScopeError {
    value: String,
}

impl fmt::Display for ParseOAuthScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid OAuth scope `{}`: expected a non-empty scope label",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthScopeSet {
    pub primary: OAuthScope,
    pub documented: Vec<OAuthScope>,
}

impl OAuthScopeSet {
    pub fn new(primary: OAuthScope, documented: Vec<OAuthScope>) -> Self {
        Self {
            primary,
            documented,
        }
    }

    pub fn primary(&self) -> &OAuthScope {
        &self.primary
    }

    pub fn documented(&self) -> &[OAuthScope] {
        &self.documented
    }

    pub fn covers(&self, scope: &OAuthScope) -> bool {
        self.primary == *scope || self.documented.iter().any(|item| item == scope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeClass {
    ReadOnly,
    ContentRead,
    ContentWrite,
    SharingWrite,
    OutboundSend,
    AdminRead,
    AdminWrite,
}

impl PrivilegeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ContentRead => "content_read",
            Self::ContentWrite => "content_write",
            Self::SharingWrite => "sharing_write",
            Self::OutboundSend => "outbound_send",
            Self::AdminRead => "admin_read",
            Self::AdminWrite => "admin_write",
        }
    }
}

impl fmt::Display for PrivilegeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderActionMetadata {
    pub action: ProviderActionId,
    pub method: ProviderMethod,
    pub canonical_resource: CanonicalResource,
    pub side_effect: SideEffect,
    pub oauth_scopes: OAuthScopeSet,
    pub privilege_class: PrivilegeClass,
}

impl ProviderActionMetadata {
    pub fn new(
        action: ProviderActionId,
        method: ProviderMethod,
        canonical_resource: CanonicalResource,
        side_effect: SideEffect,
        oauth_scopes: OAuthScopeSet,
        privilege_class: PrivilegeClass,
    ) -> Self {
        Self {
            action,
            method,
            canonical_resource,
            side_effect,
            oauth_scopes,
            privilege_class,
        }
    }

    pub fn provider_id(&self) -> &ProviderId {
        &self.action.provider_id
    }

    pub fn action_key(&self) -> &ActionKey {
        &self.action.action_key
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderMetadataCatalog {
    pub entries: Vec<ProviderActionMetadata>,
}

impl ProviderMetadataCatalog {
    pub fn new(entries: Vec<ProviderActionMetadata>) -> Self {
        Self { entries }
    }

    pub fn find(&self, action: &ProviderActionId) -> Option<&ProviderActionMetadata> {
        self.entries.iter().find(|entry| &entry.action == action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAbstractionPlan {
    pub taxonomy: ProviderTaxonomyBoundary,
    pub contract: ProviderContractBoundary,
    pub metadata: ProviderMetadataBoundary,
}

impl ProviderAbstractionPlan {
    pub fn bootstrap() -> Self {
        let taxonomy = ProviderTaxonomyBoundary::default();
        let contract = ProviderContractBoundary::from_taxonomy_boundary(&taxonomy);
        let metadata = ProviderMetadataBoundary::from_contract_boundary(&contract);

        Self {
            taxonomy,
            contract,
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTaxonomyBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub output_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl Default for ProviderTaxonomyBoundary {
    fn default() -> Self {
        Self {
            providers: vec!["gws", "github"],
            input_fields: vec![
                "provider_hint",
                "surface_hint",
                "method_hint",
                "path_hint",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
            ],
            output_fields: vec![
                "provider_id",
                "provider_action_label",
                "target_hint",
                "taxonomy_reason",
            ],
            responsibilities: vec![
                "accept provider-native API, browser, or network hints and map them into provider-local action candidates",
                "own provider-specific labels and matching heuristics for surfaces such as GWS today and GitHub next",
                "handoff provider_id plus provider_action_label and target_hint without defining the shared policy contract or metadata catalog",
            ],
            redaction_contract: PROVIDER_ABSTRACTION_REDACTION_RULE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderContractBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl ProviderContractBoundary {
    pub fn from_taxonomy_boundary(taxonomy: &ProviderTaxonomyBoundary) -> Self {
        Self {
            providers: taxonomy.providers.clone(),
            input_fields: taxonomy.output_fields.clone(),
            contract_fields: vec!["provider_id", "action_key", "target_hint"],
            responsibilities: vec![
                "define the provider-neutral action identity consumed by agenta-core and later agenta-policy generalization",
                "stabilize a provider plus action_key handoff so downstream policy and audit code do not depend on GWS-specific labels",
                "carry only redaction-safe action identity and target summaries, not provider-native matching heuristics or docs-backed scope catalogs",
            ],
            redaction_contract: taxonomy.redaction_contract,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadataBoundary {
    pub providers: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub documentation_sources: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl ProviderMetadataBoundary {
    pub fn from_contract_boundary(contract: &ProviderContractBoundary) -> Self {
        Self {
            providers: contract.providers.clone(),
            contract_fields: contract.contract_fields.clone(),
            metadata_fields: vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ],
            documentation_sources: vec![
                "official provider method documentation",
                "official provider auth and scope documentation",
                "repository-owned risk and posture notes",
            ],
            responsibilities: vec![
                "attach docs-backed method, resource, side effect, OAuth scope, and privilege descriptors to shared provider actions",
                "key metadata by the shared provider_id plus action_key contract without re-running provider-specific classification",
                "act as the descriptive catalog for policy, audit, docs, and later UI work without mutating shared action identity",
            ],
            redaction_contract: contract.redaction_contract,
        }
    }
}

fn is_valid_provider_id(value: &str) -> bool {
    is_valid_identifier(value, |character| matches!(character, '.' | '-'))
}

fn is_valid_action_key(value: &str) -> bool {
    is_valid_identifier(value, |character| matches!(character, '.' | '_'))
}

fn is_valid_identifier(value: &str, is_separator: impl Fn(char) -> bool) -> bool {
    if value.is_empty() {
        return false;
    }

    let mut previous_was_separator = false;

    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            previous_was_separator = false;
            continue;
        }

        if is_separator(character) {
            if index == 0 || previous_was_separator {
                return false;
            }
            previous_was_separator = true;
            continue;
        }

        return false;
    }

    !previous_was_separator
}

fn is_non_empty_descriptor(value: &str) -> bool {
    !value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ActionKey, CanonicalResource, OAuthScope, OAuthScopeSet, PrivilegeClass,
        ProviderAbstractionPlan, ProviderActionId, ProviderActionMetadata, ProviderId,
        ProviderMetadataCatalog, ProviderMethod, ProviderSemanticAction, SideEffect,
    };

    #[test]
    fn provider_id_helpers_parse_and_serde_round_trip() {
        let gws = ProviderId::gws();
        let github = ProviderId::github();

        assert_eq!(gws.as_str(), "gws");
        assert_eq!(github.as_str(), "github");
        assert!(gws.is_known_provider());
        assert!(github.is_known_provider());
        assert_eq!("gws".parse::<ProviderId>().unwrap(), gws);
        assert_eq!("github".parse::<ProviderId>().unwrap(), github);
        assert_eq!(
            serde_json::to_value(ProviderId::gws()).unwrap(),
            json!("gws")
        );
        assert_eq!(
            serde_json::from_value::<ProviderId>(json!("github")).unwrap(),
            ProviderId::github()
        );
        assert!("GWS".parse::<ProviderId>().is_err());
    }

    #[test]
    fn action_key_parse_and_serde_round_trip() {
        let action_key = ActionKey::new("drive.files.get_media").unwrap();

        assert_eq!(action_key.as_str(), "drive.files.get_media");
        assert_eq!(action_key.to_string(), "drive.files.get_media");
        assert_eq!(
            "drive.files.get_media".parse::<ActionKey>().unwrap(),
            action_key
        );
        assert_eq!(
            serde_json::to_value(&action_key).unwrap(),
            json!("drive.files.get_media")
        );
        assert_eq!(
            serde_json::from_value::<ActionKey>(json!("gmail.users.messages.send")).unwrap(),
            ActionKey::new("gmail.users.messages.send").unwrap()
        );
        assert!(ActionKey::new("drive files get media").is_err());
    }

    #[test]
    fn provider_action_id_parses_and_serializes_as_shared_identity() {
        let id = ProviderActionId::from_parts("gws", "drive.permissions.update").unwrap();

        assert_eq!(id.to_string(), "gws:drive.permissions.update");
        assert_eq!(
            "gws:drive.permissions.update"
                .parse::<ProviderActionId>()
                .unwrap(),
            id
        );
        assert_eq!(
            serde_json::to_value(&id).unwrap(),
            json!({
                "provider_id": "gws",
                "action_key": "drive.permissions.update",
            })
        );
        assert!(
            "gws/drive.permissions.update"
                .parse::<ProviderActionId>()
                .is_err()
        );
    }

    #[test]
    fn provider_semantic_action_carries_shared_contract_fields() {
        let semantic_action = ProviderSemanticAction::new(
            ProviderId::gws(),
            ActionKey::new("gmail.users.messages.send").unwrap(),
            "gmail.users/me",
        );

        assert_eq!(
            semantic_action.id(),
            ProviderActionId::from_parts("gws", "gmail.users.messages.send").unwrap()
        );
        assert_eq!(semantic_action.target_hint(), "gmail.users/me");
        assert_eq!(
            serde_json::to_value(&semantic_action).unwrap(),
            json!({
                "provider_id": "gws",
                "action_key": "gmail.users.messages.send",
                "target_hint": "gmail.users/me",
            })
        );
    }

    #[test]
    fn provider_method_parses_http_verbs_and_privilege_class_formats() {
        assert_eq!(
            "patch".parse::<ProviderMethod>().unwrap(),
            ProviderMethod::Patch
        );
        assert_eq!(ProviderMethod::Get.to_string(), "GET");
        assert_eq!(PrivilegeClass::SharingWrite.to_string(), "sharing_write");
        assert!("TRACE".parse::<ProviderMethod>().is_err());
    }

    #[test]
    fn provider_metadata_structures_round_trip_through_serde() {
        let metadata = ProviderActionMetadata::new(
            ProviderActionId::from_parts("gws", "drive.permissions.update").unwrap(),
            ProviderMethod::Patch,
            CanonicalResource::new("drive.files/{fileId}/permissions/{permissionId}").unwrap(),
            SideEffect::new(
                "updates a Drive permission and may transfer ownership when transferOwnership=true",
            )
            .unwrap(),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/drive.file").unwrap(),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/drive").unwrap(),
                    OAuthScope::new("https://www.googleapis.com/auth/drive.file").unwrap(),
                ],
            ),
            PrivilegeClass::SharingWrite,
        );

        assert_eq!(metadata.provider_id(), &ProviderId::gws());
        assert_eq!(
            metadata.action_key(),
            &ActionKey::new("drive.permissions.update").unwrap()
        );
        assert_eq!(metadata.method, ProviderMethod::Patch);
        assert_eq!(
            metadata.canonical_resource.as_str(),
            "drive.files/{fileId}/permissions/{permissionId}"
        );
        assert!(
            metadata
                .oauth_scopes
                .covers(&OAuthScope::new("https://www.googleapis.com/auth/drive.file").unwrap())
        );
        assert_eq!(
            serde_json::to_value(&metadata).unwrap(),
            json!({
                "action": {
                    "provider_id": "gws",
                    "action_key": "drive.permissions.update"
                },
                "method": "patch",
                "canonical_resource": "drive.files/{fileId}/permissions/{permissionId}",
                "side_effect": "updates a Drive permission and may transfer ownership when transferOwnership=true",
                "oauth_scopes": {
                    "primary": "https://www.googleapis.com/auth/drive.file",
                    "documented": [
                        "https://www.googleapis.com/auth/drive",
                        "https://www.googleapis.com/auth/drive.file"
                    ]
                },
                "privilege_class": "sharing_write"
            })
        );
    }

    #[test]
    fn provider_metadata_catalog_is_keyed_by_shared_action_identity() {
        let drive_download = ProviderActionMetadata::new(
            ProviderActionId::from_parts("gws", "drive.files.get_media").unwrap(),
            ProviderMethod::Get,
            CanonicalResource::new("drive.files/{fileId}/content").unwrap(),
            SideEffect::new("returns Drive file content bytes").unwrap(),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/drive.readonly").unwrap(),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/drive").unwrap(),
                    OAuthScope::new("https://www.googleapis.com/auth/drive.readonly").unwrap(),
                ],
            ),
            PrivilegeClass::ContentRead,
        );
        let gmail_send = ProviderActionMetadata::new(
            ProviderActionId::from_parts("gws", "gmail.users.messages.send").unwrap(),
            ProviderMethod::Post,
            CanonicalResource::new("gmail.users/{userId}/messages:send").unwrap(),
            SideEffect::new("sends the specified message to the listed recipients").unwrap(),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/gmail.send").unwrap(),
                vec![OAuthScope::new("https://www.googleapis.com/auth/gmail.send").unwrap()],
            ),
            PrivilegeClass::OutboundSend,
        );
        let catalog = ProviderMetadataCatalog::new(vec![drive_download, gmail_send]);

        let found = catalog
            .find(&ProviderActionId::from_parts("gws", "drive.files.get_media").unwrap())
            .unwrap();

        assert_eq!(found.method, ProviderMethod::Get);
        assert_eq!(found.privilege_class, PrivilegeClass::ContentRead);
        assert_eq!(
            found.oauth_scopes.primary(),
            &OAuthScope::new("https://www.googleapis.com/auth/drive.readonly").unwrap()
        );
        assert!(
            catalog
                .find(&ProviderActionId::from_parts("github", "repos.contents.get").unwrap())
                .is_none()
        );
    }

    #[test]
    fn provider_metadata_rejects_blank_descriptors() {
        assert!(CanonicalResource::new("   ").is_err());
        assert!(SideEffect::new("\n").is_err());
        assert!(OAuthScope::new("").is_err());
    }

    #[test]
    fn bootstrap_plan_separates_provider_contract_metadata_and_taxonomy_ownership() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-local action candidates"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("GWS today and GitHub next"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );

        assert!(
            plan.contract
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-neutral action identity"))
        );
        assert!(
            plan.contract
                .responsibilities
                .iter()
                .all(|item| !item.contains("OAuth scope"))
        );
        assert!(plan.contract.responsibilities.iter().any(|item| {
            item.contains("not provider-native matching heuristics or docs-backed scope catalogs")
        }));

        assert!(plan
            .metadata
            .responsibilities
            .iter()
            .any(|item| item.contains("docs-backed method, resource, side effect, OAuth scope, and privilege descriptors")));
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("without re-running provider-specific classification"))
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("without mutating shared action identity"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_labels_and_redaction_guardrails() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert_eq!(plan.taxonomy.providers, vec!["gws", "github"]);
        assert_eq!(plan.taxonomy.providers, plan.contract.providers);
        assert_eq!(plan.contract.providers, plan.metadata.providers);
        assert_eq!(plan.taxonomy.output_fields, plan.contract.input_fields);
        assert_eq!(
            plan.contract.contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(plan.contract.contract_fields, plan.metadata.contract_fields);
        assert_eq!(
            plan.metadata.metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.taxonomy.redaction_contract,
            "provider abstraction seams carry action identity, target hints, and docs-backed descriptors only; raw provider payloads, message bodies, file contents, and diff bodies must not cross the seam"
        );
        assert_eq!(
            plan.taxonomy.redaction_contract,
            plan.contract.redaction_contract
        );
        assert_eq!(
            plan.contract.redaction_contract,
            plan.metadata.redaction_contract
        );
    }

    #[test]
    fn bootstrap_plan_keeps_provider_metadata_keyed_by_shared_contract() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert_eq!(
            plan.metadata.documentation_sources,
            vec![
                "official provider method documentation",
                "official provider auth and scope documentation",
                "repository-owned risk and posture notes",
            ]
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("provider_id plus action_key"))
        );
        assert!(
            plan.contract
                .responsibilities
                .iter()
                .any(|item| item.contains("provider plus action_key handoff"))
        );
    }
}
