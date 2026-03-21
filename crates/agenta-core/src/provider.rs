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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ActionKey, ProviderAbstractionPlan, ProviderActionId, ProviderId, ProviderSemanticAction,
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
            serde_json::to_value(&ProviderId::gws()).unwrap(),
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
