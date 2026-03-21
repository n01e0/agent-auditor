use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::provider::{
    ActionKey, OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionId, ProviderActionMetadata,
    ProviderId, ProviderMethod, ProviderSemanticAction, SideEffect,
};

pub const GENERIC_REST_OAUTH_REDACTION_RULE: &str = "generic REST / OAuth seams carry route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only; raw request bodies, response bodies, message text, file bytes, token values, signed URLs, and full query strings must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RestHost(String);

impl RestHost {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseRestHostError> {
        let value = value.into();
        if is_valid_rest_host(&value) {
            Ok(Self(value))
        } else {
            Err(ParseRestHostError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RestHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RestHost {
    type Err = ParseRestHostError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for RestHost {
    type Error = ParseRestHostError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RestHost> for String {
    fn from(value: RestHost) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRestHostError {
    value: String,
}

impl fmt::Display for ParseRestHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid REST host `{}`: expected a non-empty host or authority label without scheme, path, or query",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PathTemplate(String);

impl PathTemplate {
    pub fn new(value: impl Into<String>) -> Result<Self, ParsePathTemplateError> {
        let value = value.into();
        if is_valid_path_template(&value) {
            Ok(Self(value))
        } else {
            Err(ParsePathTemplateError { value })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PathTemplate {
    type Err = ParsePathTemplateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for PathTemplate {
    type Error = ParsePathTemplateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PathTemplate> for String {
    fn from(value: PathTemplate) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePathTemplateError {
    value: String,
}

impl fmt::Display for ParsePathTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid path template `{}`: expected a non-empty HTTP path template starting with `/`",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryClass {
    None,
    ResourceSelector,
    Filter,
    Search,
    CursorPagination,
    ActionArguments,
    Unknown,
}

impl QueryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ResourceSelector => "resource_selector",
            Self::Filter => "filter",
            Self::Search => "search",
            Self::CursorPagination => "cursor_pagination",
            Self::ActionArguments => "action_arguments",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for QueryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for QueryClass {
    type Err = ParseQueryClassError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "resource_selector" => Ok(Self::ResourceSelector),
            "filter" => Ok(Self::Filter),
            "search" => Ok(Self::Search),
            "cursor_pagination" => Ok(Self::CursorPagination),
            "action_arguments" => Ok(Self::ActionArguments),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ParseQueryClassError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseQueryClassError {
    value: String,
}

impl fmt::Display for ParseQueryClassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid query class `{}`: expected a supported generic REST query classification",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericRestAction {
    pub provider_id: ProviderId,
    pub action_key: ActionKey,
    pub target_hint: String,
    pub method: ProviderMethod,
    pub host: RestHost,
    pub path_template: PathTemplate,
    pub query_class: QueryClass,
    pub oauth_scope_labels: OAuthScopeSet,
    pub side_effect: SideEffect,
    pub privilege_class: PrivilegeClass,
}

impl GenericRestAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        action_key: ActionKey,
        target_hint: impl Into<String>,
        method: ProviderMethod,
        host: RestHost,
        path_template: PathTemplate,
        query_class: QueryClass,
        oauth_scope_labels: OAuthScopeSet,
        side_effect: SideEffect,
        privilege_class: PrivilegeClass,
    ) -> Self {
        Self {
            provider_id,
            action_key,
            target_hint: target_hint.into(),
            method,
            host,
            path_template,
            query_class,
            oauth_scope_labels,
            side_effect,
            privilege_class,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_provider_action(
        action: ProviderSemanticAction,
        method: ProviderMethod,
        host: RestHost,
        path_template: PathTemplate,
        query_class: QueryClass,
        oauth_scope_labels: OAuthScopeSet,
        side_effect: SideEffect,
        privilege_class: PrivilegeClass,
    ) -> Self {
        Self::new(
            action.provider_id,
            action.action_key,
            action.target_hint,
            method,
            host,
            path_template,
            query_class,
            oauth_scope_labels,
            side_effect,
            privilege_class,
        )
    }

    pub fn from_provider_metadata(
        action: ProviderSemanticAction,
        host: RestHost,
        path_template: PathTemplate,
        query_class: QueryClass,
        metadata: &ProviderActionMetadata,
    ) -> Result<Self, GenericRestContractError> {
        let expected = action.id();
        if metadata.action != expected {
            return Err(GenericRestContractError::ProviderMetadataMismatch {
                expected,
                actual: metadata.action.clone(),
            });
        }

        Ok(Self::from_provider_action(
            action,
            metadata.method,
            host,
            path_template,
            query_class,
            metadata.oauth_scopes.clone(),
            metadata.side_effect.clone(),
            metadata.privilege_class,
        ))
    }

    pub fn id(&self) -> ProviderActionId {
        ProviderActionId::new(self.provider_id.clone(), self.action_key.clone())
    }

    pub fn provider_action(&self) -> ProviderSemanticAction {
        ProviderSemanticAction::new(
            self.provider_id.clone(),
            self.action_key.clone(),
            self.target_hint.clone(),
        )
    }

    pub fn target_hint(&self) -> &str {
        &self.target_hint
    }

    pub fn redaction_contract(&self) -> &'static str {
        GENERIC_REST_OAUTH_REDACTION_RULE
    }

    pub fn scope_covers(&self, scope: &OAuthScope) -> bool {
        self.oauth_scope_labels.covers(scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericRestContractError {
    ProviderMetadataMismatch {
        expected: ProviderActionId,
        actual: ProviderActionId,
    },
}

impl fmt::Display for GenericRestContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderMetadataMismatch { expected, actual } => write!(
                f,
                "generic REST contract metadata mismatch: expected provider action `{expected}`, got `{actual}`"
            ),
        }
    }
}

fn is_valid_rest_host(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.contains(char::is_whitespace)
        && !value.contains("//")
        && !value.contains('/')
        && !value.contains('?')
        && !value.contains('#')
}

fn is_valid_path_template(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.starts_with('/')
        && !value.contains(char::is_whitespace)
        && !value.contains('?')
        && !value.contains('#')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        GENERIC_REST_OAUTH_REDACTION_RULE, GenericRestAction, GenericRestContractError,
        PathTemplate, QueryClass, RestHost,
    };
    use crate::provider::{
        OAuthScope, OAuthScopeSet, PrivilegeClass, ProviderActionId, ProviderActionMetadata,
        ProviderId, ProviderMethod, ProviderSemanticAction, SideEffect,
    };

    #[test]
    fn rest_host_parse_and_serde_round_trip() {
        let github = RestHost::new("api.github.com").unwrap();
        let slack = RestHost::new("{workspace}.slack.com").unwrap();

        assert_eq!(github.as_str(), "api.github.com");
        assert_eq!(slack.to_string(), "{workspace}.slack.com");
        assert_eq!("api.github.com".parse::<RestHost>().unwrap(), github);
        assert_eq!(
            serde_json::to_value(&github).unwrap(),
            json!("api.github.com")
        );
        assert_eq!(
            serde_json::from_value::<RestHost>(json!("discord.com")).unwrap(),
            RestHost::new("discord.com").unwrap()
        );
        assert!(RestHost::new("").is_err());
        assert!(RestHost::new("https://api.github.com").is_err());
        assert!(RestHost::new("api.github.com/v3").is_err());
    }

    #[test]
    fn path_template_parse_and_serde_round_trip() {
        let template =
            PathTemplate::new("/repos/{owner}/{repo}/pulls/{pull_number}/merge").unwrap();

        assert_eq!(
            template.as_str(),
            "/repos/{owner}/{repo}/pulls/{pull_number}/merge"
        );
        assert_eq!(
            "/repos/{owner}/{repo}".parse::<PathTemplate>().unwrap(),
            PathTemplate::new("/repos/{owner}/{repo}").unwrap()
        );
        assert_eq!(
            serde_json::to_value(&template).unwrap(),
            json!("/repos/{owner}/{repo}/pulls/{pull_number}/merge")
        );
        assert!(PathTemplate::new("").is_err());
        assert!(PathTemplate::new("repos/{owner}/{repo}").is_err());
        assert!(PathTemplate::new("/repos/{owner}/{repo}?q=x").is_err());
    }

    #[test]
    fn query_class_parse_display_and_serde_round_trip() {
        assert_eq!(QueryClass::Filter.as_str(), "filter");
        assert_eq!(QueryClass::ActionArguments.to_string(), "action_arguments");
        assert_eq!("search".parse::<QueryClass>().unwrap(), QueryClass::Search);
        assert_eq!(
            "cursor_pagination".parse::<QueryClass>().unwrap(),
            QueryClass::CursorPagination
        );
        assert_eq!(
            serde_json::to_value(QueryClass::ResourceSelector).unwrap(),
            json!("resource_selector")
        );
        assert_eq!(
            serde_json::from_value::<QueryClass>(json!("unknown")).unwrap(),
            QueryClass::Unknown
        );
        assert!(" freeform ".parse::<QueryClass>().is_err());
    }

    #[test]
    fn generic_rest_action_can_be_built_from_provider_action_parts() {
        let action = GenericRestAction::from_provider_action(
            ProviderSemanticAction::new(
                ProviderId::github(),
                "pulls.merge".parse().unwrap(),
                "repos/n01e0/agent-auditor/pulls/77",
            ),
            ProviderMethod::Put,
            RestHost::new("api.github.com").unwrap(),
            PathTemplate::new("/repos/{owner}/{repo}/pulls/{pull_number}/merge").unwrap(),
            QueryClass::None,
            OAuthScopeSet::new(
                OAuthScope::new("github.permission:contents:write").unwrap(),
                vec![OAuthScope::new("github.oauth:repo").unwrap()],
            ),
            SideEffect::new("merges a pull request into the base branch").unwrap(),
            PrivilegeClass::ContentWrite,
        );

        assert_eq!(
            action.id(),
            ProviderActionId::from_parts("github", "pulls.merge").unwrap()
        );
        assert_eq!(action.method, ProviderMethod::Put);
        assert_eq!(action.host.as_str(), "api.github.com");
        assert_eq!(
            action.path_template.as_str(),
            "/repos/{owner}/{repo}/pulls/{pull_number}/merge"
        );
        assert_eq!(action.query_class, QueryClass::None);
        assert_eq!(action.target_hint(), "repos/n01e0/agent-auditor/pulls/77");
        assert_eq!(
            action.provider_action(),
            ProviderSemanticAction::new(
                ProviderId::github(),
                "pulls.merge".parse().unwrap(),
                "repos/n01e0/agent-auditor/pulls/77",
            )
        );
        assert!(action.scope_covers(&OAuthScope::new("github.oauth:repo").unwrap()));
        assert_eq!(
            action.redaction_contract(),
            GENERIC_REST_OAUTH_REDACTION_RULE
        );
    }

    #[test]
    fn generic_rest_action_can_join_provider_metadata_with_host_path_and_query_shape() {
        let provider_action = ProviderSemanticAction::new(
            ProviderId::gws(),
            "admin.reports.activities.list".parse().unwrap(),
            "admin/activity/reports",
        );
        let metadata = ProviderActionMetadata::new(
            provider_action.id(),
            ProviderMethod::Get,
            "admin/reports/activities".parse().unwrap(),
            SideEffect::new("lists admin activity reports without mutating tenant state").unwrap(),
            OAuthScopeSet::new(
                OAuthScope::new("https://www.googleapis.com/auth/admin.reports.audit.readonly")
                    .unwrap(),
                vec![
                    OAuthScope::new("https://www.googleapis.com/auth/admin.reports.audit.readonly")
                        .unwrap(),
                ],
            ),
            PrivilegeClass::AdminRead,
        );

        let rest_action = GenericRestAction::from_provider_metadata(
            provider_action,
            RestHost::new("admin.googleapis.com").unwrap(),
            PathTemplate::new(
                "/admin/reports/v1/activity/users/all/applications/{applicationName}",
            )
            .unwrap(),
            QueryClass::Filter,
            &metadata,
        )
        .unwrap();

        assert_eq!(rest_action.provider_id, ProviderId::gws());
        assert_eq!(
            rest_action.action_key.as_str(),
            "admin.reports.activities.list"
        );
        assert_eq!(rest_action.method, ProviderMethod::Get);
        assert_eq!(rest_action.host.as_str(), "admin.googleapis.com");
        assert_eq!(
            rest_action.path_template.as_str(),
            "/admin/reports/v1/activity/users/all/applications/{applicationName}"
        );
        assert_eq!(rest_action.query_class, QueryClass::Filter);
        assert_eq!(
            rest_action.oauth_scope_labels.primary(),
            &OAuthScope::new("https://www.googleapis.com/auth/admin.reports.audit.readonly")
                .unwrap()
        );
        assert_eq!(rest_action.privilege_class, PrivilegeClass::AdminRead);
    }

    #[test]
    fn generic_rest_action_rejects_mismatched_provider_metadata() {
        let provider_action = ProviderSemanticAction::new(
            ProviderId::github(),
            "pulls.merge".parse().unwrap(),
            "repos/n01e0/agent-auditor/pulls/77",
        );
        let metadata = ProviderActionMetadata::new(
            ProviderActionId::from_parts("github", "actions.workflow_dispatch").unwrap(),
            ProviderMethod::Post,
            "repos/{owner}/{repo}/actions/workflows/{workflow_id}"
                .parse()
                .unwrap(),
            SideEffect::new("creates a workflow_dispatch event").unwrap(),
            OAuthScopeSet::new(
                OAuthScope::new("github.permission:actions:write").unwrap(),
                vec![OAuthScope::new("github.oauth:repo").unwrap()],
            ),
            PrivilegeClass::AdminWrite,
        );

        let error = GenericRestAction::from_provider_metadata(
            provider_action,
            RestHost::new("api.github.com").unwrap(),
            PathTemplate::new("/repos/{owner}/{repo}/pulls/{pull_number}/merge").unwrap(),
            QueryClass::None,
            &metadata,
        )
        .unwrap_err();

        assert_eq!(
            error,
            GenericRestContractError::ProviderMetadataMismatch {
                expected: ProviderActionId::from_parts("github", "pulls.merge").unwrap(),
                actual: ProviderActionId::from_parts("github", "actions.workflow_dispatch")
                    .unwrap(),
            }
        );
    }
}
