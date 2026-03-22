use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};

pub const GENERIC_LIVE_ACTION_REDACTION_RULE: &str = "generic live action seams carry proxy source, request and correlation ids, session lineage, provider hints, live surface hints, HTTP method and authority and path labels, redaction-safe header classes, body classes, auth hints, target hints, mode labels, and content-retention status only; raw header values, cookies, bearer tokens, request bodies, response bodies, message text, file bytes, and provider-opaque payloads must not cross the seam";

pub const GENERIC_LIVE_ACTION_FIELDS: [&str; 19] = [
    "source",
    "request_id",
    "correlation_id",
    "session_id",
    "agent_id",
    "workspace_id",
    "provider_hint",
    "correlation_status",
    "live_surface",
    "transport",
    "method",
    "authority",
    "path",
    "headers",
    "body_class",
    "auth_hint",
    "target_hint",
    "mode",
    "content_retained",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCaptureSource {
    ForwardProxy,
    BrowserRelay,
    SidecarProxy,
}

impl LiveCaptureSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForwardProxy => "forward_proxy",
            Self::BrowserRelay => "browser_relay",
            Self::SidecarProxy => "sidecar_proxy",
        }
    }
}

impl fmt::Display for LiveCaptureSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LiveRequestId(String);

impl LiveRequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseLiveRequestIdError> {
        let value = validate_token("request_id", value)
            .map_err(|value| ParseLiveRequestIdError { value })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LiveRequestId {
    type Err = ParseLiveRequestIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for LiveRequestId {
    type Error = ParseLiveRequestIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LiveRequestId> for String {
    fn from(value: LiveRequestId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLiveRequestIdError {
    value: String,
}

impl fmt::Display for ParseLiveRequestIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid live request id `{}`: expected a non-empty token without whitespace",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LiveCorrelationId(String);

impl LiveCorrelationId {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseLiveCorrelationIdError> {
        let value = validate_token("correlation_id", value)
            .map_err(|value| ParseLiveCorrelationIdError { value })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveCorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LiveCorrelationId {
    type Err = ParseLiveCorrelationIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for LiveCorrelationId {
    type Error = ParseLiveCorrelationIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LiveCorrelationId> for String {
    fn from(value: LiveCorrelationId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLiveCorrelationIdError {
    value: String,
}

impl fmt::Display for ParseLiveCorrelationIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid live correlation id `{}`: expected a non-empty token without whitespace",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LiveTransport(String);

impl LiveTransport {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseLiveTransportError> {
        let value = validate_transport(value).map_err(|value| ParseLiveTransportError { value })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LiveTransport {
    type Err = ParseLiveTransportError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for LiveTransport {
    type Error = ParseLiveTransportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LiveTransport> for String {
    fn from(value: LiveTransport) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLiveTransportError {
    value: String,
}

impl fmt::Display for ParseLiveTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid live transport `{}`: expected a lowercase transport label without whitespace or URI punctuation",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LivePath(String);

impl LivePath {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseLivePathError> {
        let value = validate_path(value).map_err(|value| ParseLivePathError { value })?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LivePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LivePath {
    type Err = ParseLivePathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for LivePath {
    type Error = ParseLivePathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LivePath> for String {
    fn from(value: LivePath) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLivePathError {
    value: String,
}

impl fmt::Display for ParseLivePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid live path `{}`: expected a non-empty path starting with `/` and carrying no scheme, query, fragment, or whitespace",
            self.value
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LiveSurface(String);

impl LiveSurface {
    pub fn new(value: impl Into<String>) -> Result<Self, ParseLiveSurfaceError> {
        let value = value.into();
        if is_valid_surface_label(&value) {
            Ok(Self(value))
        } else {
            Err(ParseLiveSurfaceError { value })
        }
    }

    pub fn http_request() -> Self {
        Self("http.request".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LiveSurface {
    type Err = ParseLiveSurfaceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for LiveSurface {
    type Error = ParseLiveSurfaceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<LiveSurface> for String {
    fn from(value: LiveSurface) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLiveSurfaceError {
    value: String,
}

impl fmt::Display for ParseLiveSurfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid live surface `{}`: expected a lowercase dot-or-underscore-delimited label like `http.request`",
            self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCorrelationStatus {
    Confirmed,
    Provisional,
    Uncorrelated,
}

impl LiveCorrelationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Provisional => "provisional",
            Self::Uncorrelated => "uncorrelated",
        }
    }
}

impl fmt::Display for LiveCorrelationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveHeaderClass {
    Authorization,
    BrowserFetch,
    Conditional,
    ContentForm,
    ContentJson,
    Cookie,
    FileUploadMetadata,
    IdempotencyKey,
    MessageMetadata,
    TenantScope,
}

impl LiveHeaderClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::BrowserFetch => "browser_fetch",
            Self::Conditional => "conditional",
            Self::ContentForm => "content_form",
            Self::ContentJson => "content_json",
            Self::Cookie => "cookie",
            Self::FileUploadMetadata => "file_upload_metadata",
            Self::IdempotencyKey => "idempotency_key",
            Self::MessageMetadata => "message_metadata",
            Self::TenantScope => "tenant_scope",
        }
    }
}

impl fmt::Display for LiveHeaderClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LiveHeaders(Vec<LiveHeaderClass>);

impl LiveHeaders {
    pub fn new(classes: impl IntoIterator<Item = LiveHeaderClass>) -> Self {
        let mut classes = classes.into_iter().collect::<Vec<_>>();
        classes.sort_by_key(|class| class.as_str());
        classes.dedup();
        Self(classes)
    }

    pub fn classes(&self) -> &[LiveHeaderClass] {
        &self.0
    }

    pub fn labels(&self) -> Vec<&'static str> {
        self.0.iter().map(|class| class.as_str()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveBodyClass {
    Binary,
    FormUrlencoded,
    Json,
    MultipartFormData,
    None,
    Text,
    Unknown,
}

impl LiveBodyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::FormUrlencoded => "form_urlencoded",
            Self::Json => "json",
            Self::MultipartFormData => "multipart_form_data",
            Self::None => "none",
            Self::Text => "text",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for LiveBodyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveAuthHint {
    ApiKey,
    Basic,
    Bearer,
    CookieSession,
    None,
    OAuthServiceAccount,
    OAuthUser,
    Unknown,
}

impl LiveAuthHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::CookieSession => "cookie_session",
            Self::None => "none",
            Self::OAuthServiceAccount => "oauth_service_account",
            Self::OAuthUser => "oauth_user",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for LiveAuthHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInterceptionMode {
    Shadow,
    EnforcePreview,
    Unsupported,
}

impl LiveInterceptionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::EnforcePreview => "enforce_preview",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for LiveInterceptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericLiveActionEnvelope {
    pub source: LiveCaptureSource,
    pub request_id: LiveRequestId,
    pub correlation_id: LiveCorrelationId,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub workspace_id: Option<String>,
    pub provider_hint: Option<ProviderId>,
    pub correlation_status: LiveCorrelationStatus,
    pub live_surface: LiveSurface,
    pub transport: LiveTransport,
    pub method: ProviderMethod,
    pub authority: RestHost,
    pub path: LivePath,
    pub headers: LiveHeaders,
    pub body_class: LiveBodyClass,
    pub auth_hint: LiveAuthHint,
    pub target_hint: Option<String>,
    pub mode: LiveInterceptionMode,
    pub content_retained: bool,
}

impl GenericLiveActionEnvelope {
    pub fn field_names() -> &'static [&'static str] {
        &GENERIC_LIVE_ACTION_FIELDS
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: LiveCaptureSource,
        request_id: LiveRequestId,
        correlation_id: LiveCorrelationId,
        session_id: impl Into<String>,
        agent_id: Option<String>,
        workspace_id: Option<String>,
        provider_hint: Option<ProviderId>,
        correlation_status: LiveCorrelationStatus,
        live_surface: LiveSurface,
        transport: LiveTransport,
        method: ProviderMethod,
        authority: RestHost,
        path: LivePath,
        headers: LiveHeaders,
        body_class: LiveBodyClass,
        auth_hint: LiveAuthHint,
        target_hint: Option<String>,
        mode: LiveInterceptionMode,
    ) -> Self {
        Self {
            source,
            request_id,
            correlation_id,
            session_id: session_id.into(),
            agent_id,
            workspace_id,
            provider_hint,
            correlation_status,
            live_surface,
            transport,
            method,
            authority,
            path,
            headers,
            body_class,
            auth_hint,
            target_hint,
            mode,
            content_retained: false,
        }
    }

    pub fn preview_github_repos_update_visibility() -> Self {
        Self::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new("req_live_proxy_github_repos_update_visibility_preview")
                .expect("preview request id should be valid"),
            LiveCorrelationId::new("corr_live_proxy_github_repos_update_visibility_preview")
                .expect("preview correlation id should be valid"),
            "sess_live_proxy_preview",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::github()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").expect("preview transport should be valid"),
            ProviderMethod::Patch,
            RestHost::new("api.github.com").expect("preview authority should be valid"),
            LivePath::new("/repos/n01e0/agent-auditor").expect("preview path should be valid"),
            LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            Some("repos/n01e0/agent-auditor/visibility".to_owned()),
            LiveInterceptionMode::Shadow,
        )
    }

    pub fn summary_line(&self) -> String {
        let headers = self.headers.labels();
        let headers = if headers.is_empty() {
            "none".to_owned()
        } else {
            headers.join(",")
        };
        let provider_hint = self
            .provider_hint
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "none".to_owned());
        let target_hint = self
            .target_hint
            .clone()
            .unwrap_or_else(|| "none".to_owned());

        format!(
            "source={} request_id={} correlation_id={} session_id={} provider_hint={} correlation_status={} live_surface={} transport={} method={} authority={} path={} headers={} body_class={} auth_hint={} target_hint={} mode={} content_retained={}",
            self.source,
            self.request_id,
            self.correlation_id,
            self.session_id,
            provider_hint,
            self.correlation_status,
            self.live_surface,
            self.transport,
            self.method,
            self.authority,
            self.path,
            headers,
            self.body_class,
            self.auth_hint,
            target_hint,
            self.mode,
            self.content_retained,
        )
    }
}

fn validate_token(field: &str, value: impl Into<String>) -> Result<String, String> {
    let value = value.into().trim().to_owned();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(value);
    }

    let _ = field;
    Ok(value)
}

fn validate_transport(value: impl Into<String>) -> Result<String, String> {
    let value = value.into().trim().to_ascii_lowercase();
    if value.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
    {
        return Err(value);
    }

    Ok(value)
}

fn validate_path(value: impl Into<String>) -> Result<String, String> {
    let value = value.into().trim().to_owned();
    if value.is_empty()
        || !value.starts_with('/')
        || value.contains("://")
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_whitespace)
    {
        return Err(value);
    }

    Ok(value)
}

fn is_valid_surface_label(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_')
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        GENERIC_LIVE_ACTION_FIELDS, GENERIC_LIVE_ACTION_REDACTION_RULE, GenericLiveActionEnvelope,
        LiveAuthHint, LiveCaptureSource, LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass,
        LiveHeaders, LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    };
    use crate::{
        provider::{ProviderId, ProviderMethod},
        rest::RestHost,
    };

    #[test]
    fn generic_live_action_envelope_fixes_the_common_field_names_before_provider_taxonomy() {
        assert_eq!(
            GenericLiveActionEnvelope::field_names(),
            &GENERIC_LIVE_ACTION_FIELDS
        );
        assert_eq!(
            GenericLiveActionEnvelope::field_names(),
            &[
                "source",
                "request_id",
                "correlation_id",
                "session_id",
                "agent_id",
                "workspace_id",
                "provider_hint",
                "correlation_status",
                "live_surface",
                "transport",
                "method",
                "authority",
                "path",
                "headers",
                "body_class",
                "auth_hint",
                "target_hint",
                "mode",
                "content_retained",
            ]
        );
    }

    #[test]
    fn live_identifiers_transport_and_path_validate_redaction_safe_shapes() {
        assert!(LiveRequestId::new("").is_err());
        assert!(LiveRequestId::new("req with space").is_err());
        assert!(LiveCorrelationId::new("").is_err());
        assert!(LiveCorrelationId::new("corr with space").is_err());
        assert!(LiveTransport::new("").is_err());
        assert!(LiveTransport::new("https transport").is_err());
        assert!(LivePath::new("").is_err());
        assert!(LivePath::new("repos/n01e0/agent-auditor").is_err());
        assert!(LivePath::new("/repos/n01e0/agent-auditor?per_page=10").is_err());
        assert_eq!(
            LiveTransport::new("HTTPS")
                .expect("transport label should normalize to lowercase")
                .as_str(),
            "https"
        );
        assert_eq!(
            LivePath::new("/repos/n01e0/agent-auditor")
                .expect("plain path should be valid")
                .as_str(),
            "/repos/n01e0/agent-auditor"
        );
    }

    #[test]
    fn live_surface_and_header_classes_stay_stable_and_redaction_safe() {
        assert_eq!(LiveSurface::http_request().as_str(), "http.request");
        assert!(LiveSurface::new("browser.fetch").is_ok());
        assert!(LiveSurface::new("HTTP.request").is_err());

        let headers = LiveHeaders::new([
            LiveHeaderClass::TenantScope,
            LiveHeaderClass::Authorization,
            LiveHeaderClass::Authorization,
            LiveHeaderClass::ContentJson,
        ]);

        assert_eq!(
            headers.labels(),
            vec!["authorization", "content_json", "tenant_scope"]
        );
    }

    #[test]
    fn preview_generic_live_action_envelope_uses_shared_provider_and_rest_types() {
        let envelope = GenericLiveActionEnvelope::preview_github_repos_update_visibility();

        assert_eq!(envelope.source, LiveCaptureSource::ForwardProxy);
        assert_eq!(envelope.provider_hint, Some(ProviderId::github()));
        assert_eq!(
            envelope.correlation_status,
            LiveCorrelationStatus::Confirmed
        );
        assert_eq!(envelope.live_surface.as_str(), "http.request");
        assert_eq!(envelope.transport.as_str(), "https");
        assert_eq!(envelope.method, ProviderMethod::Patch);
        assert_eq!(envelope.authority, RestHost::new("api.github.com").unwrap());
        assert_eq!(envelope.path.as_str(), "/repos/n01e0/agent-auditor");
        assert_eq!(
            envelope.headers.labels(),
            vec!["authorization", "content_json"]
        );
        assert_eq!(envelope.auth_hint, LiveAuthHint::Bearer);
        assert_eq!(envelope.mode, LiveInterceptionMode::Shadow);
        assert!(!envelope.content_retained);
        assert!(envelope.summary_line().contains("provider_hint=github"));
        assert!(envelope.summary_line().contains("content_retained=false"));
    }

    #[test]
    fn generic_live_action_envelope_serializes_expected_shape() {
        let envelope = GenericLiveActionEnvelope::preview_github_repos_update_visibility();
        let value = serde_json::to_value(&envelope).expect("live envelope should serialize");

        assert_eq!(value["source"], json!("forward_proxy"));
        assert_eq!(
            value["request_id"],
            json!("req_live_proxy_github_repos_update_visibility_preview")
        );
        assert_eq!(value["provider_hint"], json!("github"));
        assert_eq!(value["live_surface"], json!("http.request"));
        assert_eq!(value["transport"], json!("https"));
        assert_eq!(value["method"], json!("patch"));
        assert_eq!(value["authority"], json!("api.github.com"));
        assert_eq!(value["path"], json!("/repos/n01e0/agent-auditor"));
        assert_eq!(value["headers"], json!(["authorization", "content_json"]));
        assert_eq!(value["mode"], json!("shadow"));
        assert_eq!(value["content_retained"], json!(false));
    }

    #[test]
    fn redaction_rule_mentions_only_redaction_safe_live_fields() {
        assert!(GENERIC_LIVE_ACTION_REDACTION_RULE.contains("proxy source"));
        assert!(GENERIC_LIVE_ACTION_REDACTION_RULE.contains("request and correlation ids"));
        assert!(GENERIC_LIVE_ACTION_REDACTION_RULE.contains("raw header values"));
        assert!(GENERIC_LIVE_ACTION_REDACTION_RULE.contains("provider-opaque payloads"));
    }
}
