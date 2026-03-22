use std::fmt;

pub const LIVE_PROXY_INTERCEPTION_REDACTION_RULE: &str = "live proxy seams carry only redaction-safe method, authority, path, header classes, body classes, auth hints, correlation ids, session lineage, semantic family hints, mode labels, and approval/audit linkage; raw header values, cookies, bearer tokens, request bodies, response bodies, message content, file bytes, and provider-opaque payloads must not cross the seam";

pub const LIVE_PROXY_SOURCE_LABELS: [&str; 3] = ["forward_proxy", "browser_relay", "sidecar_proxy"];
pub const LIVE_INTERCEPTION_MODE_LABELS: [&str; 3] = ["shadow", "enforce_preview", "unsupported"];
pub const LIVE_HTTP_REQUEST_FIELDS: [&str; 11] = [
    "source",
    "request_id",
    "correlation_id",
    "transport",
    "method",
    "authority",
    "path",
    "headers",
    "body_class",
    "auth_hint",
    "mode",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveProxySource {
    ForwardProxy,
    BrowserRelay,
    SidecarProxy,
}

impl LiveProxySource {
    pub fn label(self) -> &'static str {
        match self {
            Self::ForwardProxy => "forward_proxy",
            Self::BrowserRelay => "browser_relay",
            Self::SidecarProxy => "sidecar_proxy",
        }
    }
}

impl fmt::Display for LiveProxySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRequestId(String);

impl LiveRequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        validate_token("request_id", value).map(Self)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCorrelationId(String);

impl LiveCorrelationId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        validate_token("correlation_id", value).map(Self)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTransport(String);

impl LiveTransport {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        validate_transport(value).map(Self)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LiveHttpMethod {
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
}

impl LiveHttpMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

impl fmt::Display for LiveHttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHttpAuthority(String);

impl LiveHttpAuthority {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let authority = value.into().trim().to_owned();
        if authority.is_empty() {
            return Err("authority must not be blank".to_owned());
        }
        if authority.contains("://")
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.chars().any(char::is_whitespace)
        {
            return Err(
                "authority must contain only the authority component without scheme, path, query, fragment, or whitespace"
                    .to_owned(),
            );
        }

        Ok(Self(authority))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveHttpAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHttpPath(String);

impl LiveHttpPath {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let path = value.into().trim().to_owned();
        if path.is_empty() {
            return Err("path must not be blank".to_owned());
        }
        if !path.starts_with('/') {
            return Err(
                "path must start with '/' so the contract cannot carry authority fragments"
                    .to_owned(),
            );
        }
        if path.contains("://")
            || path.contains('?')
            || path.contains('#')
            || path.chars().any(char::is_whitespace)
        {
            return Err(
                "path must contain only the redaction-safe path component without scheme, query, fragment, or whitespace"
                    .to_owned(),
            );
        }

        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LiveHttpPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LiveHttpHeaderClass {
    Authorization,
    BrowserFetch,
    Conditional,
    ContentJson,
    ContentForm,
    Cookie,
    FileUploadMetadata,
    IdempotencyKey,
    MessageMetadata,
    TenantScope,
}

impl LiveHttpHeaderClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::BrowserFetch => "browser_fetch",
            Self::Conditional => "conditional",
            Self::ContentJson => "content_json",
            Self::ContentForm => "content_form",
            Self::Cookie => "cookie",
            Self::FileUploadMetadata => "file_upload_metadata",
            Self::IdempotencyKey => "idempotency_key",
            Self::MessageMetadata => "message_metadata",
            Self::TenantScope => "tenant_scope",
        }
    }
}

impl fmt::Display for LiveHttpHeaderClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LiveHttpHeaders {
    classes: Vec<LiveHttpHeaderClass>,
}

impl LiveHttpHeaders {
    pub fn new(classes: impl IntoIterator<Item = LiveHttpHeaderClass>) -> Self {
        let mut classes = classes.into_iter().collect::<Vec<_>>();
        classes.sort_by_key(|class| class.label());
        classes.dedup();

        Self { classes }
    }

    pub fn classes(&self) -> &[LiveHttpHeaderClass] {
        &self.classes
    }

    pub fn labels(&self) -> Vec<&'static str> {
        self.classes.iter().map(|class| class.label()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveHttpBodyClass {
    Binary,
    FormUrlEncoded,
    Json,
    MultipartFormData,
    None,
    Text,
    Unknown,
}

impl LiveHttpBodyClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::FormUrlEncoded => "form_urlencoded",
            Self::Json => "json",
            Self::MultipartFormData => "multipart_form_data",
            Self::None => "none",
            Self::Text => "text",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for LiveHttpBodyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveHttpAuthHint {
    ApiKey,
    Basic,
    Bearer,
    CookieSession,
    None,
    OAuthServiceAccount,
    OAuthUser,
    Unknown,
}

impl LiveHttpAuthHint {
    pub fn label(self) -> &'static str {
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

impl fmt::Display for LiveHttpAuthHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveInterceptionMode {
    Shadow,
    EnforcePreview,
    Unsupported,
}

impl LiveInterceptionMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::EnforcePreview => "enforce_preview",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for LiveInterceptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHttpRequestContract {
    pub source: LiveProxySource,
    pub request_id: LiveRequestId,
    pub correlation_id: LiveCorrelationId,
    pub transport: LiveTransport,
    pub method: LiveHttpMethod,
    pub authority: LiveHttpAuthority,
    pub path: LiveHttpPath,
    pub headers: LiveHttpHeaders,
    pub body_class: LiveHttpBodyClass,
    pub auth_hint: LiveHttpAuthHint,
    pub mode: LiveInterceptionMode,
}

impl LiveHttpRequestContract {
    pub fn field_names() -> &'static [&'static str] {
        &LIVE_HTTP_REQUEST_FIELDS
    }

    pub fn preview_github_repos_update_visibility() -> Self {
        Self {
            source: LiveProxySource::ForwardProxy,
            request_id: LiveRequestId::new("req_live_proxy_github_repos_update_visibility_preview")
                .expect("preview request id should be valid"),
            correlation_id: LiveCorrelationId::new(
                "corr_live_proxy_github_repos_update_visibility_preview",
            )
            .expect("preview correlation id should be valid"),
            transport: LiveTransport::new("https").expect("preview transport should be valid"),
            method: LiveHttpMethod::Patch,
            authority: LiveHttpAuthority::new("api.github.com")
                .expect("preview authority should be valid"),
            path: LiveHttpPath::new("/repos/n01e0/agent-auditor")
                .expect("preview path should be valid"),
            headers: LiveHttpHeaders::new([
                LiveHttpHeaderClass::Authorization,
                LiveHttpHeaderClass::ContentJson,
            ]),
            body_class: LiveHttpBodyClass::Json,
            auth_hint: LiveHttpAuthHint::Bearer,
            mode: LiveInterceptionMode::Shadow,
        }
    }

    pub fn summary_line(&self) -> String {
        let headers = self.headers.labels();
        let headers = if headers.is_empty() {
            "none".to_owned()
        } else {
            headers.join(",")
        };

        format!(
            "event=live_proxy.http_request source={} request_id={} correlation_id={} transport={} method={} authority={} path={} headers={} body_class={} auth_hint={} mode={}",
            self.source,
            self.request_id,
            self.correlation_id,
            self.transport,
            self.method,
            self.authority,
            self.path,
            headers,
            self.body_class,
            self.auth_hint,
            self.mode,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySeamBoundary {
    pub sources: Vec<&'static str>,
    pub request_fields: Vec<&'static str>,
    pub handoff_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCorrelationBoundary {
    pub sources: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub correlation_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticConversionBoundary {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub semantic_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundary {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBoundary {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub approval_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBoundary {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

fn validate_token(field: &str, value: impl Into<String>) -> Result<String, String> {
    let value = value.into().trim().to_owned();
    if value.is_empty() {
        return Err(format!("{field} must not be blank"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{field} must not contain whitespace"));
    }

    Ok(value)
}

fn validate_transport(value: impl Into<String>) -> Result<String, String> {
    let transport = value.into().trim().to_ascii_lowercase();
    if transport.is_empty() {
        return Err("transport must not be blank".to_owned());
    }
    if transport.chars().any(char::is_whitespace)
        || transport.contains('/')
        || transport.contains('?')
        || transport.contains('#')
    {
        return Err(
            "transport must be a stable label such as http, https, or h2 without whitespace or URI punctuation"
                .to_owned(),
        );
    }

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::{
        LIVE_HTTP_REQUEST_FIELDS, LIVE_INTERCEPTION_MODE_LABELS, LIVE_PROXY_SOURCE_LABELS,
        LiveCorrelationId, LiveHttpAuthHint, LiveHttpAuthority, LiveHttpBodyClass,
        LiveHttpHeaderClass, LiveHttpHeaders, LiveHttpPath, LiveHttpRequestContract,
        LiveInterceptionMode, LiveProxySource, LiveRequestId, LiveTransport,
    };

    #[test]
    fn live_http_request_contract_fixes_the_minimal_field_names() {
        assert_eq!(
            LiveHttpRequestContract::field_names(),
            &LIVE_HTTP_REQUEST_FIELDS
        );
        assert_eq!(
            LiveHttpRequestContract::field_names(),
            &[
                "source",
                "request_id",
                "correlation_id",
                "transport",
                "method",
                "authority",
                "path",
                "headers",
                "body_class",
                "auth_hint",
                "mode",
            ]
        );
    }

    #[test]
    fn authority_rejects_scheme_path_query_fragment_and_whitespace() {
        assert!(LiveHttpAuthority::new("").is_err());
        assert!(LiveHttpAuthority::new("https://api.github.com").is_err());
        assert!(LiveHttpAuthority::new("api.github.com/repos").is_err());
        assert!(LiveHttpAuthority::new("api.github.com?foo=bar").is_err());
        assert!(LiveHttpAuthority::new("api.github.com#frag").is_err());
        assert!(LiveHttpAuthority::new("api github.com").is_err());
        assert_eq!(
            LiveHttpAuthority::new("api.github.com:443")
                .expect("port-qualified authority should be valid")
                .as_str(),
            "api.github.com:443"
        );
    }

    #[test]
    fn path_rejects_missing_leading_slash_and_query_or_fragment_components() {
        assert!(LiveHttpPath::new("").is_err());
        assert!(LiveHttpPath::new("repos/n01e0/agent-auditor").is_err());
        assert!(LiveHttpPath::new("https://api.github.com/repos/n01e0/agent-auditor").is_err());
        assert!(LiveHttpPath::new("/repos/n01e0/agent-auditor?per_page=100").is_err());
        assert!(LiveHttpPath::new("/repos/n01e0/agent-auditor#frag").is_err());
        assert_eq!(
            LiveHttpPath::new("/repos/n01e0/agent-auditor")
                .expect("plain path should be valid")
                .as_str(),
            "/repos/n01e0/agent-auditor"
        );
    }

    #[test]
    fn request_ids_correlation_ids_and_transport_reject_blank_or_whitespace_values() {
        assert!(LiveRequestId::new("").is_err());
        assert!(LiveRequestId::new("req with space").is_err());
        assert!(LiveCorrelationId::new("").is_err());
        assert!(LiveCorrelationId::new("corr with space").is_err());
        assert!(LiveTransport::new("").is_err());
        assert!(LiveTransport::new("https transport").is_err());
        assert_eq!(
            LiveTransport::new("HTTPS")
                .expect("transport label should normalize to lowercase")
                .as_str(),
            "https"
        );
    }

    #[test]
    fn headers_deduplicate_into_stable_redaction_safe_labels() {
        let headers = LiveHttpHeaders::new([
            LiveHttpHeaderClass::TenantScope,
            LiveHttpHeaderClass::Authorization,
            LiveHttpHeaderClass::Authorization,
            LiveHttpHeaderClass::ContentJson,
        ]);

        assert_eq!(
            headers.classes(),
            &[
                LiveHttpHeaderClass::Authorization,
                LiveHttpHeaderClass::ContentJson,
                LiveHttpHeaderClass::TenantScope,
            ]
        );
        assert_eq!(
            headers.labels(),
            vec!["authorization", "content_json", "tenant_scope"]
        );
    }

    #[test]
    fn preview_request_keeps_only_redaction_safe_contract_shapes() {
        let request = LiveHttpRequestContract::preview_github_repos_update_visibility();

        assert_eq!(request.source, LiveProxySource::ForwardProxy);
        assert_eq!(
            request.request_id.as_str(),
            "req_live_proxy_github_repos_update_visibility_preview"
        );
        assert_eq!(
            request.correlation_id.as_str(),
            "corr_live_proxy_github_repos_update_visibility_preview"
        );
        assert_eq!(request.transport.as_str(), "https");
        assert_eq!(request.method.to_string(), "PATCH");
        assert_eq!(request.authority.as_str(), "api.github.com");
        assert_eq!(request.path.as_str(), "/repos/n01e0/agent-auditor");
        assert_eq!(
            request.headers.labels(),
            vec!["authorization", "content_json"]
        );
        assert_eq!(request.body_class, LiveHttpBodyClass::Json);
        assert_eq!(request.auth_hint, LiveHttpAuthHint::Bearer);
        assert_eq!(request.mode, LiveInterceptionMode::Shadow);
        assert!(
            request
                .summary_line()
                .contains("headers=authorization,content_json")
        );
        assert!(request.summary_line().contains("mode=shadow"));
    }

    #[test]
    fn source_and_mode_labels_match_pipeline_constants() {
        assert_eq!(
            LIVE_PROXY_SOURCE_LABELS,
            [
                LiveProxySource::ForwardProxy.label(),
                LiveProxySource::BrowserRelay.label(),
                LiveProxySource::SidecarProxy.label(),
            ]
        );
        assert_eq!(
            LIVE_INTERCEPTION_MODE_LABELS,
            [
                LiveInterceptionMode::Shadow.label(),
                LiveInterceptionMode::EnforcePreview.label(),
                LiveInterceptionMode::Unsupported.label(),
            ]
        );
    }
}
