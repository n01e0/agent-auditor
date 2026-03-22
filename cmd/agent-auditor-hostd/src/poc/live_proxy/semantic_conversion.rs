use agenta_core::{
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
        LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};

use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, LiveHttpAuthHint, LiveHttpBodyClass,
    LiveHttpHeaderClass, LiveHttpRequestContract, LiveInterceptionMode as ProxyInterceptionMode,
    LiveProxySource, SemanticConversionBoundary, SessionCorrelationBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticConversionPlan {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub semantic_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SemanticConversionBoundary,
}

impl SemanticConversionPlan {
    pub fn from_session_correlation_boundary(boundary: SessionCorrelationBoundary) -> Self {
        let consumers = vec!["generic_rest", "gws", "github", "messaging"];
        let input_fields = boundary.correlation_fields;
        let semantic_fields = GenericLiveActionEnvelope::field_names().to_vec();

        Self {
            consumers: consumers.clone(),
            input_fields: input_fields.clone(),
            semantic_fields: semantic_fields.clone(),
            responsibilities: vec![
                "convert correlated live proxy requests into one agenta-core generic live action seam and envelope before generic REST, GWS, GitHub, or messaging-specific taxonomy consumes them",
                "derive only redaction-safe live surface, target, and provider hints without re-opening raw payload access or pre-committing to provider-local action labels",
                "separate cross-provider live request facts from provider-specific taxonomy so later adapters can reuse the same upstream envelope",
                "surface unsupported or degraded semantic conversion as explicit status instead of silently skipping downstream policy or records",
            ],
            stages: vec![
                "provider_hint",
                "generic_live_envelope",
                "provider_taxonomy_input",
                "handoff",
            ],
            handoff: SemanticConversionBoundary {
                consumers,
                input_fields,
                semantic_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> SemanticConversionBoundary {
        self.handoff.clone()
    }

    pub fn preview_generic_live_action_envelope(&self) -> GenericLiveActionEnvelope {
        let request = LiveHttpRequestContract::preview_github_repos_update_visibility();

        GenericLiveActionEnvelope::new(
            live_capture_source(request.source),
            LiveRequestId::new(request.request_id.to_string())
                .expect("preview request id should stay valid across the seam"),
            LiveCorrelationId::new(request.correlation_id.to_string())
                .expect("preview correlation id should stay valid across the seam"),
            "sess_live_proxy_preview",
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::github()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new(request.transport.to_string())
                .expect("preview transport should stay valid across the seam"),
            provider_method(request.method),
            RestHost::new(request.authority.to_string())
                .expect("preview authority should stay valid across the seam"),
            LivePath::new(request.path.to_string())
                .expect("preview path should stay valid across the seam"),
            live_headers(&request),
            live_body_class(request.body_class),
            live_auth_hint(request.auth_hint),
            Some("repos/n01e0/agent-auditor/visibility".to_owned()),
            live_mode(request.mode),
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "consumers={} semantic_fields={} stages={}",
            self.consumers.join(","),
            self.semantic_fields.join(","),
            self.stages.join("->")
        )
    }
}

fn live_capture_source(source: LiveProxySource) -> LiveCaptureSource {
    match source {
        LiveProxySource::ForwardProxy => LiveCaptureSource::ForwardProxy,
        LiveProxySource::BrowserRelay => LiveCaptureSource::BrowserRelay,
        LiveProxySource::SidecarProxy => LiveCaptureSource::SidecarProxy,
    }
}

fn provider_method(method: super::contract::LiveHttpMethod) -> ProviderMethod {
    match method {
        super::contract::LiveHttpMethod::Delete => ProviderMethod::Delete,
        super::contract::LiveHttpMethod::Get => ProviderMethod::Get,
        super::contract::LiveHttpMethod::Head => ProviderMethod::Head,
        super::contract::LiveHttpMethod::Options => ProviderMethod::Options,
        super::contract::LiveHttpMethod::Patch => ProviderMethod::Patch,
        super::contract::LiveHttpMethod::Post => ProviderMethod::Post,
        super::contract::LiveHttpMethod::Put => ProviderMethod::Put,
    }
}

fn live_headers(request: &LiveHttpRequestContract) -> LiveHeaders {
    LiveHeaders::new(
        request
            .headers
            .classes()
            .iter()
            .copied()
            .map(live_header_class),
    )
}

fn live_header_class(class: LiveHttpHeaderClass) -> LiveHeaderClass {
    match class {
        LiveHttpHeaderClass::Authorization => LiveHeaderClass::Authorization,
        LiveHttpHeaderClass::BrowserFetch => LiveHeaderClass::BrowserFetch,
        LiveHttpHeaderClass::Conditional => LiveHeaderClass::Conditional,
        LiveHttpHeaderClass::ContentJson => LiveHeaderClass::ContentJson,
        LiveHttpHeaderClass::ContentForm => LiveHeaderClass::ContentForm,
        LiveHttpHeaderClass::Cookie => LiveHeaderClass::Cookie,
        LiveHttpHeaderClass::FileUploadMetadata => LiveHeaderClass::FileUploadMetadata,
        LiveHttpHeaderClass::IdempotencyKey => LiveHeaderClass::IdempotencyKey,
        LiveHttpHeaderClass::MessageMetadata => LiveHeaderClass::MessageMetadata,
        LiveHttpHeaderClass::TenantScope => LiveHeaderClass::TenantScope,
    }
}

fn live_body_class(body_class: LiveHttpBodyClass) -> LiveBodyClass {
    match body_class {
        LiveHttpBodyClass::Binary => LiveBodyClass::Binary,
        LiveHttpBodyClass::FormUrlEncoded => LiveBodyClass::FormUrlencoded,
        LiveHttpBodyClass::Json => LiveBodyClass::Json,
        LiveHttpBodyClass::MultipartFormData => LiveBodyClass::MultipartFormData,
        LiveHttpBodyClass::None => LiveBodyClass::None,
        LiveHttpBodyClass::Text => LiveBodyClass::Text,
        LiveHttpBodyClass::Unknown => LiveBodyClass::Unknown,
    }
}

fn live_auth_hint(auth_hint: LiveHttpAuthHint) -> LiveAuthHint {
    match auth_hint {
        LiveHttpAuthHint::ApiKey => LiveAuthHint::ApiKey,
        LiveHttpAuthHint::Basic => LiveAuthHint::Basic,
        LiveHttpAuthHint::Bearer => LiveAuthHint::Bearer,
        LiveHttpAuthHint::CookieSession => LiveAuthHint::CookieSession,
        LiveHttpAuthHint::None => LiveAuthHint::None,
        LiveHttpAuthHint::OAuthServiceAccount => LiveAuthHint::OAuthServiceAccount,
        LiveHttpAuthHint::OAuthUser => LiveAuthHint::OAuthUser,
        LiveHttpAuthHint::Unknown => LiveAuthHint::Unknown,
    }
}

fn live_mode(mode: ProxyInterceptionMode) -> LiveInterceptionMode {
    match mode {
        ProxyInterceptionMode::Shadow => LiveInterceptionMode::Shadow,
        ProxyInterceptionMode::EnforcePreview => LiveInterceptionMode::EnforcePreview,
        ProxyInterceptionMode::Unsupported => LiveInterceptionMode::Unsupported,
    }
}
