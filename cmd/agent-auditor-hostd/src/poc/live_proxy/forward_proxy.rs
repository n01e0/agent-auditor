#![allow(clippy::result_large_err)]

use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader},
    path::PathBuf,
};

use agenta_core::{
    EventEnvelope, PolicyDecision,
    live::{
        GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
        LiveCorrelationId as CoreLiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass,
        LiveHeaders, LiveInterceptionMode, LivePath as CoreLivePath,
        LiveRequestId as CoreLiveRequestId, LiveSurface, LiveTransport as CoreLiveTransport,
    },
    provider::{ProviderId, ProviderMethod},
    rest::RestHost,
};
use thiserror::Error;

use crate::{
    poc::{
        persistence::{PersistenceError, append_json_line},
        rest::persist::GenericRestPocStore,
    },
    runtime,
};

use super::{
    LiveProxyInterceptionPlan,
    approval::LivePreviewApprovalProjection,
    audit::LivePreviewAuditReflection,
    contract::{
        LiveCorrelationId, LiveHttpAuthHint, LiveHttpAuthority, LiveHttpBodyClass,
        LiveHttpHeaderClass, LiveHttpHeaders, LiveHttpMethod, LiveHttpPath,
        LiveHttpRequestContract, LiveInterceptionMode as ProxyInterceptionMode, LiveProxySource,
        LiveRequestId, LiveTransport,
    },
    generic_rest::{GenericRestLivePreviewPlan, LiveGenericRestPreviewError},
    policy::{LivePreviewConsumer, LivePreviewPolicyError},
    session_correlation::{
        CorrelatedLiveRequest, ObservedRuntimePath, RuntimeSessionLineage, SessionCorrelationError,
    },
};

const INGRESS_DIR_NAME: &str = "agent-auditor-hostd-live-proxy-forward-proxy-ingress";
const INBOX_FILENAME: &str = "requests.jsonl";
const CURSOR_FILENAME: &str = "requests.cursor";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardProxyIngressPaths {
    pub root: PathBuf,
    pub inbox: PathBuf,
    pub cursor: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardProxyIngressInbox {
    paths: ForwardProxyIngressPaths,
}

impl ForwardProxyIngressInbox {
    pub const SOURCE_LABEL: &'static str = "forward_proxy_jsonl";

    pub fn bootstrap() -> Result<Self, ForwardProxyIngressError> {
        Self::from_root(runtime::runtime_store_root(INGRESS_DIR_NAME))
    }

    fn from_root(root: impl Into<PathBuf>) -> Result<Self, ForwardProxyIngressError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| ForwardProxyIngressError::PrepareRoot {
            path: root.clone(),
            source,
        })?;

        Ok(Self {
            paths: ForwardProxyIngressPaths {
                inbox: root.join(INBOX_FILENAME),
                cursor: root.join(CURSOR_FILENAME),
                root,
            },
        })
    }

    pub fn paths(&self) -> &ForwardProxyIngressPaths {
        &self.paths
    }

    pub fn append(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<(), ForwardProxyIngressError> {
        append_json_line(&self.paths.inbox, envelope).map_err(ForwardProxyIngressError::Persist)
    }

    pub fn drain_available(
        &self,
    ) -> Result<Vec<GenericLiveActionEnvelope>, ForwardProxyIngressError> {
        if !self.paths.inbox.exists() {
            return Ok(Vec::new());
        }

        let cursor = self.read_cursor()?;
        let file = OpenOptions::new()
            .read(true)
            .open(&self.paths.inbox)
            .map_err(|source| ForwardProxyIngressError::ReadInbox {
                path: self.paths.inbox.clone(),
                source,
            })?;
        let reader = BufReader::new(file);
        let mut drained = Vec::new();
        let mut processed_lines = cursor;

        for (line_idx, line) in reader.lines().enumerate() {
            let line_no = line_idx + 1;
            let line = line.map_err(|source| ForwardProxyIngressError::ReadInbox {
                path: self.paths.inbox.clone(),
                source,
            })?;
            if line_no <= cursor {
                continue;
            }
            if line.trim().is_empty() {
                processed_lines = line_no;
                continue;
            }

            let envelope =
                serde_json::from_str::<GenericLiveActionEnvelope>(&line).map_err(|source| {
                    ForwardProxyIngressError::DeserializeEnvelope {
                        path: self.paths.inbox.clone(),
                        line: line_no,
                        source,
                    }
                })?;
            drained.push(envelope);
            processed_lines = line_no;
        }

        self.write_cursor(processed_lines)?;
        Ok(drained)
    }

    fn read_cursor(&self) -> Result<usize, ForwardProxyIngressError> {
        match fs::read_to_string(&self.paths.cursor) {
            Ok(value) => value.trim().parse::<usize>().map_err(|source| {
                ForwardProxyIngressError::ParseCursor {
                    path: self.paths.cursor.clone(),
                    value,
                    source,
                }
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(ForwardProxyIngressError::ReadCursor {
                path: self.paths.cursor.clone(),
                source,
            }),
        }
    }

    fn write_cursor(&self, value: usize) -> Result<(), ForwardProxyIngressError> {
        fs::write(&self.paths.cursor, value.to_string()).map_err(|source| {
            ForwardProxyIngressError::WriteCursor {
                path: self.paths.cursor.clone(),
                source,
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardProxyProcessedRecord {
    pub request: LiveHttpRequestContract,
    pub correlated: CorrelatedLiveRequest,
    pub normalized_event: EventEnvelope,
    pub policy_decision: PolicyDecision,
    pub approval: LivePreviewApprovalProjection,
    pub reflection: LivePreviewAuditReflection,
}

impl ForwardProxyProcessedRecord {
    pub fn summary(&self) -> String {
        format!(
            "request_id={} source_kind={} event_id={} policy_decision={:?} approval_request={} mode_status={}",
            self.request.request_id,
            self.correlated.source_kind(),
            self.reflection.audit_record.event_id,
            self.policy_decision.decision,
            self.approval
                .approval_request
                .as_ref()
                .map(|request| request.approval_id.as_str())
                .unwrap_or("none"),
            self.reflection.mode_status,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardProxyIngressRuntime {
    inbox: ForwardProxyIngressInbox,
    observed_runtime: ObservedRuntimePath,
    store: GenericRestPocStore,
    generic_rest: GenericRestLivePreviewPlan,
    live_proxy: LiveProxyInterceptionPlan,
}

impl ForwardProxyIngressRuntime {
    pub fn bootstrap() -> Result<Self, ForwardProxyIngressRuntimeError> {
        Self::build(
            ForwardProxyIngressInbox::bootstrap()?,
            GenericRestPocStore::bootstrap().map_err(ForwardProxyIngressRuntimeError::Store)?,
            None,
        )
    }

    #[cfg(test)]
    fn fresh(root: impl Into<PathBuf>) -> Result<Self, ForwardProxyIngressRuntimeError> {
        let root = root.into();
        Self::build(
            ForwardProxyIngressInbox::from_root(root.join("ingress"))?,
            GenericRestPocStore::fresh(root.join("store"))
                .map_err(ForwardProxyIngressRuntimeError::Store)?,
            Some(root.join("observed")),
        )
    }

    fn build(
        inbox: ForwardProxyIngressInbox,
        store: GenericRestPocStore,
        observed_root: Option<PathBuf>,
    ) -> Result<Self, ForwardProxyIngressRuntimeError> {
        let live_proxy = LiveProxyInterceptionPlan::bootstrap();
        let observed_runtime = match observed_root {
            Some(root) => ObservedRuntimePath::from_root(root),
            None => live_proxy.session_correlation.observed_runtime(),
        }
        .map_err(|error| ForwardProxyIngressRuntimeError::SessionCorrelation(Box::new(error)))?;

        Ok(Self {
            inbox,
            observed_runtime,
            store,
            generic_rest: GenericRestLivePreviewPlan::default(),
            live_proxy,
        })
    }

    pub fn inbox(&self) -> &ForwardProxyIngressInbox {
        &self.inbox
    }

    pub fn observed_runtime(&self) -> &ObservedRuntimePath {
        &self.observed_runtime
    }

    pub fn store(&self) -> &GenericRestPocStore {
        &self.store
    }

    pub fn preview_fixture(session_id: impl Into<String>) -> GenericLiveActionEnvelope {
        GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            CoreLiveRequestId::new(
                "req_live_proxy_forward_proxy_gmail_users_messages_send_preview",
            )
            .expect("preview request id should stay valid"),
            CoreLiveCorrelationId::new(
                "corr_live_proxy_forward_proxy_gmail_users_messages_send_preview",
            )
            .expect("preview correlation id should stay valid"),
            session_id,
            Some("openclaw-main".to_owned()),
            Some("agent-auditor".to_owned()),
            Some(ProviderId::gws()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            CoreLiveTransport::new("https").expect("preview transport should stay valid"),
            ProviderMethod::Post,
            RestHost::new("gmail.googleapis.com").expect("preview authority should stay valid"),
            CoreLivePath::new("/gmail/v1/users/me/messages/send")
                .expect("preview path should stay valid"),
            LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            Some("gmail.users/me".to_owned()),
            LiveInterceptionMode::EnforcePreview,
        )
    }

    pub fn record(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<ForwardProxyProcessedRecord, ForwardProxyIngressRuntimeError> {
        let correlated = self
            .live_proxy
            .session_correlation
            .correlate_fixture(envelope)
            .map_err(|error| {
                ForwardProxyIngressRuntimeError::SessionCorrelation(Box::new(error))
            })?;
        self.record_correlated(correlated)
    }

    pub fn record_observed(
        &self,
        envelope: &GenericLiveActionEnvelope,
        lineage: &RuntimeSessionLineage,
    ) -> Result<ForwardProxyProcessedRecord, ForwardProxyIngressRuntimeError> {
        let correlated = self
            .live_proxy
            .session_correlation
            .correlate_observed_request(envelope, lineage)
            .map_err(|error| {
                ForwardProxyIngressRuntimeError::SessionCorrelation(Box::new(error))
            })?;
        self.record_correlated(correlated)
    }

    pub fn drain_observed_available(
        &self,
    ) -> Result<Vec<ForwardProxyProcessedRecord>, ForwardProxyIngressRuntimeError> {
        let mut records = Vec::new();
        for session_path in self
            .observed_runtime
            .discover_session_paths()
            .map_err(|error| ForwardProxyIngressRuntimeError::SessionCorrelation(Box::new(error)))?
        {
            let lineage = session_path.lineage().clone();
            for envelope in session_path.drain_available().map_err(|error| {
                ForwardProxyIngressRuntimeError::SessionCorrelation(Box::new(error))
            })? {
                records.push(self.record_observed(&envelope, &lineage)?);
            }
        }
        Ok(records)
    }

    fn record_correlated(
        &self,
        correlated: CorrelatedLiveRequest,
    ) -> Result<ForwardProxyProcessedRecord, ForwardProxyIngressRuntimeError> {
        let envelope = &correlated.envelope;
        validate_forward_proxy_envelope(envelope)?;
        let request = live_http_request_from_envelope(envelope)?;
        let normalized_event = self
            .generic_rest
            .normalize_live_request(&correlated)
            .map_err(ForwardProxyIngressRuntimeError::GenericRest)?;
        let annotated = self.live_proxy.policy.annotate_preview_event(
            LivePreviewConsumer::GenericRest,
            &normalized_event,
            envelope.mode.as_str(),
            request.summary_line(),
        );
        let evaluation = self
            .live_proxy
            .policy
            .evaluate_preview_event(LivePreviewConsumer::GenericRest, &annotated)
            .map_err(ForwardProxyIngressRuntimeError::Policy)?;
        let approval = self
            .live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .map_err(ForwardProxyIngressRuntimeError::Approval)?;
        let reflection = self
            .live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);
        self.live_proxy
            .audit
            .persist_reflection(&self.store, &reflection)
            .map_err(ForwardProxyIngressRuntimeError::AuditPersistence)?;

        Ok(ForwardProxyProcessedRecord {
            request,
            correlated,
            normalized_event: evaluation.normalized_event,
            policy_decision: evaluation.policy_decision,
            approval,
            reflection,
        })
    }

    pub fn drain_available(
        &self,
    ) -> Result<Vec<ForwardProxyProcessedRecord>, ForwardProxyIngressRuntimeError> {
        self.inbox
            .drain_available()?
            .into_iter()
            .map(|envelope| self.record(&envelope))
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum ForwardProxyIngressError {
    #[error("failed to prepare forward-proxy ingress root `{path}`: {source}")]
    PrepareRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to persist forward-proxy ingress payload: {0}")]
    Persist(#[source] PersistenceError),
    #[error("failed to read forward-proxy inbox `{path}`: {source}")]
    ReadInbox {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read forward-proxy cursor `{path}`: {source}")]
    ReadCursor {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse forward-proxy cursor `{path}` with value `{value}`: {source}")]
    ParseCursor {
        path: PathBuf,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("failed to write forward-proxy cursor `{path}`: {source}")]
    WriteCursor {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to deserialize forward-proxy envelope from `{path}` line {line}: {source}")]
    DeserializeEnvelope {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Error)]
pub enum ForwardProxyIngressRuntimeError {
    #[error(transparent)]
    Inbox(#[from] ForwardProxyIngressError),
    #[error("failed to bootstrap forward-proxy generic REST store: {0}")]
    Store(#[source] PersistenceError),
    #[error("forward-proxy session correlation failed: {0}")]
    SessionCorrelation(#[source] Box<SessionCorrelationError>),
    #[error("forward-proxy ingress requires source=forward_proxy but received {0}")]
    WrongSource(LiveCaptureSource),
    #[error("forward-proxy ingress requires content_retained=false")]
    ContentRetained,
    #[error("forward-proxy ingress request contract validation failed: {0}")]
    RequestContract(String),
    #[error(
        "forward-proxy ingress could not normalize the live envelope into generic REST preview: {0}"
    )]
    GenericRest(LiveGenericRestPreviewError),
    #[error("forward-proxy ingress policy evaluation failed: {0}")]
    Policy(#[source] LivePreviewPolicyError),
    #[error("forward-proxy ingress approval projection failed: {0}")]
    Approval(#[source] super::approval::LivePreviewApprovalError),
    #[error("forward-proxy ingress audit persistence failed: {0}")]
    AuditPersistence(#[source] super::audit::LivePreviewPersistenceError),
}

fn validate_forward_proxy_envelope(
    envelope: &GenericLiveActionEnvelope,
) -> Result<(), ForwardProxyIngressRuntimeError> {
    if envelope.source != LiveCaptureSource::ForwardProxy {
        return Err(ForwardProxyIngressRuntimeError::WrongSource(
            envelope.source,
        ));
    }
    if envelope.content_retained {
        return Err(ForwardProxyIngressRuntimeError::ContentRetained);
    }

    Ok(())
}

fn live_http_request_from_envelope(
    envelope: &GenericLiveActionEnvelope,
) -> Result<LiveHttpRequestContract, ForwardProxyIngressRuntimeError> {
    Ok(LiveHttpRequestContract {
        source: LiveProxySource::ForwardProxy,
        request_id: LiveRequestId::new(envelope.request_id.to_string())
            .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        correlation_id: LiveCorrelationId::new(envelope.correlation_id.to_string())
            .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        transport: LiveTransport::new(envelope.transport.as_str())
            .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        method: live_http_method(envelope.method),
        authority: LiveHttpAuthority::new(envelope.authority.to_string())
            .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        path: LiveHttpPath::new(envelope.path.to_string())
            .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        headers: LiveHttpHeaders::new(
            envelope
                .headers
                .labels()
                .into_iter()
                .map(parse_live_http_header_class)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ForwardProxyIngressRuntimeError::RequestContract)?,
        ),
        body_class: live_http_body_class(envelope.body_class),
        auth_hint: live_http_auth_hint(envelope.auth_hint),
        mode: live_proxy_mode(envelope.mode),
    })
}

fn live_http_method(method: ProviderMethod) -> LiveHttpMethod {
    match method {
        ProviderMethod::Delete => LiveHttpMethod::Delete,
        ProviderMethod::Get => LiveHttpMethod::Get,
        ProviderMethod::Head => LiveHttpMethod::Head,
        ProviderMethod::Options => LiveHttpMethod::Options,
        ProviderMethod::Patch => LiveHttpMethod::Patch,
        ProviderMethod::Post => LiveHttpMethod::Post,
        ProviderMethod::Put => LiveHttpMethod::Put,
    }
}

fn parse_live_http_header_class(label: &str) -> Result<LiveHttpHeaderClass, String> {
    match label {
        "authorization" => Ok(LiveHttpHeaderClass::Authorization),
        "browser_fetch" => Ok(LiveHttpHeaderClass::BrowserFetch),
        "conditional" => Ok(LiveHttpHeaderClass::Conditional),
        "content_form" => Ok(LiveHttpHeaderClass::ContentForm),
        "content_json" => Ok(LiveHttpHeaderClass::ContentJson),
        "cookie" => Ok(LiveHttpHeaderClass::Cookie),
        "file_upload_metadata" => Ok(LiveHttpHeaderClass::FileUploadMetadata),
        "idempotency_key" => Ok(LiveHttpHeaderClass::IdempotencyKey),
        "message_metadata" => Ok(LiveHttpHeaderClass::MessageMetadata),
        "tenant_scope" => Ok(LiveHttpHeaderClass::TenantScope),
        _ => Err(format!("unsupported live header class `{label}`")),
    }
}

fn live_http_body_class(body_class: LiveBodyClass) -> LiveHttpBodyClass {
    match body_class {
        LiveBodyClass::Binary => LiveHttpBodyClass::Binary,
        LiveBodyClass::FormUrlencoded => LiveHttpBodyClass::FormUrlEncoded,
        LiveBodyClass::Json => LiveHttpBodyClass::Json,
        LiveBodyClass::MultipartFormData => LiveHttpBodyClass::MultipartFormData,
        LiveBodyClass::None => LiveHttpBodyClass::None,
        LiveBodyClass::Text => LiveHttpBodyClass::Text,
        LiveBodyClass::Unknown => LiveHttpBodyClass::Unknown,
    }
}

fn live_http_auth_hint(auth_hint: LiveAuthHint) -> LiveHttpAuthHint {
    match auth_hint {
        LiveAuthHint::ApiKey => LiveHttpAuthHint::ApiKey,
        LiveAuthHint::Basic => LiveHttpAuthHint::Basic,
        LiveAuthHint::Bearer => LiveHttpAuthHint::Bearer,
        LiveAuthHint::CookieSession => LiveHttpAuthHint::CookieSession,
        LiveAuthHint::None => LiveHttpAuthHint::None,
        LiveAuthHint::OAuthServiceAccount => LiveHttpAuthHint::OAuthServiceAccount,
        LiveAuthHint::OAuthUser => LiveHttpAuthHint::OAuthUser,
        LiveAuthHint::Unknown => LiveHttpAuthHint::Unknown,
    }
}

fn live_proxy_mode(mode: LiveInterceptionMode) -> ProxyInterceptionMode {
    match mode {
        LiveInterceptionMode::Shadow => ProxyInterceptionMode::Shadow,
        LiveInterceptionMode::EnforcePreview => ProxyInterceptionMode::EnforcePreview,
        LiveInterceptionMode::Unsupported => ProxyInterceptionMode::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::poc::live_proxy::{
        contract::{
            LiveHttpMethod, LiveInterceptionMode as ProxyInterceptionMode, LiveProxySource,
        },
        session_correlation::RuntimeSessionLineage,
    };

    use super::{
        ForwardProxyIngressInbox, ForwardProxyIngressRuntime, live_http_request_from_envelope,
    };

    #[test]
    fn inbox_drains_only_new_forward_proxy_envelopes() {
        let inbox = ForwardProxyIngressInbox::from_root(unique_state_dir())
            .expect("inbox should bootstrap");
        let first = ForwardProxyIngressRuntime::preview_fixture("sess_forward_proxy_first");
        let second = ForwardProxyIngressRuntime::preview_fixture("sess_forward_proxy_second");

        inbox.append(&first).expect("first envelope should append");
        inbox
            .append(&second)
            .expect("second envelope should append");

        let drained = inbox.drain_available().expect("drain should succeed");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].session_id, "sess_forward_proxy_first");
        assert_eq!(drained[1].session_id, "sess_forward_proxy_second");
        assert!(
            inbox
                .drain_available()
                .expect("second drain should succeed")
                .is_empty()
        );
    }

    #[test]
    fn preview_fixture_round_trips_into_the_proxy_request_contract() {
        let envelope = ForwardProxyIngressRuntime::preview_fixture("sess_forward_proxy_round_trip");
        let request = live_http_request_from_envelope(&envelope)
            .expect("preview fixture should validate as a proxy seam request");

        assert_eq!(request.source, LiveProxySource::ForwardProxy);
        assert_eq!(request.method, LiveHttpMethod::Post);
        assert_eq!(request.authority.to_string(), "gmail.googleapis.com");
        assert_eq!(request.path.to_string(), "/gmail/v1/users/me/messages/send");
        assert_eq!(
            request.headers.labels(),
            vec!["authorization", "content_json"]
        );
        assert_eq!(request.mode, ProxyInterceptionMode::EnforcePreview);
    }

    #[test]
    fn observed_runtime_drain_records_non_fixture_source_kind() {
        let runtime = ForwardProxyIngressRuntime::fresh(unique_state_dir())
            .expect("runtime should bootstrap");
        let lineage = RuntimeSessionLineage::new(
            "sess_forward_proxy_observed_runtime",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let session_path = runtime
            .observed_runtime()
            .session_path(lineage.clone())
            .expect("observed session path should initialize");
        let envelope = ForwardProxyIngressRuntime::preview_fixture(lineage.session_id.clone());

        session_path
            .append(&envelope)
            .expect("observed envelope should append");

        let mut records = runtime
            .drain_observed_available()
            .expect("observed runtime should drain");
        let record = records.pop().expect("observed record should exist");

        assert_eq!(record.correlated.source_kind(), "live_proxy_observed");
        assert_eq!(record.correlated.event_suffix(), "observed");
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("source_kind")
                .and_then(|value| value.as_str()),
            Some("live_proxy_observed")
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("observation_provenance")
                .and_then(|value| value.as_str()),
            Some("observed_request")
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("validation_status")
                .and_then(|value| value.as_str()),
            Some("observed_request")
        );
        assert_eq!(
            record
                .normalized_event
                .action
                .attributes
                .get("session_correlation_status")
                .and_then(|value| value.as_str()),
            Some("runtime_path_confirmed")
        );
    }

    fn unique_state_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!(
            "agent-auditor-hostd-forward-proxy-inbox-test-{nonce}"
        ))
    }
}
