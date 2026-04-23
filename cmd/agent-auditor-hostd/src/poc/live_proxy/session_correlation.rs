#![allow(clippy::result_large_err)]

use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use agenta_core::{SessionRef, live::GenericLiveActionEnvelope};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    poc::persistence::{PersistenceError, append_json_line},
    runtime,
};

use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, ProxySeamBoundary, SessionCorrelationBoundary,
};

const OBSERVED_RUNTIME_DIR_NAME: &str = "agent-auditor-hostd-live-proxy-observed-runtime";
const SESSIONS_DIR_NAME: &str = "sessions";
const REQUESTS_FILENAME: &str = "requests.jsonl";
const CURSOR_FILENAME: &str = "requests.cursor";
const METADATA_FILENAME: &str = "session.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveRequestProvenance {
    FixturePreview,
    ObservedRuntimePath,
}

impl LiveRequestProvenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::FixturePreview => "live_proxy_preview",
            Self::ObservedRuntimePath => "live_proxy_observed",
        }
    }

    pub fn event_suffix(self) -> &'static str {
        match self {
            Self::FixturePreview => "preview",
            Self::ObservedRuntimePath => "observed",
        }
    }

    pub fn session_correlation_status(self) -> &'static str {
        match self {
            Self::FixturePreview => "fixture_lineage",
            Self::ObservedRuntimePath => "runtime_path_confirmed",
        }
    }

    pub fn session_correlation_reason(self) -> &'static str {
        match self {
            Self::FixturePreview => {
                "synthetic fixture supplied session lineage inline for preview coverage"
            }
            Self::ObservedRuntimePath => {
                "session-owned runtime path bound the observed request to hostd session lineage"
            }
        }
    }

    pub fn result_reason(self) -> &'static str {
        match self {
            Self::FixturePreview => {
                "normalized from a live proxy envelope into the generic REST preview contract"
            }
            Self::ObservedRuntimePath => {
                "normalized from a session-correlated observed live proxy envelope into the generic REST preview contract"
            }
        }
    }

    pub fn host_id(self) -> &'static str {
        match self {
            Self::FixturePreview => "hostd-live-proxy-preview",
            Self::ObservedRuntimePath => "hostd-live-proxy-observed",
        }
    }

    pub fn policy_bundle_version(self) -> &'static str {
        match self {
            Self::FixturePreview => "bundle-live-proxy-preview",
            Self::ObservedRuntimePath => "bundle-live-proxy-observed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSessionLineage {
    pub session_id: String,
    pub agent_id: String,
    pub workspace_id: Option<String>,
}

impl RuntimeSessionLineage {
    pub fn new(
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        workspace_id: Option<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            agent_id: agent_id.into(),
            workspace_id,
        }
    }

    pub fn session_ref(&self, policy_bundle_version: impl Into<String>) -> SessionRef {
        SessionRef {
            session_id: self.session_id.clone(),
            agent_id: Some(self.agent_id.clone()),
            initiator_id: None,
            workspace_id: self.workspace_id.clone(),
            policy_bundle_version: Some(policy_bundle_version.into()),
            environment: Some("dev".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedLiveRequest {
    pub envelope: GenericLiveActionEnvelope,
    pub session: SessionRef,
    pub provenance: LiveRequestProvenance,
    pub session_correlation_status: &'static str,
    pub session_correlation_reason: &'static str,
}

impl CorrelatedLiveRequest {
    pub fn event_suffix(&self) -> &'static str {
        self.provenance.event_suffix()
    }

    pub fn source_kind(&self) -> &'static str {
        self.provenance.label()
    }

    pub fn result_reason(&self) -> &'static str {
        self.provenance.result_reason()
    }

    pub fn host_id(&self) -> &'static str {
        self.provenance.host_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRuntimePaths {
    pub root: PathBuf,
    pub sessions_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRuntimePath {
    paths: ObservedRuntimePaths,
}

impl ObservedRuntimePath {
    pub const SOURCE_LABEL: &'static str = "forward_proxy_observed_runtime_path";

    pub fn bootstrap() -> Result<Self, SessionCorrelationError> {
        Self::from_root(runtime::runtime_store_root(OBSERVED_RUNTIME_DIR_NAME))
    }

    pub fn from_root(root: impl Into<PathBuf>) -> Result<Self, SessionCorrelationError> {
        let root = root.into();
        let sessions_root = root.join(SESSIONS_DIR_NAME);
        fs::create_dir_all(&sessions_root).map_err(|source| {
            SessionCorrelationError::PrepareObservedRoot {
                path: sessions_root.clone(),
                source,
            }
        })?;

        Ok(Self {
            paths: ObservedRuntimePaths {
                root,
                sessions_root,
            },
        })
    }

    pub fn paths(&self) -> &ObservedRuntimePaths {
        &self.paths
    }

    pub fn session_path(
        &self,
        lineage: RuntimeSessionLineage,
    ) -> Result<ObservedSessionPath, SessionCorrelationError> {
        ObservedSessionPath::new(self.paths.sessions_root.clone(), lineage)
    }

    pub fn discover_session_paths(
        &self,
    ) -> Result<Vec<ObservedSessionPath>, SessionCorrelationError> {
        if !self.paths.sessions_root.exists() {
            return Ok(Vec::new());
        }

        let mut discovered = Vec::new();
        for entry in fs::read_dir(&self.paths.sessions_root).map_err(|source| {
            SessionCorrelationError::ReadObservedSessionsRoot {
                path: self.paths.sessions_root.clone(),
                source,
            }
        })? {
            let entry =
                entry.map_err(|source| SessionCorrelationError::ReadObservedSessionsRoot {
                    path: self.paths.sessions_root.clone(),
                    source,
                })?;
            if !entry
                .file_type()
                .map_err(|source| SessionCorrelationError::ReadObservedSessionsRoot {
                    path: entry.path(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }
            let path = entry.path();
            if !path.join(METADATA_FILENAME).exists() {
                continue;
            }
            discovered.push(ObservedSessionPath::load(path)?);
        }

        discovered.sort_by(|left, right| {
            left.lineage
                .session_id
                .cmp(&right.lineage.session_id)
                .then_with(|| left.lineage.agent_id.cmp(&right.lineage.agent_id))
                .then_with(|| left.lineage.workspace_id.cmp(&right.lineage.workspace_id))
        });
        Ok(discovered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSessionPaths {
    pub root: PathBuf,
    pub metadata: PathBuf,
    pub inbox: PathBuf,
    pub cursor: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSessionPath {
    lineage: RuntimeSessionLineage,
    paths: ObservedSessionPaths,
}

impl ObservedSessionPath {
    fn new(
        sessions_root: PathBuf,
        lineage: RuntimeSessionLineage,
    ) -> Result<Self, SessionCorrelationError> {
        let root = session_dir(&sessions_root, &lineage);
        fs::create_dir_all(&root).map_err(|source| {
            SessionCorrelationError::PrepareObservedSessionRoot {
                path: root.clone(),
                source,
            }
        })?;

        let path = Self {
            lineage,
            paths: ObservedSessionPaths {
                metadata: root.join(METADATA_FILENAME),
                inbox: root.join(REQUESTS_FILENAME),
                cursor: root.join(CURSOR_FILENAME),
                root,
            },
        };
        path.persist_metadata()?;
        Ok(path)
    }

    fn load(root: PathBuf) -> Result<Self, SessionCorrelationError> {
        let metadata_path = root.join(METADATA_FILENAME);
        let metadata = fs::read_to_string(&metadata_path).map_err(|source| {
            SessionCorrelationError::ReadObservedSessionMetadata {
                path: metadata_path.clone(),
                source,
            }
        })?;
        let lineage =
            serde_json::from_str::<RuntimeSessionLineage>(&metadata).map_err(|source| {
                SessionCorrelationError::ParseObservedSessionMetadata {
                    path: metadata_path.clone(),
                    source,
                }
            })?;

        Ok(Self {
            lineage,
            paths: ObservedSessionPaths {
                metadata: metadata_path,
                inbox: root.join(REQUESTS_FILENAME),
                cursor: root.join(CURSOR_FILENAME),
                root,
            },
        })
    }

    pub fn lineage(&self) -> &RuntimeSessionLineage {
        &self.lineage
    }

    pub fn paths(&self) -> &ObservedSessionPaths {
        &self.paths
    }

    pub fn append(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<(), SessionCorrelationError> {
        append_json_line(&self.paths.inbox, envelope)
            .map_err(SessionCorrelationError::PersistObservedEnvelope)
    }

    pub fn drain_available(
        &self,
    ) -> Result<Vec<GenericLiveActionEnvelope>, SessionCorrelationError> {
        if !self.paths.inbox.exists() {
            return Ok(Vec::new());
        }

        let cursor = self.read_cursor()?;
        let file = OpenOptions::new()
            .read(true)
            .open(&self.paths.inbox)
            .map_err(|source| SessionCorrelationError::ReadObservedInbox {
                path: self.paths.inbox.clone(),
                source,
            })?;
        let reader = BufReader::new(file);
        let mut drained = Vec::new();
        let mut processed_lines = cursor;

        for (line_idx, line) in reader.lines().enumerate() {
            let line_no = line_idx + 1;
            let line = line.map_err(|source| SessionCorrelationError::ReadObservedInbox {
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
                    SessionCorrelationError::DeserializeObservedEnvelope {
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

    fn persist_metadata(&self) -> Result<(), SessionCorrelationError> {
        if self.paths.metadata.exists() {
            let existing = fs::read_to_string(&self.paths.metadata).map_err(|source| {
                SessionCorrelationError::ReadObservedSessionMetadata {
                    path: self.paths.metadata.clone(),
                    source,
                }
            })?;
            let existing =
                serde_json::from_str::<RuntimeSessionLineage>(&existing).map_err(|source| {
                    SessionCorrelationError::ParseObservedSessionMetadata {
                        path: self.paths.metadata.clone(),
                        source,
                    }
                })?;
            if existing == self.lineage {
                return Ok(());
            }
            return Err(SessionCorrelationError::ObservedSessionMetadataConflict {
                path: self.paths.metadata.clone(),
                expected: Box::new(self.lineage.clone()),
                actual: Box::new(existing),
            });
        }

        let serialized =
            serde_json::to_string(&self.lineage).expect("runtime session lineage should serialize");
        fs::write(&self.paths.metadata, serialized).map_err(|source| {
            SessionCorrelationError::WriteObservedSessionMetadata {
                path: self.paths.metadata.clone(),
                source,
            }
        })
    }

    fn read_cursor(&self) -> Result<usize, SessionCorrelationError> {
        match fs::read_to_string(&self.paths.cursor) {
            Ok(value) => value.trim().parse::<usize>().map_err(|source| {
                SessionCorrelationError::ParseObservedCursor {
                    path: self.paths.cursor.clone(),
                    value,
                    source,
                }
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(SessionCorrelationError::ReadObservedCursor {
                path: self.paths.cursor.clone(),
                source,
            }),
        }
    }

    fn write_cursor(&self, value: usize) -> Result<(), SessionCorrelationError> {
        fs::write(&self.paths.cursor, value.to_string()).map_err(|source| {
            SessionCorrelationError::WriteObservedCursor {
                path: self.paths.cursor.clone(),
                source,
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCorrelationPlan {
    pub sources: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub correlation_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SessionCorrelationBoundary,
}

impl SessionCorrelationPlan {
    pub fn from_proxy_seam_boundary(boundary: ProxySeamBoundary) -> Self {
        let sources = boundary.sources.clone();
        let input_fields = boundary.handoff_fields;
        let correlation_fields = vec![
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
            "session_id",
            "agent_id",
            "workspace_id",
            "provider_hint",
            "correlation_reason",
            "correlation_status",
            "session_correlation_reason",
            "session_correlation_status",
            "source_kind",
        ];

        Self {
            sources: sources.clone(),
            input_fields: input_fields.clone(),
            correlation_fields: correlation_fields.clone(),
            responsibilities: vec![
                "bind live proxy requests to the same runtime session identity used by hostd events and approval records",
                "decide whether request ids, correlation ids, workspace hints, or runtime lineage are strong enough to claim session ownership",
                "preserve provider and surface hints for downstream semantic conversion without deciding the final generic or provider-specific action taxonomy",
                "surface uncorrelated or degraded requests explicitly instead of letting later policy code guess ownership",
            ],
            stages: vec!["lookup", "bind_session", "lineage_hint", "handoff"],
            handoff: SessionCorrelationBoundary {
                sources,
                input_fields,
                correlation_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn correlate_fixture(
        &self,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<CorrelatedLiveRequest, SessionCorrelationError> {
        let lineage = RuntimeSessionLineage::new(
            envelope.session_id.clone(),
            envelope
                .agent_id
                .clone()
                .ok_or(SessionCorrelationError::MissingAgentId)?,
            envelope.workspace_id.clone(),
        );

        Ok(CorrelatedLiveRequest {
            envelope: envelope.clone(),
            session: lineage
                .session_ref(LiveRequestProvenance::FixturePreview.policy_bundle_version()),
            provenance: LiveRequestProvenance::FixturePreview,
            session_correlation_status: LiveRequestProvenance::FixturePreview
                .session_correlation_status(),
            session_correlation_reason: LiveRequestProvenance::FixturePreview
                .session_correlation_reason(),
        })
    }

    pub fn correlate_observed_request(
        &self,
        envelope: &GenericLiveActionEnvelope,
        lineage: &RuntimeSessionLineage,
    ) -> Result<CorrelatedLiveRequest, SessionCorrelationError> {
        let agent_id = envelope
            .agent_id
            .as_deref()
            .ok_or(SessionCorrelationError::MissingAgentId)?;
        if envelope.session_id != lineage.session_id {
            return Err(SessionCorrelationError::SessionLineageMismatch {
                field: "session_id",
                expected: lineage.session_id.clone(),
                actual: envelope.session_id.clone(),
            });
        }
        if agent_id != lineage.agent_id {
            return Err(SessionCorrelationError::SessionLineageMismatch {
                field: "agent_id",
                expected: lineage.agent_id.clone(),
                actual: agent_id.to_owned(),
            });
        }
        if envelope.workspace_id != lineage.workspace_id {
            return Err(SessionCorrelationError::WorkspaceLineageMismatch {
                expected: lineage.workspace_id.clone(),
                actual: envelope.workspace_id.clone(),
            });
        }

        Ok(CorrelatedLiveRequest {
            envelope: envelope.clone(),
            session: lineage
                .session_ref(LiveRequestProvenance::ObservedRuntimePath.policy_bundle_version()),
            provenance: LiveRequestProvenance::ObservedRuntimePath,
            session_correlation_status: LiveRequestProvenance::ObservedRuntimePath
                .session_correlation_status(),
            session_correlation_reason: LiveRequestProvenance::ObservedRuntimePath
                .session_correlation_reason(),
        })
    }

    pub fn observed_runtime(&self) -> Result<ObservedRuntimePath, SessionCorrelationError> {
        ObservedRuntimePath::bootstrap()
    }

    pub fn handoff(&self) -> SessionCorrelationBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "sources={} correlation_fields={} stages={}",
            self.sources.join(","),
            self.correlation_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[derive(Debug, Error)]
pub enum SessionCorrelationError {
    #[error("forward-proxy observed runtime root `{path}` could not be prepared: {source}")]
    PrepareObservedRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("forward-proxy observed session root `{path}` could not be prepared: {source}")]
    PrepareObservedSessionRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read observed-session metadata `{path}`: {source}")]
    ReadObservedSessionMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse observed-session metadata `{path}`: {source}")]
    ParseObservedSessionMetadata {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write observed-session metadata `{path}`: {source}")]
    WriteObservedSessionMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "observed-session metadata `{path}` conflicts with requested lineage: expected {expected:?}, found {actual:?}"
    )]
    ObservedSessionMetadataConflict {
        path: PathBuf,
        expected: Box<RuntimeSessionLineage>,
        actual: Box<RuntimeSessionLineage>,
    },
    #[error("failed to read observed sessions root `{path}`: {source}")]
    ReadObservedSessionsRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to persist observed live envelope: {0}")]
    PersistObservedEnvelope(#[source] PersistenceError),
    #[error("failed to read observed inbox `{path}`: {source}")]
    ReadObservedInbox {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to deserialize observed envelope from `{path}` line {line}: {source}")]
    DeserializeObservedEnvelope {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to read observed cursor `{path}`: {source}")]
    ReadObservedCursor {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse observed cursor `{path}` with value `{value}`: {source}")]
    ParseObservedCursor {
        path: PathBuf,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("failed to write observed cursor `{path}`: {source}")]
    WriteObservedCursor {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("observed live envelope is missing agent_id")]
    MissingAgentId,
    #[error(
        "observed live envelope {field} does not match runtime lineage: expected `{expected}`, found `{actual}`"
    )]
    SessionLineageMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "observed live envelope workspace_id does not match runtime lineage: expected `{expected:?}`, found `{actual:?}`"
    )]
    WorkspaceLineageMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
}

fn session_dir(sessions_root: &Path, lineage: &RuntimeSessionLineage) -> PathBuf {
    sessions_root.join(format!(
        "{}__{}__{}",
        sanitize_id_segment(&lineage.session_id),
        sanitize_id_segment(&lineage.agent_id),
        lineage
            .workspace_id
            .as_deref()
            .map(sanitize_id_segment)
            .unwrap_or_else(|| "workspace_none".to_owned())
    ))
}

fn sanitize_id_segment(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        live::{
            GenericLiveActionEnvelope, LiveAuthHint, LiveBodyClass, LiveCaptureSource,
            LiveCorrelationId, LiveCorrelationStatus, LiveHeaderClass, LiveHeaders,
            LiveInterceptionMode, LivePath, LiveRequestId, LiveSurface, LiveTransport,
        },
        provider::{ProviderId, ProviderMethod},
        rest::RestHost,
    };

    use super::{
        LiveRequestProvenance, ObservedRuntimePath, RuntimeSessionLineage, SessionCorrelationPlan,
    };

    #[test]
    fn observed_runtime_path_discovers_and_drains_session_owned_requests() {
        let root = ObservedRuntimePath::from_root(unique_state_dir())
            .expect("runtime path should bootstrap");
        let first_lineage = RuntimeSessionLineage::new(
            "sess_live_proxy_runtime_1",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let second_lineage = RuntimeSessionLineage::new(
            "sess_live_proxy_runtime_2",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let first = root
            .session_path(first_lineage.clone())
            .expect("first session path should init");
        let second = root
            .session_path(second_lineage.clone())
            .expect("second session path should init");

        first
            .append(&observed_envelope(&first_lineage, "req_one", "corr_one"))
            .expect("first observed request should append");
        second
            .append(&observed_envelope(&second_lineage, "req_two", "corr_two"))
            .expect("second observed request should append");

        let discovered = root
            .discover_session_paths()
            .expect("session paths should discover");
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].lineage().session_id, first_lineage.session_id);
        assert_eq!(
            discovered[1].lineage().session_id,
            second_lineage.session_id
        );

        let drained = discovered[0]
            .drain_available()
            .expect("first observed inbox should drain");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].session_id, first_lineage.session_id);
        assert!(
            discovered[0]
                .drain_available()
                .expect("draining the same inbox again should be empty")
                .is_empty()
        );
    }

    #[test]
    fn session_correlation_marks_observed_runtime_path_as_non_fixture() {
        let plan = SessionCorrelationPlan::from_proxy_seam_boundary(
            crate::poc::live_proxy::proxy_seam::ProxySeamPlan::default().handoff(),
        );
        let lineage = RuntimeSessionLineage::new(
            "sess_live_proxy_observed",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let correlated = plan
            .correlate_observed_request(
                &observed_envelope(&lineage, "req_observed", "corr_observed"),
                &lineage,
            )
            .expect("observed request should correlate to runtime lineage");

        assert_eq!(
            correlated.provenance,
            LiveRequestProvenance::ObservedRuntimePath
        );
        assert_eq!(correlated.source_kind(), "live_proxy_observed");
        assert_eq!(correlated.event_suffix(), "observed");
        assert_eq!(
            correlated.session_correlation_status,
            "runtime_path_confirmed"
        );
        assert_eq!(correlated.session.session_id, lineage.session_id);
        assert_eq!(
            correlated.session.agent_id.as_deref(),
            Some(lineage.agent_id.as_str())
        );
        assert_eq!(
            correlated.session.workspace_id.as_deref(),
            lineage.workspace_id.as_deref()
        );
    }

    fn observed_envelope(
        lineage: &RuntimeSessionLineage,
        request_id: &str,
        correlation_id: &str,
    ) -> GenericLiveActionEnvelope {
        GenericLiveActionEnvelope::new(
            LiveCaptureSource::ForwardProxy,
            LiveRequestId::new(request_id).expect("request id should be valid"),
            LiveCorrelationId::new(correlation_id).expect("correlation id should be valid"),
            lineage.session_id.clone(),
            Some(lineage.agent_id.clone()),
            lineage.workspace_id.clone(),
            Some(ProviderId::gws()),
            LiveCorrelationStatus::Confirmed,
            LiveSurface::http_request(),
            LiveTransport::new("https").expect("transport should be valid"),
            ProviderMethod::Post,
            RestHost::new("gmail.googleapis.com").expect("authority should be valid"),
            LivePath::new("/gmail/v1/users/me/messages/send").expect("path should be valid"),
            LiveHeaders::new([LiveHeaderClass::Authorization, LiveHeaderClass::ContentJson]),
            LiveBodyClass::Json,
            LiveAuthHint::Bearer,
            Some("gmail.users/me".to_owned()),
            LiveInterceptionMode::EnforcePreview,
        )
    }

    fn unique_state_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!(
            "agent-auditor-hostd-live-proxy-observed-runtime-test-{nonce}"
        ))
    }
}
