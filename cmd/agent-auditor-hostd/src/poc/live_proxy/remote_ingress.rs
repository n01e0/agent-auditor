#![allow(clippy::result_large_err)]

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use agenta_core::live::GenericLiveActionEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::session_correlation::{
    ObservedAppendOutcome, ObservedRuntimePath, RuntimeSessionLineage, SessionCorrelationError,
};

const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemoteObservedRuntimeIngressRequest {
    BootstrapSession {
        session: RuntimeSessionLineage,
    },
    AppendEnvelope {
        session: RuntimeSessionLineage,
        envelope: Box<GenericLiveActionEnvelope>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteObservedRuntimeIngressResponse {
    pub accepted: bool,
    pub duplicate: bool,
    pub message: String,
}

impl RemoteObservedRuntimeIngressResponse {
    fn accepted(message: impl Into<String>) -> Self {
        Self {
            accepted: true,
            duplicate: false,
            message: message.into(),
        }
    }

    fn duplicate(message: impl Into<String>) -> Self {
        Self {
            accepted: true,
            duplicate: true,
            message: message.into(),
        }
    }

    fn rejected(message: impl Into<String>) -> Self {
        Self {
            accepted: false,
            duplicate: false,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub struct RemoteObservedRuntimeIngressServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
}

impl RemoteObservedRuntimeIngressServer {
    pub fn start(
        bind_addr: &str,
        observed_runtime: ObservedRuntimePath,
    ) -> Result<Self, RemoteObservedRuntimeIngressError> {
        let listener = TcpListener::bind(bind_addr).map_err(|source| {
            RemoteObservedRuntimeIngressError::Bind {
                addr: bind_addr.to_owned(),
                source,
            }
        })?;
        listener
            .set_nonblocking(true)
            .map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;
        let local_addr = listener
            .local_addr()
            .map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();
        let listener_thread = thread::spawn(move || {
            while !shutdown_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = handle_connection(stream, &observed_runtime) {
                            eprintln!("forward_proxy_remote_ingress_error={error}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(error) => {
                        eprintln!("forward_proxy_remote_ingress_error={error}");
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            listener: Some(listener_thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for RemoteObservedRuntimeIngressServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteObservedRuntimeIngressWriter {
    addr: String,
    timeout: Duration,
}

impl RemoteObservedRuntimeIngressWriter {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            timeout: DEFAULT_IO_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(addr: impl Into<String>, timeout: Duration) -> Self {
        Self {
            addr: addr.into(),
            timeout,
        }
    }

    pub fn bootstrap_session(
        &self,
        session: &RuntimeSessionLineage,
    ) -> Result<RemoteObservedRuntimeIngressResponse, RemoteObservedRuntimeIngressWriteError> {
        self.round_trip(&RemoteObservedRuntimeIngressRequest::BootstrapSession {
            session: session.clone(),
        })
    }

    pub fn append_envelope(
        &self,
        session: &RuntimeSessionLineage,
        envelope: &GenericLiveActionEnvelope,
    ) -> Result<RemoteObservedRuntimeIngressResponse, RemoteObservedRuntimeIngressWriteError> {
        self.round_trip(&RemoteObservedRuntimeIngressRequest::AppendEnvelope {
            session: session.clone(),
            envelope: Box::new(envelope.clone()),
        })
    }

    fn round_trip(
        &self,
        request: &RemoteObservedRuntimeIngressRequest,
    ) -> Result<RemoteObservedRuntimeIngressResponse, RemoteObservedRuntimeIngressWriteError> {
        let mut stream = TcpStream::connect(&self.addr).map_err(|source| {
            RemoteObservedRuntimeIngressWriteError::Connect {
                addr: self.addr.clone(),
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(RemoteObservedRuntimeIngressWriteError::Io)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(RemoteObservedRuntimeIngressWriteError::Io)?;
        let payload = serde_json::to_string(request)
            .map_err(RemoteObservedRuntimeIngressWriteError::SerializeRequest)?;
        writeln!(stream, "{payload}").map_err(RemoteObservedRuntimeIngressWriteError::Io)?;
        stream
            .flush()
            .map_err(RemoteObservedRuntimeIngressWriteError::Io)?;

        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        reader
            .read_line(&mut response)
            .map_err(RemoteObservedRuntimeIngressWriteError::Io)?;
        let response: RemoteObservedRuntimeIngressResponse = serde_json::from_str(response.trim())
            .map_err(RemoteObservedRuntimeIngressWriteError::DeserializeResponse)?;
        if response.accepted {
            Ok(response)
        } else {
            Err(RemoteObservedRuntimeIngressWriteError::Rejected(
                response.message,
            ))
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    observed_runtime: &ObservedRuntimePath,
) -> Result<(), RemoteObservedRuntimeIngressError> {
    stream
        .set_read_timeout(Some(DEFAULT_IO_TIMEOUT))
        .map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;
    stream
        .set_write_timeout(Some(DEFAULT_IO_TIMEOUT))
        .map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;

    let mut request = String::new();
    {
        let mut reader = BufReader::new(&mut stream);
        reader
            .read_line(&mut request)
            .map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;
    }

    let response = match serde_json::from_str::<RemoteObservedRuntimeIngressRequest>(request.trim())
    {
        Ok(request) => match process_request(request, observed_runtime) {
            Ok(response) => response,
            Err(error) => RemoteObservedRuntimeIngressResponse::rejected(error.to_string()),
        },
        Err(error) => RemoteObservedRuntimeIngressResponse::rejected(format!(
            "failed to parse remote ingress request: {error}"
        )),
    };

    let payload = serde_json::to_string(&response)
        .map_err(RemoteObservedRuntimeIngressError::SerializeResponse)?;
    writeln!(stream, "{payload}").map_err(RemoteObservedRuntimeIngressError::ListenerIo)?;
    stream
        .flush()
        .map_err(RemoteObservedRuntimeIngressError::ListenerIo)
}

fn process_request(
    request: RemoteObservedRuntimeIngressRequest,
    observed_runtime: &ObservedRuntimePath,
) -> Result<RemoteObservedRuntimeIngressResponse, RemoteObservedRuntimeIngressProcessError> {
    match request {
        RemoteObservedRuntimeIngressRequest::BootstrapSession { session } => {
            observed_runtime.session_path(session)?;
            Ok(RemoteObservedRuntimeIngressResponse::accepted(
                "session_bootstrapped",
            ))
        }
        RemoteObservedRuntimeIngressRequest::AppendEnvelope { session, envelope } => {
            validate_envelope_lineage(&session, &envelope)?;
            let session_path = observed_runtime.session_path(session)?;
            match session_path.append_deduplicated(&envelope)? {
                ObservedAppendOutcome::Appended => Ok(
                    RemoteObservedRuntimeIngressResponse::accepted("envelope_accepted"),
                ),
                ObservedAppendOutcome::Duplicate => Ok(
                    RemoteObservedRuntimeIngressResponse::duplicate("duplicate_envelope_accepted"),
                ),
            }
        }
    }
}

fn validate_envelope_lineage(
    session: &RuntimeSessionLineage,
    envelope: &GenericLiveActionEnvelope,
) -> Result<(), RemoteObservedRuntimeIngressProcessError> {
    if envelope.session_id != session.session_id {
        return Err(RemoteObservedRuntimeIngressProcessError::LineageMismatch {
            field: "session_id",
            expected: session.session_id.clone(),
            actual: envelope.session_id.clone(),
        });
    }

    let envelope_agent_id = envelope
        .agent_id
        .as_ref()
        .ok_or(RemoteObservedRuntimeIngressProcessError::MissingEnvelopeAgentId)?;
    if envelope_agent_id != &session.agent_id {
        return Err(RemoteObservedRuntimeIngressProcessError::LineageMismatch {
            field: "agent_id",
            expected: session.agent_id.clone(),
            actual: envelope_agent_id.clone(),
        });
    }

    if envelope.workspace_id != session.workspace_id {
        return Err(
            RemoteObservedRuntimeIngressProcessError::WorkspaceMismatch {
                expected: session.workspace_id.clone(),
                actual: envelope.workspace_id.clone(),
            },
        );
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum RemoteObservedRuntimeIngressError {
    #[error("failed to bind remote forward-proxy ingress listener `{addr}`: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("remote forward-proxy ingress listener IO failed: {0}")]
    ListenerIo(#[source] std::io::Error),
    #[error("failed to serialize remote forward-proxy ingress response: {0}")]
    SerializeResponse(#[source] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum RemoteObservedRuntimeIngressProcessError {
    #[error("remote ingress envelope is missing agent_id")]
    MissingEnvelopeAgentId,
    #[error(
        "remote ingress envelope `{field}` does not match declared session lineage: expected `{expected}`, found `{actual}`"
    )]
    LineageMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "remote ingress envelope workspace_id does not match declared session lineage: expected `{expected:?}`, found `{actual:?}`"
    )]
    WorkspaceMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error(transparent)]
    Session(#[from] SessionCorrelationError),
}

#[derive(Debug, Error)]
pub enum RemoteObservedRuntimeIngressWriteError {
    #[error("failed to connect to remote forward-proxy ingress `{addr}`: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize remote forward-proxy ingress request: {0}")]
    SerializeRequest(#[source] serde_json::Error),
    #[error("remote forward-proxy ingress IO failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("failed to deserialize remote forward-proxy ingress response: {0}")]
    DeserializeResponse(#[source] serde_json::Error),
    #[error("remote forward-proxy ingress rejected the request: {0}")]
    Rejected(String),
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        RemoteObservedRuntimeIngressServer, RemoteObservedRuntimeIngressWriteError,
        RemoteObservedRuntimeIngressWriter,
    };
    use crate::poc::live_proxy::{
        forward_proxy::ForwardProxyIngressRuntime,
        session_correlation::{ObservedRuntimePath, RuntimeSessionLineage},
    };

    #[test]
    fn remote_writer_bootstraps_session_and_appends_observed_envelope() {
        let root = unique_state_dir();
        let observed_runtime = ObservedRuntimePath::from_root(root.join("observed"))
            .expect("observed runtime should bootstrap");
        let server =
            RemoteObservedRuntimeIngressServer::start("127.0.0.1:0", observed_runtime.clone())
                .expect("server should start");
        let writer = RemoteObservedRuntimeIngressWriter::with_timeout(
            server.local_addr().to_string(),
            std::time::Duration::from_secs(2),
        );
        let lineage = RuntimeSessionLineage::new(
            "sess_remote_ingress_bootstrap",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let envelope = ForwardProxyIngressRuntime::preview_fixture(lineage.session_id.clone());

        let bootstrap = writer
            .bootstrap_session(&lineage)
            .expect("bootstrap should succeed");
        assert!(bootstrap.accepted);
        assert!(!bootstrap.duplicate);

        let append = writer
            .append_envelope(&lineage, &envelope)
            .expect("append should succeed");
        assert!(append.accepted);
        assert!(!append.duplicate);

        let session = observed_runtime
            .session_path(lineage)
            .expect("session should load");
        let drained = session.drain_available().expect("drain should succeed");
        assert_eq!(drained, vec![envelope]);
        assert!(session.paths().metadata.exists());
    }

    #[test]
    fn remote_writer_deduplicates_same_request_id_without_reappending() {
        let root = unique_state_dir();
        let observed_runtime = ObservedRuntimePath::from_root(root.join("observed"))
            .expect("observed runtime should bootstrap");
        let server =
            RemoteObservedRuntimeIngressServer::start("127.0.0.1:0", observed_runtime.clone())
                .expect("server should start");
        let writer = RemoteObservedRuntimeIngressWriter::new(server.local_addr().to_string());
        let lineage = RuntimeSessionLineage::new(
            "sess_remote_ingress_dedupe",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let envelope = ForwardProxyIngressRuntime::preview_fixture(lineage.session_id.clone());

        writer
            .append_envelope(&lineage, &envelope)
            .expect("first append should succeed");
        let duplicate = writer
            .append_envelope(&lineage, &envelope)
            .expect("duplicate append should still be accepted");
        assert!(duplicate.accepted);
        assert!(duplicate.duplicate);

        let session = observed_runtime
            .session_path(lineage)
            .expect("session should load");
        let persisted = fs::read_to_string(&session.paths().inbox).expect("inbox should read");
        assert_eq!(
            persisted
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
            1
        );
    }

    #[test]
    fn remote_writer_rejects_envelope_lineage_mismatch() {
        let root = unique_state_dir();
        let observed_runtime = ObservedRuntimePath::from_root(root.join("observed"))
            .expect("observed runtime should bootstrap");
        let server = RemoteObservedRuntimeIngressServer::start("127.0.0.1:0", observed_runtime)
            .expect("server should start");
        let writer = RemoteObservedRuntimeIngressWriter::new(server.local_addr().to_string());
        let lineage = RuntimeSessionLineage::new(
            "sess_remote_ingress_lineage",
            "openclaw-main",
            Some("agent-auditor".to_owned()),
        );
        let envelope = ForwardProxyIngressRuntime::preview_fixture("sess_other_lineage");

        let error = writer
            .append_envelope(&lineage, &envelope)
            .expect_err("mismatched lineage should be rejected");
        match error {
            RemoteObservedRuntimeIngressWriteError::Rejected(message) => {
                assert!(message.contains("session_id"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    fn unique_state_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-remote-ingress-test-{nonce}"))
    }
}
