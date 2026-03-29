use std::{error::Error, fmt};

use agent_auditor_hostd_ebpf as poc_ebpf;
use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{EventTransport, LoaderBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPathPlan {
    pub transport: EventTransport,
    pub raw_event_types: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: String,
    pub filename: String,
    pub exe: String,
    pub argv: Vec<String>,
    pub cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEvent {
    pub pid: u32,
    pub ppid: u32,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredExecEvent {
    pub raw_len: usize,
    pub event: ExecEvent,
    pub log_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredExitEvent {
    pub raw_len: usize,
    pub event: ExitEvent,
    pub log_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLifecycleKey {
    pub pid: u32,
    pub ppid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLifecycleRecord {
    pub key: ProcessLifecycleKey,
    pub exec: ExecEvent,
    pub exit: ExitEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventDecodeError {
    WrongLength {
        event_kind: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for EventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength {
                event_kind,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid {event_kind} event length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl Error for EventDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventCorrelationError {
    MismatchedLifecycleKey {
        exec_pid: u32,
        exec_ppid: u32,
        exit_pid: u32,
        exit_ppid: u32,
    },
}

impl fmt::Display for EventCorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MismatchedLifecycleKey {
                exec_pid,
                exec_ppid,
                exit_pid,
                exit_ppid,
            } => write!(
                f,
                "mismatched lifecycle key: exec pid={exec_pid} ppid={exec_ppid}, exit pid={exit_pid} ppid={exit_ppid}"
            ),
        }
    }
}

impl Error for EventCorrelationError {}

impl EventPathPlan {
    pub fn from_loader_boundary(boundary: LoaderBoundary) -> Self {
        Self {
            transport: boundary.transport,
            raw_event_types: boundary.raw_event_types,
            stages: vec!["receive", "decode", "correlate", "normalize", "publish"],
            responsibilities: vec![
                "read raw exec / exit records from the loader handoff",
                "decode kernel-facing structs into typed hostd records",
                "correlate process lifecycle state across exec / exit",
                "normalize records toward agenta-core envelopes",
                "fan out to logging and control-plane sinks",
            ],
        }
    }

    pub fn deliver_exec_to_log(
        &self,
        bytes: &[u8],
    ) -> Result<DeliveredExecEvent, EventDecodeError> {
        let event = ExecEvent::from_bytes(bytes)?;
        let log_line = event.log_line(self.transport);

        Ok(DeliveredExecEvent {
            raw_len: bytes.len(),
            event,
            log_line,
        })
    }

    pub fn preview_exec_delivery(&self) -> Result<DeliveredExecEvent, EventDecodeError> {
        let fixture = poc_ebpf::fixture_exec_event_bytes();
        self.deliver_exec_to_log(&fixture)
    }

    pub fn deliver_exit_to_log(
        &self,
        bytes: &[u8],
    ) -> Result<DeliveredExitEvent, EventDecodeError> {
        let event = ExitEvent::from_bytes(bytes)?;
        let log_line = event.log_line(self.transport);

        Ok(DeliveredExitEvent {
            raw_len: bytes.len(),
            event,
            log_line,
        })
    }

    pub fn preview_exit_delivery(&self) -> Result<DeliveredExitEvent, EventDecodeError> {
        let fixture = poc_ebpf::fixture_exit_event_bytes();
        self.deliver_exit_to_log(&fixture)
    }

    pub fn correlate_exec_and_exit(
        &self,
        exec: &ExecEvent,
        exit: &ExitEvent,
    ) -> Option<ProcessLifecycleRecord> {
        let exec_key = ProcessLifecycleKey {
            pid: exec.pid,
            ppid: exec.ppid,
        };
        let exit_key = ProcessLifecycleKey {
            pid: exit.pid,
            ppid: exit.ppid,
        };

        (exec_key == exit_key).then(|| ProcessLifecycleRecord {
            key: exec_key,
            exec: exec.clone(),
            exit: exit.clone(),
        })
    }

    pub fn preview_exec_exit_lifecycle(
        &self,
    ) -> Result<ProcessLifecycleRecord, EventCorrelationError> {
        let exec = ExecEvent::from_bytes(&poc_ebpf::fixture_exec_event_bytes())
            .expect("exec fixture should decode");
        let exit = ExitEvent::from_bytes(&poc_ebpf::fixture_exit_event_bytes())
            .expect("exit fixture should decode");

        self.correlate_exec_and_exit(&exec, &exit).ok_or(
            EventCorrelationError::MismatchedLifecycleKey {
                exec_pid: exec.pid,
                exec_ppid: exec.ppid,
                exit_pid: exit.pid,
                exit_ppid: exit.ppid,
            },
        )
    }

    pub fn normalize_exec_event(
        &self,
        event: &ExecEvent,
        session: &SessionRecord,
    ) -> EventEnvelope {
        self.normalize_exec_event_with_source(
            event,
            session,
            CollectorKind::Ebpf,
            Some("hostd-poc"),
        )
    }

    pub fn normalize_exec_event_with_source(
        &self,
        event: &ExecEvent,
        session: &SessionRecord,
        collector: CollectorKind,
        host_id: Option<&str>,
    ) -> EventEnvelope {
        let mut attributes = process_attributes(event.pid, event.ppid);
        insert_exec_attribution(&mut attributes, event);

        EventEnvelope::new(
            format!("poc_process_exec_{}_{}", event.pid, event.ppid),
            EventType::ProcessExec,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Process,
                verb: Some("exec".to_owned()),
                target: Some(event.filename.clone()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd exec/exit PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(event.pid, event.ppid, collector, host_id),
        )
    }

    pub fn normalize_exit_event(
        &self,
        event: &ExitEvent,
        lifecycle: Option<&ProcessLifecycleRecord>,
        session: &SessionRecord,
    ) -> EventEnvelope {
        self.normalize_exit_event_with_source(
            event,
            lifecycle,
            session,
            CollectorKind::Ebpf,
            Some("hostd-poc"),
        )
    }

    pub fn normalize_exit_event_with_source(
        &self,
        event: &ExitEvent,
        lifecycle: Option<&ProcessLifecycleRecord>,
        session: &SessionRecord,
        collector: CollectorKind,
        host_id: Option<&str>,
    ) -> EventEnvelope {
        let mut attributes = process_attributes(event.pid, event.ppid);
        attributes.insert("exit_code".to_owned(), json!(event.exit_code));
        if let Some(lifecycle) = lifecycle {
            insert_exec_attribution(&mut attributes, &lifecycle.exec);
            attributes.insert(
                "correlation_key_kind".to_owned(),
                json!("ProcessLifecycleKey { pid, ppid }"),
            );
        }

        EventEnvelope::new(
            format!("poc_process_exit_{}_{}", event.pid, event.ppid),
            EventType::ProcessExit,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Process,
                verb: Some("exit".to_owned()),
                target: lifecycle.map(|record| record.exec.filename.clone()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd exec/exit PoC".to_owned()),
                exit_code: Some(event.exit_code),
                error: None,
            },
            source_info(event.pid, event.ppid, collector, host_id),
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "transport={} raw_events={} stages={}",
            self.transport,
            self.raw_event_types.join(","),
            self.stages.join("->")
        )
    }
}

impl ExecEvent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventDecodeError> {
        if bytes.len() != poc_ebpf::EXEC_EVENT_LEN {
            return Err(EventDecodeError::WrongLength {
                event_kind: "exec",
                expected: poc_ebpf::EXEC_EVENT_LEN,
                actual: bytes.len(),
            });
        }

        let pid = read_u32(bytes, 0);
        let ppid = read_u32(bytes, 4);
        let uid = read_u32(bytes, 8);
        let gid = read_u32(bytes, 12);
        let command_start = 16;
        let filename_start = command_start + poc_ebpf::EXEC_COMM_LEN;
        let command = decode_c_string(&bytes[command_start..filename_start]);
        let filename =
            decode_c_string(&bytes[filename_start..filename_start + poc_ebpf::EXEC_FILENAME_LEN]);

        Ok(Self {
            pid,
            ppid,
            uid,
            gid,
            command: command.clone(),
            filename: filename.clone(),
            exe: filename,
            argv: vec![command],
            cwd: "/workspace/fixture".to_owned(),
        })
    }

    pub fn log_line(&self, transport: EventTransport) -> String {
        format!(
            "event=process.exec transport={} pid={} ppid={} uid={} gid={} command={} target={}",
            transport, self.pid, self.ppid, self.uid, self.gid, self.command, self.filename
        )
    }
}

impl ExitEvent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventDecodeError> {
        if bytes.len() != poc_ebpf::EXIT_EVENT_LEN {
            return Err(EventDecodeError::WrongLength {
                event_kind: "exit",
                expected: poc_ebpf::EXIT_EVENT_LEN,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            pid: read_u32(bytes, 0),
            ppid: read_u32(bytes, 4),
            exit_code: read_i32(bytes, 8),
        })
    }

    pub fn log_line(&self, transport: EventTransport) -> String {
        format!(
            "event=process.exit transport={} pid={} ppid={} exit_code={}",
            transport, self.pid, self.ppid, self.exit_code
        )
    }
}

impl ProcessLifecycleRecord {
    pub fn summary_line(&self, transport: EventTransport) -> String {
        format!(
            "event=process.lifecycle transport={} correlation=pid_ppid pid={} ppid={} command={} target={} exit_code={}",
            transport,
            self.key.pid,
            self.key.ppid,
            self.exec.command,
            self.exec.filename,
            self.exit.exit_code
        )
    }
}

fn session_ref_from_record(session: &SessionRecord) -> SessionRef {
    SessionRef {
        session_id: session.session_id.clone(),
        agent_id: Some(session.agent_id.clone()),
        initiator_id: session.initiator_id.clone(),
        workspace_id: session
            .workspace
            .as_ref()
            .and_then(|workspace| workspace.workspace_id.clone()),
        policy_bundle_version: session.policy_bundle_version.clone(),
        environment: None,
    }
}

fn hostd_actor() -> Actor {
    Actor {
        kind: ActorKind::System,
        id: Some("agent-auditor-hostd".to_owned()),
        display_name: Some("agent-auditor-hostd PoC".to_owned()),
    }
}

fn source_info(pid: u32, ppid: u32, collector: CollectorKind, host_id: Option<&str>) -> SourceInfo {
    SourceInfo {
        collector,
        host_id: host_id.map(str::to_owned),
        container_id: None,
        pod_uid: None,
        pid: Some(pid as i32),
        ppid: Some(ppid as i32),
    }
}

fn process_attributes(pid: u32, ppid: u32) -> JsonMap {
    let mut attributes = JsonMap::new();
    attributes.insert("pid".to_owned(), json!(pid));
    attributes.insert("ppid".to_owned(), json!(ppid));
    attributes.insert("lifecycle_key".to_owned(), json!(format!("{pid}:{ppid}")));
    attributes
}

fn insert_exec_attribution(attributes: &mut JsonMap, event: &ExecEvent) {
    attributes.insert("uid".to_owned(), json!(event.uid));
    attributes.insert("gid".to_owned(), json!(event.gid));
    attributes.insert("command".to_owned(), json!(event.command));
    attributes.insert("filename".to_owned(), json!(event.filename));
    attributes.insert("exe".to_owned(), json!(event.exe));
    attributes.insert("argv".to_owned(), json!(event.argv));
    attributes.insert("cwd".to_owned(), json!(event.cwd));
}

fn read_u32(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(
        bytes[start..start + 4]
            .try_into()
            .expect("slice length should match"),
    )
}

fn read_i32(bytes: &[u8], start: usize) -> i32 {
    i32::from_le_bytes(
        bytes[start..start + 4]
            .try_into()
            .expect("slice length should match"),
    )
}

fn decode_c_string(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use agent_auditor_hostd_ebpf as poc_ebpf;
    use agenta_core::{
        ActionClass, ActorKind, CollectorKind, EventType, ResultStatus, SessionRecord,
    };
    use serde_json::json;

    use super::{
        EventCorrelationError, EventDecodeError, EventPathPlan, ExecEvent, ExitEvent,
        ProcessLifecycleKey,
    };
    use crate::poc::contract::{EventTransport, LoaderBoundary};

    #[test]
    fn exec_fixture_decodes_into_process_metadata() {
        let event = ExecEvent::from_bytes(&poc_ebpf::fixture_exec_event_bytes())
            .expect("fixture exec event should decode");

        assert_eq!(event.pid, 4242);
        assert_eq!(event.ppid, 1337);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.gid, 1000);
        assert_eq!(event.command, "cargo");
        assert_eq!(event.filename, "/usr/bin/cargo");
        assert_eq!(event.exe, "/usr/bin/cargo");
        assert_eq!(event.argv, vec!["cargo"]);
        assert_eq!(event.cwd, "/workspace/fixture");
    }

    #[test]
    fn exit_fixture_decodes_into_process_metadata() {
        let event = ExitEvent::from_bytes(&poc_ebpf::fixture_exit_event_bytes())
            .expect("fixture exit event should decode");

        assert_eq!(event.pid, 4242);
        assert_eq!(event.ppid, 1337);
        assert_eq!(event.exit_code, 0);
    }

    #[test]
    fn preview_exec_delivery_emits_a_process_exec_log_line() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let delivered = plan
            .preview_exec_delivery()
            .expect("fixture exec delivery should succeed");

        assert_eq!(delivered.raw_len, poc_ebpf::EXEC_EVENT_LEN);
        assert_eq!(delivered.event.command, "cargo");
        assert_eq!(delivered.event.filename, "/usr/bin/cargo");
        assert_eq!(delivered.event.exe, "/usr/bin/cargo");
        assert_eq!(delivered.event.argv, vec!["cargo"]);
        assert_eq!(delivered.event.cwd, "/workspace/fixture");
        assert_eq!(delivered.event.pid, 4242);
        assert!(delivered.log_line.contains("event=process.exec"));
        assert!(delivered.log_line.contains("transport=ring_buffer"));
        assert!(delivered.log_line.contains("command=cargo"));
        assert!(delivered.log_line.contains("target=/usr/bin/cargo"));
    }

    #[test]
    fn preview_exit_delivery_emits_a_process_exit_log_line() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let delivered = plan
            .preview_exit_delivery()
            .expect("fixture exit delivery should succeed");

        assert_eq!(delivered.raw_len, poc_ebpf::EXIT_EVENT_LEN);
        assert_eq!(delivered.event.pid, 4242);
        assert_eq!(delivered.event.ppid, 1337);
        assert_eq!(delivered.event.exit_code, 0);
        assert!(delivered.log_line.contains("event=process.exit"));
        assert!(delivered.log_line.contains("transport=ring_buffer"));
        assert!(delivered.log_line.contains("exit_code=0"));
    }

    #[test]
    fn invalid_exec_payload_length_is_rejected() {
        let error = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer())
            .deliver_exec_to_log(&[0; 8])
            .expect_err("short payload should fail");

        assert_eq!(
            error,
            EventDecodeError::WrongLength {
                event_kind: "exec",
                expected: poc_ebpf::EXEC_EVENT_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn invalid_exit_payload_length_is_rejected() {
        let error = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer())
            .deliver_exit_to_log(&[0; 8])
            .expect_err("short payload should fail");

        assert_eq!(
            error,
            EventDecodeError::WrongLength {
                event_kind: "exit",
                expected: poc_ebpf::EXIT_EVENT_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn exec_and_exit_can_be_correlated_by_pid_and_ppid() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let record = plan
            .preview_exec_exit_lifecycle()
            .expect("fixtures should correlate");
        let log_line = record.summary_line(EventTransport::RingBuffer);

        assert_eq!(
            record.key,
            ProcessLifecycleKey {
                pid: 4242,
                ppid: 1337,
            }
        );
        assert_eq!(record.exec.command, "cargo");
        assert_eq!(record.exit.exit_code, 0);
        assert!(log_line.contains("event=process.lifecycle"));
        assert!(log_line.contains("correlation=pid_ppid"));
        assert!(log_line.contains("target=/usr/bin/cargo"));
        assert!(log_line.contains("exit_code=0"));
    }

    #[test]
    fn mismatched_exec_and_exit_do_not_correlate() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let exec = ExecEvent::from_bytes(&poc_ebpf::fixture_exec_event_bytes())
            .expect("fixture exec event should decode");
        let exit = ExitEvent {
            pid: exec.pid + 1,
            ppid: exec.ppid,
            exit_code: 17,
        };

        assert_eq!(plan.correlate_exec_and_exit(&exec, &exit), None);

        let error = EventCorrelationError::MismatchedLifecycleKey {
            exec_pid: exec.pid,
            exec_ppid: exec.ppid,
            exit_pid: exit.pid,
            exit_ppid: exit.ppid,
        };
        assert_eq!(
            error,
            EventCorrelationError::MismatchedLifecycleKey {
                exec_pid: 4242,
                exec_ppid: 1337,
                exit_pid: 4243,
                exit_ppid: 1337,
            }
        );
    }

    #[test]
    fn normalize_exec_event_uses_agenta_core_process_exec_shape() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let delivered = plan
            .preview_exec_delivery()
            .expect("fixture exec delivery should succeed");
        let session = SessionRecord::placeholder("openclaw-main", "sess_norm_exec");
        let envelope = plan.normalize_exec_event(&delivered.event, &session);

        assert_eq!(envelope.event_type, EventType::ProcessExec);
        assert_eq!(envelope.session.session_id, "sess_norm_exec");
        assert_eq!(envelope.session.agent_id.as_deref(), Some("openclaw-main"));
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Process);
        assert_eq!(envelope.action.verb.as_deref(), Some("exec"));
        assert_eq!(envelope.action.target.as_deref(), Some("/usr/bin/cargo"));
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(envelope.result.exit_code, None);
        assert_eq!(envelope.source.collector, CollectorKind::Ebpf);
        assert_eq!(envelope.source.pid, Some(4242));
        assert_eq!(envelope.source.ppid, Some(1337));
        assert_eq!(
            envelope.action.attributes.get("command"),
            Some(&json!("cargo"))
        );
        assert_eq!(
            envelope.action.attributes.get("exe"),
            Some(&json!("/usr/bin/cargo"))
        );
        assert_eq!(
            envelope.action.attributes.get("argv"),
            Some(&json!(["cargo"]))
        );
        assert_eq!(
            envelope.action.attributes.get("cwd"),
            Some(&json!("/workspace/fixture"))
        );
        assert_eq!(
            envelope.action.attributes.get("lifecycle_key"),
            Some(&json!("4242:1337"))
        );
    }

    #[test]
    fn normalize_exit_event_uses_agenta_core_process_exit_shape() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let session = SessionRecord::placeholder("openclaw-main", "sess_norm_exit");
        let lifecycle = plan
            .preview_exec_exit_lifecycle()
            .expect("fixtures should correlate");
        let envelope = plan.normalize_exit_event(&lifecycle.exit, Some(&lifecycle), &session);

        assert_eq!(envelope.event_type, EventType::ProcessExit);
        assert_eq!(envelope.session.session_id, "sess_norm_exit");
        assert_eq!(envelope.action.class, ActionClass::Process);
        assert_eq!(envelope.action.verb.as_deref(), Some("exit"));
        assert_eq!(envelope.action.target.as_deref(), Some("/usr/bin/cargo"));
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(envelope.result.exit_code, Some(0));
        assert_eq!(envelope.source.collector, CollectorKind::Ebpf);
        assert_eq!(
            envelope.action.attributes.get("command"),
            Some(&json!("cargo"))
        );
        assert_eq!(envelope.action.attributes.get("uid"), Some(&json!(1000)));
        assert_eq!(envelope.action.attributes.get("gid"), Some(&json!(1000)));
        assert_eq!(
            envelope.action.attributes.get("exe"),
            Some(&json!("/usr/bin/cargo"))
        );
        assert_eq!(
            envelope.action.attributes.get("argv"),
            Some(&json!(["cargo"]))
        );
        assert_eq!(
            envelope.action.attributes.get("cwd"),
            Some(&json!("/workspace/fixture"))
        );
        assert_eq!(
            envelope.action.attributes.get("correlation_key_kind"),
            Some(&json!("ProcessLifecycleKey { pid, ppid }"))
        );
        assert_eq!(
            envelope.action.attributes.get("lifecycle_key"),
            Some(&json!("4242:1337"))
        );
    }

    #[test]
    fn normalize_exit_event_without_lifecycle_still_emits_a_minimal_process_exit_record() {
        let plan = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer());
        let session = SessionRecord::placeholder("openclaw-main", "sess_norm_exit_minimal");
        let exit = ExitEvent::from_bytes(&poc_ebpf::fixture_exit_event_bytes())
            .expect("fixture exit event should decode");
        let envelope = plan.normalize_exit_event(&exit, None, &session);

        assert_eq!(envelope.event_type, EventType::ProcessExit);
        assert_eq!(envelope.action.target, None);
        assert_eq!(envelope.result.exit_code, Some(0));
        assert_eq!(
            envelope.action.attributes.get("lifecycle_key"),
            Some(&json!("4242:1337"))
        );
        assert_eq!(envelope.action.attributes.get("command"), None);
        assert_eq!(envelope.action.attributes.get("correlation_key_kind"), None);
    }
}
