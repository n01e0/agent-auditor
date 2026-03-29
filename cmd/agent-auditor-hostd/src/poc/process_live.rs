use std::{
    collections::{HashMap, VecDeque},
    fs, io,
    mem::{MaybeUninit, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

use agenta_core::{CollectorKind, EventEnvelope, SessionRecord};
use thiserror::Error;

use crate::poc::{
    contract::LoaderBoundary,
    event_path::{EventPathPlan, ExecEvent, ExitEvent},
    filesystem::persist::FilesystemPocStore,
    persistence::PersistenceError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveProcessEvent {
    Exec(ExecEvent),
    Exit(ExitEvent),
}

pub trait ProcessEventSource {
    fn try_next(&mut self) -> Result<Option<LiveProcessEvent>, ProcessEventSourceError>;
}

#[derive(Debug)]
pub struct ProcConnectorSource {
    socket: OwnedFd,
    buffer: Vec<u8>,
}

impl ProcConnectorSource {
    pub const SOURCE_LABEL: &'static str = "proc_connector";

    pub fn listen() -> Result<Self, ProcessEventSourceError> {
        let fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_CONNECTOR) };
        if fd < 0 {
            return Err(ProcessEventSourceError::OpenSocket(
                io::Error::last_os_error(),
            ));
        }

        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = unsafe { libc::getpid() as u32 };
        addr.nl_groups = libc::CN_IDX_PROC;
        let bind_result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            return Err(ProcessEventSourceError::BindSocket(
                io::Error::last_os_error(),
            ));
        }

        let source = Self {
            socket,
            buffer: vec![0_u8; 4096],
        };
        source.send_membership(libc::PROC_CN_MCAST_LISTEN)?;
        Ok(source)
    }

    fn send_membership(
        &self,
        operation: libc::proc_cn_mcast_op,
    ) -> Result<(), ProcessEventSourceError> {
        let message = proc_connector_membership_message(operation);
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = libc::CN_IDX_PROC;
        let sent = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(ProcessEventSourceError::Membership {
                operation: membership_label(operation),
                source: io::Error::last_os_error(),
            });
        }

        Ok(())
    }
}

impl Drop for ProcConnectorSource {
    fn drop(&mut self) {
        let _ = self.send_membership(libc::PROC_CN_MCAST_IGNORE);
    }
}

impl ProcessEventSource for ProcConnectorSource {
    fn try_next(&mut self) -> Result<Option<LiveProcessEvent>, ProcessEventSourceError> {
        loop {
            let received = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };

            if received < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    _ => Err(ProcessEventSourceError::Receive(error)),
                };
            }

            if received == 0 {
                return Ok(None);
            }

            let bytes = &self.buffer[..received as usize];
            match parse_proc_connector_message(bytes)? {
                Some(event) => return Ok(Some(event)),
                None => continue,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixtureProcessEventSource {
    events: VecDeque<LiveProcessEvent>,
}

impl FixtureProcessEventSource {
    pub fn new(events: impl IntoIterator<Item = LiveProcessEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

impl ProcessEventSource for FixtureProcessEventSource {
    fn try_next(&mut self) -> Result<Option<LiveProcessEvent>, ProcessEventSourceError> {
        Ok(self.events.pop_front())
    }
}

#[derive(Debug, Clone)]
pub struct LiveProcessRecorder {
    event_path: EventPathPlan,
    session: SessionRecord,
    store: FilesystemPocStore,
    collector: CollectorKind,
    host_id: String,
    lifecycle: HashMap<u32, ExecEvent>,
}

impl LiveProcessRecorder {
    pub fn new(
        session: SessionRecord,
        store: FilesystemPocStore,
        collector: CollectorKind,
        host_id: impl Into<String>,
    ) -> Self {
        Self {
            event_path: EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer()),
            session,
            store,
            collector,
            host_id: host_id.into(),
            lifecycle: HashMap::new(),
        }
    }

    pub fn record(&mut self, event: LiveProcessEvent) -> Result<EventEnvelope, ProcessRecordError> {
        match event {
            LiveProcessEvent::Exec(exec) => {
                self.lifecycle.insert(exec.pid, exec.clone());
                let envelope = self.event_path.normalize_exec_event_with_source(
                    &exec,
                    &self.session,
                    self.collector,
                    Some(self.host_id.as_str()),
                );
                self.store.append_audit_record(&envelope)?;
                Ok(envelope)
            }
            LiveProcessEvent::Exit(exit) => {
                let lifecycle = self
                    .lifecycle
                    .remove(&exit.pid)
                    .filter(|exec| exec.ppid == exit.ppid)
                    .map(|exec| crate::poc::event_path::ProcessLifecycleRecord {
                        key: crate::poc::event_path::ProcessLifecycleKey {
                            pid: exec.pid,
                            ppid: exec.ppid,
                        },
                        exec,
                        exit: exit.clone(),
                    });
                let envelope = self.event_path.normalize_exit_event_with_source(
                    &exit,
                    lifecycle.as_ref(),
                    &self.session,
                    self.collector,
                    Some(self.host_id.as_str()),
                );
                self.store.append_audit_record(&envelope)?;
                Ok(envelope)
            }
        }
    }

    pub fn drain_available<S: ProcessEventSource>(
        &mut self,
        source: &mut S,
    ) -> Result<Vec<EventEnvelope>, ProcessDrainError> {
        let mut envelopes = Vec::new();
        while let Some(event) = source.try_next()? {
            envelopes.push(self.record(event)?);
        }
        Ok(envelopes)
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn store(&self) -> &FilesystemPocStore {
        &self.store
    }
}

pub fn current_host_id() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[derive(Debug, Error)]
pub enum ProcessEventSourceError {
    #[error("failed to open proc connector socket: {0}")]
    OpenSocket(io::Error),
    #[error("failed to bind proc connector socket: {0}")]
    BindSocket(io::Error),
    #[error("failed to switch proc connector membership to `{operation}`: {source}")]
    Membership {
        operation: &'static str,
        source: io::Error,
    },
    #[error("failed to receive proc connector event: {0}")]
    Receive(io::Error),
    #[error("truncated proc connector message: expected at least {expected} bytes, got {actual}")]
    TruncatedMessage { expected: usize, actual: usize },
}

#[derive(Debug, Error)]
pub enum ProcessRecordError {
    #[error("failed to persist live process event: {0}")]
    Persist(#[from] PersistenceError),
}

#[derive(Debug, Error)]
pub enum ProcessDrainError {
    #[error(transparent)]
    Source(#[from] ProcessEventSourceError),
    #[error(transparent)]
    Record(#[from] ProcessRecordError),
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CbId {
    idx: u32,
    val: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CnMsg {
    id: CbId,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ProcInput {
    mcast_op: u32,
    event_type: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ProcEventHeader {
    what: u32,
    cpu: u32,
    timestamp_ns: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ExecProcEvent {
    process_pid: i32,
    process_tgid: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ExitProcEvent {
    process_pid: i32,
    process_tgid: i32,
    exit_code: u32,
    exit_signal: u32,
    parent_pid: i32,
    parent_tgid: i32,
}

fn parse_proc_connector_message(
    bytes: &[u8],
) -> Result<Option<LiveProcessEvent>, ProcessEventSourceError> {
    let required = size_of::<libc::nlmsghdr>() + size_of::<CnMsg>() + size_of::<ProcEventHeader>();
    if bytes.len() < required {
        return Err(ProcessEventSourceError::TruncatedMessage {
            expected: required,
            actual: bytes.len(),
        });
    }

    let message_header = read_copy::<libc::nlmsghdr>(bytes, 0)?;
    let declared_len = message_header.nlmsg_len as usize;
    if bytes.len() < declared_len {
        return Err(ProcessEventSourceError::TruncatedMessage {
            expected: declared_len,
            actual: bytes.len(),
        });
    }

    let connector_offset = size_of::<libc::nlmsghdr>();
    let connector = read_copy::<CnMsg>(bytes, connector_offset)?;
    if connector.id.idx != libc::CN_IDX_PROC || connector.id.val != libc::CN_VAL_PROC {
        return Ok(None);
    }

    let payload_offset = connector_offset + size_of::<CnMsg>();
    let header = read_copy::<ProcEventHeader>(bytes, payload_offset)?;
    let event_offset = payload_offset + size_of::<ProcEventHeader>();

    match header.what {
        value if value == libc::PROC_EVENT_EXEC => {
            let exec = read_copy::<ExecProcEvent>(bytes, event_offset)?;
            let pid = exec.process_tgid as u32;
            Ok(Some(LiveProcessEvent::Exec(read_exec_event(pid))))
        }
        value if value == libc::PROC_EVENT_EXIT => {
            let exit = read_copy::<ExitProcEvent>(bytes, event_offset)?;
            Ok(Some(LiveProcessEvent::Exit(ExitEvent {
                pid: exit.process_tgid as u32,
                ppid: exit.parent_tgid as u32,
                exit_code: exit.exit_code as i32,
            })))
        }
        _ => Ok(None),
    }
}

fn proc_connector_membership_message(operation: libc::proc_cn_mcast_op) -> Vec<u8> {
    let total_len = size_of::<libc::nlmsghdr>() + size_of::<CnMsg>() + size_of::<ProcInput>();
    let mut bytes = vec![0_u8; total_len];

    write_copy(
        &mut bytes,
        0,
        libc::nlmsghdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: libc::NLMSG_DONE as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: unsafe { libc::getpid() as u32 },
        },
    );
    write_copy(
        &mut bytes,
        size_of::<libc::nlmsghdr>(),
        CnMsg {
            id: CbId {
                idx: libc::CN_IDX_PROC,
                val: libc::CN_VAL_PROC,
            },
            seq: 0,
            ack: 0,
            len: size_of::<ProcInput>() as u16,
            flags: 0,
        },
    );
    write_copy(
        &mut bytes,
        size_of::<libc::nlmsghdr>() + size_of::<CnMsg>(),
        ProcInput {
            mcast_op: operation,
            event_type: 0,
        },
    );

    bytes
}

fn membership_label(operation: libc::proc_cn_mcast_op) -> &'static str {
    match operation {
        libc::PROC_CN_MCAST_LISTEN => "listen",
        libc::PROC_CN_MCAST_IGNORE => "ignore",
        _ => "unknown",
    }
}

fn read_exec_event(pid: u32) -> ExecEvent {
    let status_path = proc_path(pid, "status");
    let status = fs::read_to_string(&status_path).ok();
    let command = fs::read_to_string(proc_path(pid, "comm"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let filename = fs::read_link(proc_path(pid, "exe"))
        .ok()
        .map(|path| path.display().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| command.clone());

    ExecEvent {
        pid,
        ppid: status
            .as_deref()
            .and_then(|status| parse_status_value::<u32>(status, "PPid:"))
            .unwrap_or(0),
        uid: status
            .as_deref()
            .and_then(|status| parse_first_status_list_value(status, "Uid:"))
            .unwrap_or(0),
        gid: status
            .as_deref()
            .and_then(|status| parse_first_status_list_value(status, "Gid:"))
            .unwrap_or(0),
        command,
        filename,
    }
}

fn proc_path(pid: u32, suffix: &str) -> impl AsRef<Path> {
    format!("/proc/{pid}/{suffix}")
}

fn parse_status_value<T>(status: &str, key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

fn parse_first_status_list_value(status: &str, key: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

fn read_copy<T: Copy>(bytes: &[u8], offset: usize) -> Result<T, ProcessEventSourceError> {
    let end = offset + size_of::<T>();
    let Some(slice) = bytes.get(offset..end) else {
        return Err(ProcessEventSourceError::TruncatedMessage {
            expected: end,
            actual: bytes.len(),
        });
    };

    let mut value = MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(slice.as_ptr(), value.as_mut_ptr().cast(), slice.len());
        Ok(value.assume_init())
    }
}

fn write_copy<T: Copy>(bytes: &mut [u8], offset: usize, value: T) {
    let end = offset + size_of::<T>();
    let slice = &mut bytes[offset..end];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&value as *const T).cast::<u8>(),
            slice.as_mut_ptr(),
            slice.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{CollectorKind, EventType, ResultStatus};

    use super::{
        CbId, CnMsg, FixtureProcessEventSource, LiveProcessEvent, LiveProcessRecorder,
        ProcConnectorSource, ProcEventHeader, ProcInput, current_host_id,
        parse_first_status_list_value, parse_proc_connector_message, parse_status_value,
        proc_connector_membership_message, write_copy,
    };
    use crate::poc::{
        event_path::{ExecEvent, ExitEvent},
        filesystem::persist::FilesystemPocStore,
    };

    #[test]
    fn proc_status_parsers_extract_parent_uid_and_gid() {
        let status = "Name:\tbash\nPPid:\t1337\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n";

        assert_eq!(parse_status_value::<u32>(status, "PPid:"), Some(1337));
        assert_eq!(parse_first_status_list_value(status, "Uid:"), Some(1000));
        assert_eq!(parse_first_status_list_value(status, "Gid:"), Some(1001));
    }

    #[test]
    fn proc_connector_membership_message_embeds_a_proc_input_payload() {
        let message = proc_connector_membership_message(libc::PROC_CN_MCAST_LISTEN);
        let offset = size_of::<libc::nlmsghdr>() + size_of::<super::CnMsg>();
        let payload = super::read_copy::<ProcInput>(&message, offset)
            .expect("membership payload should decode");

        assert_eq!(payload.mcast_op, libc::PROC_CN_MCAST_LISTEN);
        assert_eq!(payload.event_type, 0);
    }

    #[test]
    fn live_process_recorder_persists_synthetic_exec_and_exit_events() {
        let store = FilesystemPocStore::fresh(unique_test_root()).expect("store should init");
        let mut recorder = LiveProcessRecorder::new(
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_live_process"),
            store.clone(),
            CollectorKind::RuntimeHint,
            "host-live",
        );
        let mut source = FixtureProcessEventSource::new([
            LiveProcessEvent::Exec(ExecEvent {
                pid: 4242,
                ppid: 1337,
                uid: 1000,
                gid: 1000,
                command: "bash".to_owned(),
                filename: "/usr/bin/bash".to_owned(),
            }),
            LiveProcessEvent::Exit(ExitEvent {
                pid: 4242,
                ppid: 1337,
                exit_code: 0,
            }),
        ]);

        let persisted = recorder
            .drain_available(&mut source)
            .expect("synthetic source should persist cleanly");

        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].event_type, EventType::ProcessExec);
        assert_eq!(persisted[1].event_type, EventType::ProcessExit);
        assert_eq!(persisted[0].source.collector, CollectorKind::RuntimeHint);
        assert_eq!(persisted[0].source.host_id.as_deref(), Some("host-live"));
        assert_eq!(persisted[1].action.target.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(persisted[1].result.status, ResultStatus::Observed);
        assert_eq!(
            store
                .latest_audit_record()
                .expect("audit record should read")
                .expect("latest audit record should exist")
                .event_type,
            EventType::ProcessExit
        );
    }

    #[test]
    fn proc_connector_parser_ignores_non_exec_non_exit_payloads() {
        let total_len =
            size_of::<libc::nlmsghdr>() + size_of::<CnMsg>() + size_of::<ProcEventHeader>() + 4;
        let mut message = vec![0_u8; total_len];
        write_copy(
            &mut message,
            0,
            libc::nlmsghdr {
                nlmsg_len: total_len as u32,
                nlmsg_type: libc::NLMSG_DONE as u16,
                nlmsg_flags: 0,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            },
        );
        write_copy(
            &mut message,
            size_of::<libc::nlmsghdr>(),
            CnMsg {
                id: CbId {
                    idx: libc::CN_IDX_PROC,
                    val: libc::CN_VAL_PROC,
                },
                seq: 0,
                ack: 0,
                len: (size_of::<ProcEventHeader>() + 4) as u16,
                flags: 0,
            },
        );
        write_copy(
            &mut message,
            size_of::<libc::nlmsghdr>() + size_of::<CnMsg>(),
            ProcEventHeader {
                what: libc::PROC_EVENT_NONE,
                cpu: 0,
                timestamp_ns: 0,
            },
        );
        write_copy(
            &mut message,
            size_of::<libc::nlmsghdr>() + size_of::<CnMsg>() + size_of::<ProcEventHeader>(),
            0_u32,
        );

        assert_eq!(
            parse_proc_connector_message(&message).expect("ack-style message should parse"),
            None
        );
    }

    #[test]
    fn source_label_and_host_id_are_stable() {
        assert_eq!(ProcConnectorSource::SOURCE_LABEL, "proc_connector");
        assert!(!current_host_id().is_empty());
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("agent-auditor-hostd-live-process-test-{nonce}"))
    }
}
