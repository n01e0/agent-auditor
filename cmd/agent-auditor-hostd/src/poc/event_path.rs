use std::{error::Error, fmt};

use agent_auditor_hostd_ebpf as poc_ebpf;

use super::contract::LoaderBoundary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPathPlan {
    pub transport: super::contract::EventTransport,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredExecEvent {
    pub raw_len: usize,
    pub event: ExecEvent,
    pub log_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecEventDecodeError {
    WrongLength { expected: usize, actual: usize },
}

impl fmt::Display for ExecEventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(
                    f,
                    "invalid exec event length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl Error for ExecEventDecodeError {}

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
    ) -> Result<DeliveredExecEvent, ExecEventDecodeError> {
        let event = ExecEvent::from_bytes(bytes)?;
        let log_line = event.log_line(self.transport);

        Ok(DeliveredExecEvent {
            raw_len: bytes.len(),
            event,
            log_line,
        })
    }

    pub fn preview_exec_delivery(&self) -> Result<DeliveredExecEvent, ExecEventDecodeError> {
        let fixture = poc_ebpf::fixture_exec_event_bytes();
        self.deliver_exec_to_log(&fixture)
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ExecEventDecodeError> {
        if bytes.len() != poc_ebpf::EXEC_EVENT_LEN {
            return Err(ExecEventDecodeError::WrongLength {
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
            command,
            filename,
        })
    }

    pub fn log_line(&self, transport: super::contract::EventTransport) -> String {
        format!(
            "event=process.exec transport={} pid={} ppid={} uid={} gid={} command={} target={}",
            transport, self.pid, self.ppid, self.uid, self.gid, self.command, self.filename
        )
    }
}

fn read_u32(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(
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

    use super::{EventPathPlan, ExecEvent, ExecEventDecodeError};
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
        assert_eq!(delivered.event.pid, 4242);
        assert!(delivered.log_line.contains("event=process.exec"));
        assert!(delivered.log_line.contains("transport=ring_buffer"));
        assert!(delivered.log_line.contains("command=cargo"));
        assert!(delivered.log_line.contains("target=/usr/bin/cargo"));
    }

    #[test]
    fn invalid_exec_payload_length_is_rejected() {
        let error = EventPathPlan::from_loader_boundary(LoaderBoundary::exec_exit_ring_buffer())
            .deliver_exec_to_log(&[0; 8])
            .expect_err("short payload should fail");

        assert_eq!(
            error,
            ExecEventDecodeError::WrongLength {
                expected: poc_ebpf::EXEC_EVENT_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn exec_log_line_keeps_transport_visible() {
        let event = ExecEvent::from_bytes(&poc_ebpf::fixture_exec_event_bytes())
            .expect("fixture exec event should decode");
        let log_line = event.log_line(EventTransport::RingBuffer);

        assert!(log_line.contains("transport=ring_buffer"));
        assert!(log_line.contains("pid=4242"));
    }
}
