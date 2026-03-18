/// Metadata for the embedded exec / exit PoC programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramSpec {
    pub name: &'static str,
    pub section: &'static str,
    pub attach_point: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEventFixture {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: &'static str,
    pub filename: &'static str,
}

pub const CRATE_NAME: &str = "agent-auditor-hostd-ebpf";
pub const OBJECT_FILENAME: &str = "agent-auditor-hostd-poc.bpf.o";
pub const LICENSE: &str = "GPL";
pub const EXEC_COMM_LEN: usize = 16;
pub const EXEC_FILENAME_LEN: usize = 64;
pub const EXEC_EVENT_LEN: usize = (4 * 4) + EXEC_COMM_LEN + EXEC_FILENAME_LEN;
pub const PROGRAMS: &[ProgramSpec] = &[
    ProgramSpec {
        name: "hostd_sched_process_exec",
        section: "tracepoint/sched/sched_process_exec",
        attach_point: "sched:sched_process_exec",
    },
    ProgramSpec {
        name: "hostd_sched_process_exit",
        section: "tracepoint/sched/sched_process_exit",
        attach_point: "sched:sched_process_exit",
    },
];

#[repr(C, align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

const EMBEDDED_OBJECT_BYTES: &AlignedBytes<
    { include_bytes!(concat!(env!("OUT_DIR"), "/agent-auditor-hostd-poc.bpf.o")).len() },
> = &AlignedBytes(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent-auditor-hostd-poc.bpf.o"
)));

pub fn object_bytes() -> &'static [u8] {
    &EMBEDDED_OBJECT_BYTES.0
}

pub fn fixture_exec_event() -> ExecEventFixture {
    ExecEventFixture {
        pid: 4242,
        ppid: 1337,
        uid: 1000,
        gid: 1000,
        command: "cargo",
        filename: "/usr/bin/cargo",
    }
}

pub fn fixture_exec_event_bytes() -> Vec<u8> {
    let fixture = fixture_exec_event();
    let mut bytes = Vec::with_capacity(EXEC_EVENT_LEN);

    bytes.extend_from_slice(&fixture.pid.to_le_bytes());
    bytes.extend_from_slice(&fixture.ppid.to_le_bytes());
    bytes.extend_from_slice(&fixture.uid.to_le_bytes());
    bytes.extend_from_slice(&fixture.gid.to_le_bytes());
    bytes.extend_from_slice(&encode_c_string::<EXEC_COMM_LEN>(fixture.command));
    bytes.extend_from_slice(&encode_c_string::<EXEC_FILENAME_LEN>(fixture.filename));

    bytes
}

fn encode_c_string<const N: usize>(value: &str) -> [u8; N] {
    let mut buffer = [0_u8; N];
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(N.saturating_sub(1));

    buffer[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buffer
}

#[cfg(test)]
mod tests {
    use super::{
        EXEC_EVENT_LEN, LICENSE, PROGRAMS, fixture_exec_event, fixture_exec_event_bytes,
        object_bytes,
    };

    #[test]
    fn embedded_object_bytes_are_present() {
        assert!(!object_bytes().is_empty());
    }

    #[test]
    fn program_metadata_covers_exec_and_exit_tracepoints() {
        assert_eq!(LICENSE, "GPL");
        assert_eq!(
            PROGRAMS
                .iter()
                .map(|program| program.attach_point)
                .collect::<Vec<_>>(),
            vec!["sched:sched_process_exec", "sched:sched_process_exit"]
        );
    }

    #[test]
    fn fixture_exec_event_bytes_have_the_expected_wire_length() {
        let fixture = fixture_exec_event();
        let bytes = fixture_exec_event_bytes();

        assert_eq!(fixture.command, "cargo");
        assert_eq!(fixture.filename, "/usr/bin/cargo");
        assert_eq!(bytes.len(), EXEC_EVENT_LEN);
    }
}
