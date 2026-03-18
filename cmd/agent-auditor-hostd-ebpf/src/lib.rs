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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEventFixture {
    pub pid: u32,
    pub ppid: u32,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEventFixture {
    pub pid: u32,
    pub sock_fd: u32,
    pub address_family: u16,
    pub transport: u16,
    pub destination_port: u16,
    pub destination_addr: [u8; CONNECT_ADDR_LEN],
}

pub const CRATE_NAME: &str = "agent-auditor-hostd-ebpf";
pub const OBJECT_FILENAME: &str = "agent-auditor-hostd-poc.bpf.o";
pub const LICENSE: &str = "GPL";
pub const EXEC_COMM_LEN: usize = 16;
pub const EXEC_FILENAME_LEN: usize = 64;
pub const EXEC_EVENT_LEN: usize = (4 * 4) + EXEC_COMM_LEN + EXEC_FILENAME_LEN;
pub const EXIT_EVENT_LEN: usize = 12;
pub const CONNECT_ADDR_LEN: usize = 16;
pub const CONNECT_EVENT_LEN: usize = 32;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const IPPROTO_TCP: u16 = 6;
pub const IPPROTO_UDP: u16 = 17;
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

pub fn fixture_exit_event() -> ExitEventFixture {
    ExitEventFixture {
        pid: 4242,
        ppid: 1337,
        exit_code: 0,
    }
}

pub fn fixture_exit_event_bytes() -> Vec<u8> {
    let fixture = fixture_exit_event();
    let mut bytes = Vec::with_capacity(EXIT_EVENT_LEN);

    bytes.extend_from_slice(&fixture.pid.to_le_bytes());
    bytes.extend_from_slice(&fixture.ppid.to_le_bytes());
    bytes.extend_from_slice(&fixture.exit_code.to_le_bytes());

    bytes
}

pub fn fixture_connect_event() -> ConnectEventFixture {
    let mut destination_addr = [0_u8; CONNECT_ADDR_LEN];
    destination_addr[..4].copy_from_slice(&[93, 184, 216, 34]);

    ConnectEventFixture {
        pid: 4242,
        sock_fd: 7,
        address_family: AF_INET,
        transport: IPPROTO_TCP,
        destination_port: 443,
        destination_addr,
    }
}

pub fn fixture_connect_event_bytes() -> Vec<u8> {
    let fixture = fixture_connect_event();
    let mut bytes = Vec::with_capacity(CONNECT_EVENT_LEN);

    bytes.extend_from_slice(&fixture.pid.to_le_bytes());
    bytes.extend_from_slice(&fixture.sock_fd.to_le_bytes());
    bytes.extend_from_slice(&fixture.address_family.to_le_bytes());
    bytes.extend_from_slice(&fixture.transport.to_le_bytes());
    bytes.extend_from_slice(&fixture.destination_port.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&fixture.destination_addr);

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
        AF_INET, CONNECT_EVENT_LEN, EXEC_EVENT_LEN, EXIT_EVENT_LEN, IPPROTO_TCP, LICENSE, PROGRAMS,
        fixture_connect_event, fixture_connect_event_bytes, fixture_exec_event,
        fixture_exec_event_bytes, fixture_exit_event, fixture_exit_event_bytes, object_bytes,
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

    #[test]
    fn fixture_exit_event_bytes_have_the_expected_wire_length() {
        let fixture = fixture_exit_event();
        let bytes = fixture_exit_event_bytes();

        assert_eq!(fixture.exit_code, 0);
        assert_eq!(bytes.len(), EXIT_EVENT_LEN);
    }

    #[test]
    fn fixture_exec_and_exit_share_the_same_lifecycle_key() {
        let exec = fixture_exec_event();
        let exit = fixture_exit_event();

        assert_eq!(exec.pid, exit.pid);
        assert_eq!(exec.ppid, exit.ppid);
    }

    #[test]
    fn fixture_connect_event_bytes_have_the_expected_wire_length() {
        let fixture = fixture_connect_event();
        let bytes = fixture_connect_event_bytes();

        assert_eq!(fixture.pid, 4242);
        assert_eq!(fixture.sock_fd, 7);
        assert_eq!(fixture.address_family, AF_INET);
        assert_eq!(fixture.transport, IPPROTO_TCP);
        assert_eq!(fixture.destination_port, 443);
        assert_eq!(&fixture.destination_addr[..4], &[93, 184, 216, 34]);
        assert_eq!(bytes.len(), CONNECT_EVENT_LEN);
    }
}
