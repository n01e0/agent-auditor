/// Metadata for the embedded exec / exit PoC programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramSpec {
    pub name: &'static str,
    pub section: &'static str,
    pub attach_point: &'static str,
}

pub const CRATE_NAME: &str = "agent-auditor-hostd-ebpf";
pub const OBJECT_FILENAME: &str = "agent-auditor-hostd-poc.bpf.o";
pub const LICENSE: &str = "GPL";
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

#[cfg(test)]
mod tests {
    use super::{LICENSE, PROGRAMS, object_bytes};

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
}
