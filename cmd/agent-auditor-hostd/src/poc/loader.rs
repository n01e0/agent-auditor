use super::contract::LoaderBoundary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderPlan {
    pub artifact_crate: String,
    pub aya_stack: String,
    pub attach_points: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: LoaderBoundary,
}

impl Default for LoaderPlan {
    fn default() -> Self {
        Self {
            artifact_crate: "agent-auditor-hostd-ebpf".to_owned(),
            aya_stack: std::any::type_name::<aya::Ebpf>().to_owned(),
            attach_points: vec!["sched_process_exec", "sched_process_exit"],
            responsibilities: vec![
                "choose and load the eBPF object",
                "attach kernel hooks for exec / exit collection",
                "own the low-level aya program lifecycle",
                "expose a raw event transport boundary to userspace",
            ],
            handoff: LoaderBoundary::exec_exit_ring_buffer(),
        }
    }
}

impl LoaderPlan {
    pub fn handoff(&self) -> LoaderBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "artifact={} aya_stack={} transport={} hooks={}",
            self.artifact_crate,
            self.aya_stack,
            self.handoff.transport,
            self.attach_points.join(",")
        )
    }
}
