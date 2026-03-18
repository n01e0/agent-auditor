use super::contract::{FilesystemCollector, WatchBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchPlan {
    pub collector: FilesystemCollector,
    pub mark_scope: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: WatchBoundary,
}

impl Default for WatchPlan {
    fn default() -> Self {
        Self {
            collector: FilesystemCollector::Fanotify,
            mark_scope: vec!["configured sensitive roots", "mounted secret directories"],
            responsibilities: vec![
                "initialize the fanotify instance and kernel-facing watch lifecycle",
                "own fanotify marks for sensitive roots and mounted secret directories",
                "resolve raw fanotify access masks and path handles into watch-side records",
                "handoff raw filesystem access signals without applying sensitivity policy",
            ],
            handoff: WatchBoundary::fanotify_poc(),
        }
    }
}

impl WatchPlan {
    pub fn handoff(&self) -> WatchBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} marks={} raw_fields={} raw_access_kinds={}",
            self.collector,
            self.mark_scope.join(","),
            self.handoff.raw_fields.join(","),
            self.handoff.raw_access_kinds.join(",")
        )
    }
}
