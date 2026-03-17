use super::contract::LoaderBoundary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPathPlan {
    pub transport: super::contract::EventTransport,
    pub raw_event_types: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
}

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

    pub fn summary(&self) -> String {
        format!(
            "transport={} raw_events={} stages={}",
            self.transport,
            self.raw_event_types.join(","),
            self.stages.join("->")
        )
    }
}
