use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTransport {
    RingBuffer,
    PerfBuffer,
}

impl fmt::Display for EventTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::RingBuffer => "ring_buffer",
            Self::PerfBuffer => "perf_buffer",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderBoundary {
    pub transport: EventTransport,
    pub raw_event_types: Vec<&'static str>,
}

impl LoaderBoundary {
    pub fn exec_exit_ring_buffer() -> Self {
        Self {
            transport: EventTransport::RingBuffer,
            raw_event_types: vec!["exec", "exit"],
        }
    }
}
