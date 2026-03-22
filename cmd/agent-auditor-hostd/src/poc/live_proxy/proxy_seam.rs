use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, LIVE_PROXY_SOURCE_LABELS, LiveHttpRequestContract,
    ProxySeamBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySeamPlan {
    pub sources: Vec<&'static str>,
    pub request_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ProxySeamBoundary,
}

impl Default for ProxySeamPlan {
    fn default() -> Self {
        let sources = LIVE_PROXY_SOURCE_LABELS.to_vec();
        let request_fields = LiveHttpRequestContract::field_names().to_vec();

        Self {
            sources: sources.clone(),
            request_fields: request_fields.clone(),
            responsibilities: vec![
                "accept redaction-safe live HTTP request metadata from forward proxies, browser relays, or sidecar proxies",
                "strip raw header values, cookies, bearer tokens, and request/response bytes down to stable classes before any downstream handoff",
                "preserve stable request identity and mode hints without attaching a runtime session or deciding semantic action families",
                "handoff one redaction-safe live request seam that later session correlation and semantic conversion stages can reuse",
            ],
            stages: vec!["ingest", "redact", "request_identity", "handoff"],
            handoff: ProxySeamBoundary {
                sources,
                request_fields: request_fields.clone(),
                handoff_fields: request_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }
}

impl ProxySeamPlan {
    pub fn handoff(&self) -> ProxySeamBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "sources={} request_fields={} stages={}",
            self.sources.join(","),
            self.request_fields.join(","),
            self.stages.join("->")
        )
    }
}
