use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, ProxySeamBoundary, SessionCorrelationBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCorrelationPlan {
    pub sources: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub correlation_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SessionCorrelationBoundary,
}

impl SessionCorrelationPlan {
    pub fn from_proxy_seam_boundary(boundary: ProxySeamBoundary) -> Self {
        let sources = boundary.sources.clone();
        let input_fields = boundary.handoff_fields;
        let correlation_fields = vec![
            "source",
            "request_id",
            "correlation_id",
            "transport",
            "method",
            "authority",
            "path",
            "headers",
            "body_class",
            "auth_hint",
            "mode",
            "session_id",
            "agent_id",
            "workspace_id",
            "provider_hint",
            "correlation_reason",
            "correlation_status",
        ];

        Self {
            sources: sources.clone(),
            input_fields: input_fields.clone(),
            correlation_fields: correlation_fields.clone(),
            responsibilities: vec![
                "bind live proxy requests to the same runtime session identity used by hostd events and approval records",
                "decide whether request ids, correlation ids, workspace hints, or runtime lineage are strong enough to claim session ownership",
                "preserve provider and surface hints for downstream semantic conversion without deciding the final generic or provider-specific action taxonomy",
                "surface uncorrelated or degraded requests explicitly instead of letting later policy code guess ownership",
            ],
            stages: vec!["lookup", "bind_session", "lineage_hint", "handoff"],
            handoff: SessionCorrelationBoundary {
                sources,
                input_fields,
                correlation_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> SessionCorrelationBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "sources={} correlation_fields={} stages={}",
            self.sources.join(","),
            self.correlation_fields.join(","),
            self.stages.join("->")
        )
    }
}
