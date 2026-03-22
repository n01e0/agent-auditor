use super::contract::{
    LIVE_PROXY_INTERCEPTION_REDACTION_RULE, SemanticConversionBoundary, SessionCorrelationBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticConversionPlan {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub semantic_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: SemanticConversionBoundary,
}

impl SemanticConversionPlan {
    pub fn from_session_correlation_boundary(boundary: SessionCorrelationBoundary) -> Self {
        let consumers = vec!["generic_rest", "gws", "github", "messaging"];
        let input_fields = boundary.correlation_fields;
        let semantic_fields = vec![
            "request_id",
            "correlation_id",
            "session_id",
            "agent_id",
            "workspace_id",
            "provider_hint",
            "correlation_status",
            "live_surface",
            "method",
            "authority",
            "path_hint",
            "header_classes",
            "body_class",
            "auth_hint",
            "target_hint",
            "semantic_family_hint",
            "mode_hint",
            "content_retained",
        ];

        Self {
            consumers: consumers.clone(),
            input_fields: input_fields.clone(),
            semantic_fields: semantic_fields.clone(),
            responsibilities: vec![
                "convert correlated live proxy requests into one generic live action seam before generic REST, GWS, GitHub, or messaging-specific taxonomy consumes them",
                "derive only redaction-safe live surface, target, and semantic-family hints without re-opening raw payload access",
                "separate cross-provider live request facts from provider-specific taxonomy so later adapters can reuse the same upstream envelope",
                "surface unsupported or degraded semantic conversion as explicit status instead of silently skipping downstream policy or records",
            ],
            stages: vec![
                "provider_hint",
                "generic_live_envelope",
                "semantic_family_hint",
                "handoff",
            ],
            handoff: SemanticConversionBoundary {
                consumers,
                input_fields,
                semantic_fields,
                redaction_contract: LIVE_PROXY_INTERCEPTION_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> SemanticConversionBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "consumers={} semantic_fields={} stages={}",
            self.consumers.join(","),
            self.semantic_fields.join(","),
            self.stages.join("->")
        )
    }
}
