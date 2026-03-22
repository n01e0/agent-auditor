pub const LIVE_PROXY_INTERCEPTION_REDACTION_RULE: &str = "live proxy seams carry only redaction-safe method, authority, path hints, header classes, body classes, auth hints, correlation ids, session lineage, semantic family hints, mode labels, and approval/audit linkage; raw header values, cookies, bearer tokens, request bodies, response bodies, message content, file bytes, and provider-opaque payloads must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySeamBoundary {
    pub sources: Vec<&'static str>,
    pub request_fields: Vec<&'static str>,
    pub handoff_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCorrelationBoundary {
    pub sources: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub correlation_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticConversionBoundary {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub semantic_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundary {
    pub consumers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBoundary {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub approval_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBoundary {
    pub modes: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}
