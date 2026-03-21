pub const GENERIC_REST_GOVERNANCE_REDACTION_RULE: &str = "generic REST / OAuth seams carry route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only; raw request bodies, response bodies, message text, file bytes, token values, signed URLs, and full query strings must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInputBoundary {
    pub providers: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRestContractBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}
