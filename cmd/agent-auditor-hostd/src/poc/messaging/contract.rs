pub const MESSAGING_GOVERNANCE_REDACTION_RULE: &str = "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMessagingInputBoundary {
    pub providers: Vec<&'static str>,
    pub provider_contract_fields: Vec<&'static str>,
    pub generic_rest_fields: Vec<&'static str>,
    pub provider_taxonomy_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingContractBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub decision_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}
