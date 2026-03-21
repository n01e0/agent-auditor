use super::contract::{
    GENERIC_REST_GOVERNANCE_REDACTION_RULE, GenericRestContractBoundary, ProviderInputBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizePlan {
    pub providers: Vec<&'static str>,
    pub upstream_contract_fields: Vec<&'static str>,
    pub upstream_metadata_fields: Vec<&'static str>,
    pub generic_contract_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    provider_input: ProviderInputBoundary,
    handoff: GenericRestContractBoundary,
}

impl Default for NormalizePlan {
    fn default() -> Self {
        Self {
            providers: vec!["gws", "github"],
            upstream_contract_fields: vec!["provider_id", "action_key", "target_hint"],
            upstream_metadata_fields: vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ],
            generic_contract_fields: vec![
                "provider_id",
                "action_key",
                "target_hint",
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ],
            responsibilities: vec![
                "accept shared provider action identity plus docs-backed provider metadata without re-running provider-specific taxonomy",
                "normalize provider-specific actions into a provider-neutral REST / OAuth governance contract centered on method, host, path template, query class, scope labels, side effect, and privilege class",
                "preserve provider lineage and redaction-safe target hints for downstream policy and audit explainability without carrying raw payloads or full query strings",
            ],
            stages: vec![
                "provider_contract_join",
                "rest_normalize",
                "oauth_label",
                "handoff",
            ],
            provider_input: ProviderInputBoundary {
                providers: vec!["gws", "github"],
                contract_fields: vec!["provider_id", "action_key", "target_hint"],
                metadata_fields: vec![
                    "method",
                    "canonical_resource",
                    "side_effect",
                    "oauth_scopes",
                    "privilege_class",
                ],
                redaction_contract: GENERIC_REST_GOVERNANCE_REDACTION_RULE,
            },
            handoff: GenericRestContractBoundary {
                providers: vec!["gws", "github"],
                input_fields: vec![
                    "provider_id",
                    "action_key",
                    "target_hint",
                    "method",
                    "canonical_resource",
                    "side_effect",
                    "oauth_scopes",
                    "privilege_class",
                ],
                contract_fields: vec![
                    "provider_id",
                    "action_key",
                    "target_hint",
                    "method",
                    "host",
                    "path_template",
                    "query_class",
                    "oauth_scope_labels",
                    "side_effect",
                    "privilege_class",
                ],
                redaction_contract: GENERIC_REST_GOVERNANCE_REDACTION_RULE,
            },
        }
    }
}

impl NormalizePlan {
    pub fn provider_input(&self) -> ProviderInputBoundary {
        self.provider_input.clone()
    }

    pub fn handoff(&self) -> GenericRestContractBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} upstream_contract={} upstream_metadata={} generic_fields={} stages={}",
            self.providers.join(","),
            self.upstream_contract_fields.join(","),
            self.upstream_metadata_fields.join(","),
            self.generic_contract_fields.join(","),
            self.stages.join("->")
        )
    }
}
