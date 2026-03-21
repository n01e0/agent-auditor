use super::contract::{
    MESSAGING_GOVERNANCE_REDACTION_RULE, MessagingContractBoundary, ProviderMessagingInputBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyPlan {
    pub providers: Vec<&'static str>,
    pub action_families: Vec<&'static str>,
    pub upstream_provider_contract_fields: Vec<&'static str>,
    pub upstream_generic_rest_fields: Vec<&'static str>,
    pub upstream_provider_taxonomy_fields: Vec<&'static str>,
    pub messaging_contract_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    provider_input: ProviderMessagingInputBoundary,
    handoff: MessagingContractBoundary,
}

impl Default for TaxonomyPlan {
    fn default() -> Self {
        Self {
            providers: vec!["slack", "discord"],
            action_families: vec![
                "message.send",
                "channel.invite",
                "permission.update",
                "file.upload",
            ],
            upstream_provider_contract_fields: vec!["provider_id", "action_key", "target_hint"],
            upstream_generic_rest_fields: vec![
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ],
            upstream_provider_taxonomy_fields: vec![
                "semantic_surface",
                "classifier_labels",
                "classifier_reasons",
            ],
            messaging_contract_fields: vec![
                "provider_id",
                "action_key",
                "action_family",
                "target_hint",
                "channel_hint",
                "conversation_hint",
                "delivery_scope",
                "membership_target_kind",
                "permission_target_kind",
                "file_target_kind",
                "attachment_count_hint",
            ],
            responsibilities: vec![
                "join provider action identity, provider-local semantic hints, and generic REST lineage into a shared collaboration action family without re-running provider-specific route matching downstream",
                "separate lower-level REST semantics from higher-level collaboration intent such as message delivery, channel membership expansion, permission mutation, and file publication",
                "preserve only redaction-safe collaboration hints for downstream policy and audit explainability without carrying raw message bodies, participant rosters, or uploaded bytes",
            ],
            stages: vec![
                "provider_join",
                "family_inference",
                "messaging_normalize",
                "handoff",
            ],
            provider_input: ProviderMessagingInputBoundary {
                providers: vec!["slack", "discord"],
                provider_contract_fields: vec!["provider_id", "action_key", "target_hint"],
                generic_rest_fields: vec![
                    "method",
                    "host",
                    "path_template",
                    "query_class",
                    "oauth_scope_labels",
                    "side_effect",
                    "privilege_class",
                ],
                provider_taxonomy_fields: vec![
                    "semantic_surface",
                    "classifier_labels",
                    "classifier_reasons",
                ],
                redaction_contract: MESSAGING_GOVERNANCE_REDACTION_RULE,
            },
            handoff: MessagingContractBoundary {
                providers: vec!["slack", "discord"],
                action_families: vec![
                    "message.send",
                    "channel.invite",
                    "permission.update",
                    "file.upload",
                ],
                input_fields: vec![
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
                    "semantic_surface",
                    "classifier_labels",
                    "classifier_reasons",
                ],
                contract_fields: vec![
                    "provider_id",
                    "action_key",
                    "action_family",
                    "target_hint",
                    "channel_hint",
                    "conversation_hint",
                    "delivery_scope",
                    "membership_target_kind",
                    "permission_target_kind",
                    "file_target_kind",
                    "attachment_count_hint",
                ],
                redaction_contract: MESSAGING_GOVERNANCE_REDACTION_RULE,
            },
        }
    }
}

impl TaxonomyPlan {
    pub fn provider_input(&self) -> ProviderMessagingInputBoundary {
        self.provider_input.clone()
    }

    pub fn handoff(&self) -> MessagingContractBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "providers={} action_families={} upstream_provider_contract={} upstream_generic_rest={} upstream_provider_taxonomy={} messaging_fields={} stages={}",
            self.providers.join(","),
            self.action_families.join(","),
            self.upstream_provider_contract_fields.join(","),
            self.upstream_generic_rest_fields.join(","),
            self.upstream_provider_taxonomy_fields.join(","),
            self.messaging_contract_fields.join(","),
            self.stages.join("->")
        )
    }
}
