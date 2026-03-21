const PROVIDER_ABSTRACTION_REDACTION_RULE: &str = "provider abstraction seams carry action identity, target hints, and docs-backed descriptors only; raw provider payloads, message bodies, file contents, and diff bodies must not cross the seam";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAbstractionPlan {
    pub taxonomy: ProviderTaxonomyBoundary,
    pub contract: ProviderContractBoundary,
    pub metadata: ProviderMetadataBoundary,
}

impl ProviderAbstractionPlan {
    pub fn bootstrap() -> Self {
        let taxonomy = ProviderTaxonomyBoundary::default();
        let contract = ProviderContractBoundary::from_taxonomy_boundary(&taxonomy);
        let metadata = ProviderMetadataBoundary::from_contract_boundary(&contract);

        Self {
            taxonomy,
            contract,
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTaxonomyBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub output_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl Default for ProviderTaxonomyBoundary {
    fn default() -> Self {
        Self {
            providers: vec!["gws", "github"],
            input_fields: vec![
                "provider_hint",
                "surface_hint",
                "method_hint",
                "path_hint",
                "target_hint",
                "classifier_labels",
                "classifier_reasons",
            ],
            output_fields: vec![
                "provider_id",
                "provider_action_label",
                "target_hint",
                "taxonomy_reason",
            ],
            responsibilities: vec![
                "accept provider-native API, browser, or network hints and map them into provider-local action candidates",
                "own provider-specific labels and matching heuristics for surfaces such as GWS today and GitHub next",
                "handoff provider_id plus provider_action_label and target_hint without defining the shared policy contract or metadata catalog",
            ],
            redaction_contract: PROVIDER_ABSTRACTION_REDACTION_RULE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderContractBoundary {
    pub providers: Vec<&'static str>,
    pub input_fields: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl ProviderContractBoundary {
    pub fn from_taxonomy_boundary(taxonomy: &ProviderTaxonomyBoundary) -> Self {
        Self {
            providers: taxonomy.providers.clone(),
            input_fields: taxonomy.output_fields.clone(),
            contract_fields: vec!["provider_id", "action_key", "target_hint"],
            responsibilities: vec![
                "define the provider-neutral action identity consumed by agenta-core and later agenta-policy generalization",
                "stabilize a provider plus action_key handoff so downstream policy and audit code do not depend on GWS-specific labels",
                "carry only redaction-safe action identity and target summaries, not provider-native matching heuristics or docs-backed scope catalogs",
            ],
            redaction_contract: taxonomy.redaction_contract,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadataBoundary {
    pub providers: Vec<&'static str>,
    pub contract_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub documentation_sources: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl ProviderMetadataBoundary {
    pub fn from_contract_boundary(contract: &ProviderContractBoundary) -> Self {
        Self {
            providers: contract.providers.clone(),
            contract_fields: contract.contract_fields.clone(),
            metadata_fields: vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ],
            documentation_sources: vec![
                "official provider method documentation",
                "official provider auth and scope documentation",
                "repository-owned risk and posture notes",
            ],
            responsibilities: vec![
                "attach docs-backed method, resource, side effect, OAuth scope, and privilege descriptors to shared provider actions",
                "key metadata by the shared provider_id plus action_key contract without re-running provider-specific classification",
                "act as the descriptive catalog for policy, audit, docs, and later UI work without mutating shared action identity",
            ],
            redaction_contract: contract.redaction_contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderAbstractionPlan;

    #[test]
    fn bootstrap_plan_separates_provider_contract_metadata_and_taxonomy_ownership() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-local action candidates"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("GWS today and GitHub next"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );

        assert!(
            plan.contract
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-neutral action identity"))
        );
        assert!(
            plan.contract
                .responsibilities
                .iter()
                .all(|item| !item.contains("OAuth scope"))
        );
        assert!(plan.contract.responsibilities.iter().any(|item| {
            item.contains("not provider-native matching heuristics or docs-backed scope catalogs")
        }));

        assert!(plan
            .metadata
            .responsibilities
            .iter()
            .any(|item| item.contains("docs-backed method, resource, side effect, OAuth scope, and privilege descriptors")));
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("without re-running provider-specific classification"))
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("without mutating shared action identity"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_labels_and_redaction_guardrails() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert_eq!(plan.taxonomy.providers, vec!["gws", "github"]);
        assert_eq!(plan.taxonomy.providers, plan.contract.providers);
        assert_eq!(plan.contract.providers, plan.metadata.providers);
        assert_eq!(plan.taxonomy.output_fields, plan.contract.input_fields);
        assert_eq!(
            plan.contract.contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(plan.contract.contract_fields, plan.metadata.contract_fields);
        assert_eq!(
            plan.metadata.metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.taxonomy.redaction_contract,
            "provider abstraction seams carry action identity, target hints, and docs-backed descriptors only; raw provider payloads, message bodies, file contents, and diff bodies must not cross the seam"
        );
        assert_eq!(
            plan.taxonomy.redaction_contract,
            plan.contract.redaction_contract
        );
        assert_eq!(
            plan.contract.redaction_contract,
            plan.metadata.redaction_contract
        );
    }

    #[test]
    fn bootstrap_plan_keeps_provider_metadata_keyed_by_shared_contract() {
        let plan = ProviderAbstractionPlan::bootstrap();

        assert_eq!(
            plan.metadata.documentation_sources,
            vec![
                "official provider method documentation",
                "official provider auth and scope documentation",
                "repository-owned risk and posture notes",
            ]
        );
        assert!(
            plan.metadata
                .responsibilities
                .iter()
                .any(|item| item.contains("provider_id plus action_key"))
        );
        assert!(
            plan.contract
                .responsibilities
                .iter()
                .any(|item| item.contains("provider plus action_key handoff"))
        );
    }
}
