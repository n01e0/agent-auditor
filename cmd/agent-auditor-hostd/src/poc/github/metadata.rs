use super::contract::{
    GITHUB_GOVERNANCE_REDACTION_RULE, GitHubGovernanceActionKind, MetadataBoundary,
};
use super::taxonomy::TaxonomyPlan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPlan {
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub contract_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub documentation_sources: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: MetadataBoundary,
}

impl MetadataPlan {
    pub fn from_taxonomy_plan(taxonomy: &TaxonomyPlan) -> Self {
        Self {
            semantic_actions: taxonomy.semantic_actions.clone(),
            contract_fields: vec!["provider_id", "action_key"],
            metadata_fields: vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ],
            documentation_sources: vec![
                "docs/architecture/provider-abstraction-github-candidate-catalog.md",
                "official GitHub REST endpoint documentation",
                "official GitHub fine-grained permission and OAuth scope documentation",
            ],
            responsibilities: vec![
                "own docs-backed GitHub method, canonical resource, side effect, auth-label, and privilege descriptors keyed by provider_id plus action_key",
                "reuse the shared provider metadata shape without re-running GitHub semantic classification",
                "act as the descriptive catalog that policy, audit, docs, and later UI work can join against without choosing policy outcomes",
                "avoid owning session context, live request matching, or durable audit / approval storage",
            ],
            stages: vec!["catalog", "lookup"],
            handoff: MetadataBoundary {
                semantic_actions: taxonomy.semantic_actions.clone(),
                contract_fields: vec!["provider_id", "action_key"],
                metadata_fields: vec![
                    "method",
                    "canonical_resource",
                    "side_effect",
                    "oauth_scopes",
                    "privilege_class",
                ],
                documentation_sources: vec![
                    "docs/architecture/provider-abstraction-github-candidate-catalog.md",
                    "official GitHub REST endpoint documentation",
                    "official GitHub fine-grained permission and OAuth scope documentation",
                ],
                redaction_contract: GITHUB_GOVERNANCE_REDACTION_RULE,
            },
        }
    }

    pub fn handoff(&self) -> MetadataBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        let actions = self
            .semantic_actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "contract_fields={} metadata_fields={} semantic_actions={} stages={} documentation_sources={}",
            self.contract_fields.join(","),
            self.metadata_fields.join(","),
            actions,
            self.stages.join("->"),
            self.documentation_sources.join("|")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::MetadataPlan;
    use crate::poc::github::{contract::GitHubGovernanceActionKind, taxonomy::TaxonomyPlan};

    #[test]
    fn metadata_plan_reuses_taxonomy_action_identity_without_policy_or_record_logic() {
        let taxonomy = TaxonomyPlan::default();
        let plan = MetadataPlan::from_taxonomy_plan(&taxonomy);

        assert_eq!(plan.semantic_actions, taxonomy.semantic_actions);
        assert_eq!(plan.contract_fields, vec!["provider_id", "action_key"]);
        assert_eq!(
            plan.metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("avoid owning session context"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("without choosing policy outcomes"))
        );
        assert!(
            plan.semantic_actions
                .contains(&GitHubGovernanceActionKind::PullsMerge)
        );
    }

    #[test]
    fn metadata_summary_mentions_catalog_sources() {
        let summary = MetadataPlan::from_taxonomy_plan(&TaxonomyPlan::default()).summary();

        assert!(summary.contains(
            "metadata_fields=method,canonical_resource,side_effect,oauth_scopes,privilege_class"
        ));
        assert!(summary.contains("provider-abstraction-github-candidate-catalog.md"));
    }
}
