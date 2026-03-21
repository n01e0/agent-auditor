use super::contract::{
    GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource, MetadataBoundary,
    RecordBoundary, TaxonomyBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub taxonomy_fields: Vec<&'static str>,
    pub metadata_fields: Vec<&'static str>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: RecordBoundary,
}

impl PolicyPlan {
    pub fn from_boundaries(taxonomy: TaxonomyBoundary, metadata: MetadataBoundary) -> Self {
        Self {
            sources: taxonomy.sources.clone(),
            semantic_surfaces: taxonomy.semantic_surfaces.clone(),
            taxonomy_fields: taxonomy.taxonomy_fields.clone(),
            metadata_fields: metadata.metadata_fields.clone(),
            semantic_actions: metadata.semantic_actions.clone(),
            responsibilities: vec![
                "normalize redaction-safe GitHub governance candidates toward agenta-core without redefining GitHub taxonomy or mutating the metadata catalog",
                "join docs-backed provider metadata onto provider_id plus action_key before agenta-policy evaluation",
                "bridge normalized GitHub governance events into agenta-policy and project allow / deny / require_approval outcomes",
                "carry the GitHub governance redaction contract forward into audit and approval recording",
            ],
            stages: vec!["normalize", "annotate", "evaluate", "project"],
            handoff: RecordBoundary {
                sources: taxonomy.sources,
                semantic_surfaces: taxonomy.semantic_surfaces,
                semantic_actions: metadata.semantic_actions,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: taxonomy.redaction_contract,
            },
        }
    }

    pub fn handoff(&self) -> RecordBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        let sources = self
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let surfaces = self
            .semantic_surfaces
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} surfaces={} taxonomy_fields={} metadata_fields={} stages={}",
            sources,
            surfaces,
            self.taxonomy_fields.join(","),
            self.metadata_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyPlan;
    use crate::poc::github::{metadata::MetadataPlan, taxonomy::TaxonomyPlan};

    #[test]
    fn policy_plan_joins_taxonomy_and_metadata_without_owning_either_boundary() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let plan = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());

        assert!(
            plan.responsibilities
                .iter()
                .any(|item| item.contains("join docs-backed provider metadata"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("durable audit"))
        );
        assert!(
            plan.responsibilities
                .iter()
                .all(|item| !item.contains("live request matching"))
        );
        assert_eq!(
            plan.handoff().record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
    }

    #[test]
    fn policy_summary_mentions_normalize_and_evaluate_stages() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let summary = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff()).summary();

        assert!(summary.contains("stages=normalize->annotate->evaluate->project"));
        assert!(summary.contains(
            "metadata_fields=method,canonical_resource,side_effect,oauth_scopes,privilege_class"
        ));
    }
}
