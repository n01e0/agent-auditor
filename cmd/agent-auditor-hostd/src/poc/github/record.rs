use super::contract::{
    GitHubGovernanceActionKind, GitHubSemanticSurface, GitHubSignalSource, RecordBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlan {
    pub sources: Vec<GitHubSignalSource>,
    pub semantic_surfaces: Vec<GitHubSemanticSurface>,
    pub semantic_actions: Vec<GitHubGovernanceActionKind>,
    pub record_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

impl RecordPlan {
    pub fn from_policy_boundary(boundary: RecordBoundary) -> Self {
        Self {
            sources: boundary.sources,
            semantic_surfaces: boundary.semantic_surfaces,
            semantic_actions: boundary.semantic_actions,
            record_fields: boundary.record_fields,
            responsibilities: vec![
                "persist redaction-safe GitHub governance audit records",
                "persist approval requests created by approval-gated GitHub governance actions",
                "fan out recorded artifacts to structured logs and later control-plane sinks",
                "avoid re-classifying GitHub actions, mutating docs-backed metadata, or re-evaluating policy while recording results",
            ],
            sinks: vec!["structured_log", "audit_store", "approval_store"],
            stages: vec!["persist", "publish"],
            redaction_contract: boundary.redaction_contract,
        }
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
            "sources={} surfaces={} record_fields={} stages={} sinks={}",
            sources,
            surfaces,
            self.record_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::RecordPlan;
    use crate::poc::github::{metadata::MetadataPlan, policy::PolicyPlan, taxonomy::TaxonomyPlan};

    #[test]
    fn record_plan_preserves_redaction_contract_and_storage_sinks() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let plan = RecordPlan::from_policy_boundary(policy.handoff());

        assert_eq!(plan.stages, vec!["persist", "publish"]);
        assert_eq!(
            plan.sinks,
            vec!["structured_log", "audit_store", "approval_store"]
        );
        assert_eq!(
            plan.redaction_contract,
            "raw GitHub request or response payloads, issue bodies, pull-request bodies, diff hunks, workflow YAML bodies, and secret values must not cross the GitHub governance seams"
        );
    }

    #[test]
    fn record_summary_mentions_record_fields_and_sinks() {
        let taxonomy = TaxonomyPlan::default();
        let metadata = MetadataPlan::from_taxonomy_plan(&taxonomy);
        let policy = PolicyPlan::from_boundaries(taxonomy.handoff(), metadata.handoff());
        let summary = RecordPlan::from_policy_boundary(policy.handoff()).summary();

        assert!(summary.contains(
            "record_fields=normalized_event,policy_decision,approval_request,redaction_status"
        ));
        assert!(summary.contains("sinks=structured_log,audit_store,approval_store"));
    }
}
