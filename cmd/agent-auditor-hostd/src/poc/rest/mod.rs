pub mod contract;
pub mod normalize;
pub mod policy;
pub mod record;

use self::{normalize::NormalizePlan, policy::PolicyPlan, record::RecordPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRestOAuthGovernancePlan {
    pub normalize: NormalizePlan,
    pub policy: PolicyPlan,
    pub record: RecordPlan,
}

impl GenericRestOAuthGovernancePlan {
    pub fn bootstrap() -> Self {
        let normalize = NormalizePlan::default();
        let policy = PolicyPlan::from_contract_boundary(normalize.handoff());
        let record = RecordPlan::from_policy_boundary(policy.handoff());

        Self {
            normalize,
            policy,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GenericRestOAuthGovernancePlan;

    #[test]
    fn bootstrap_plan_keeps_normalize_policy_and_record_responsibilities_separate() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert!(
            plan.normalize
                .responsibilities
                .iter()
                .any(|item| item.contains("provider-neutral REST / OAuth governance contract"))
        );
        assert!(
            plan.normalize
                .responsibilities
                .iter()
                .all(|item| !item.contains("append redaction-safe generic REST audit records"))
        );

        assert!(
            plan.policy
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-policy"))
        );
        assert!(
            plan.policy
                .responsibilities
                .iter()
                .all(|item| !item.contains("append-only storage"))
        );

        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("append redaction-safe generic REST audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_contract_and_metadata_fields_into_generic_rest() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert_eq!(plan.normalize.providers, vec!["gws", "github"]);
        assert_eq!(
            plan.normalize.upstream_contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(
            plan.normalize.upstream_metadata_fields,
            vec![
                "method",
                "canonical_resource",
                "side_effect",
                "oauth_scopes",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.normalize.generic_contract_fields,
            vec![
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
            ]
        );
        assert_eq!(plan.normalize.providers, plan.policy.providers);
        assert_eq!(plan.policy.providers, plan.record.providers);
        assert_eq!(
            plan.policy.input_fields,
            plan.normalize.generic_contract_fields
        );
        assert_eq!(plan.policy.input_fields, plan.policy.handoff().input_fields);
        assert_eq!(plan.policy.decision_fields, plan.record.input_fields);
        assert_eq!(
            plan.record.record_fields,
            plan.record.handoff().record_fields
        );
    }

    #[test]
    fn bootstrap_plan_preserves_generic_rest_redaction_guardrails() {
        let plan = GenericRestOAuthGovernancePlan::bootstrap();

        assert_eq!(
            plan.normalize.provider_input().redaction_contract,
            "generic REST / OAuth seams carry route templates, authority labels, query classes, shared action identity, target hints, and docs-backed auth/risk descriptors only; raw request bodies, response bodies, message text, file bytes, token values, signed URLs, and full query strings must not cross the seam"
        );
        assert_eq!(
            plan.normalize.provider_input().redaction_contract,
            plan.normalize.handoff().redaction_contract
        );
        assert_eq!(
            plan.normalize.handoff().redaction_contract,
            plan.policy.handoff().redaction_contract
        );
        assert_eq!(
            plan.policy.handoff().redaction_contract,
            plan.record.redaction_contract
        );
    }
}
