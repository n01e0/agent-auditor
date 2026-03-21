pub mod contract;
pub mod policy;
pub mod record;
pub mod taxonomy;

use self::{policy::PolicyPlan, record::RecordPlan, taxonomy::TaxonomyPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingCollaborationGovernancePlan {
    pub taxonomy: TaxonomyPlan,
    pub policy: PolicyPlan,
    pub record: RecordPlan,
}

impl MessagingCollaborationGovernancePlan {
    pub fn bootstrap() -> Self {
        let taxonomy = TaxonomyPlan::default();
        let policy = PolicyPlan::from_contract_boundary(taxonomy.handoff());
        let record = RecordPlan::from_policy_boundary(policy.handoff());

        Self {
            taxonomy,
            policy,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessagingCollaborationGovernancePlan;

    #[test]
    fn bootstrap_plan_keeps_taxonomy_policy_and_record_responsibilities_separate() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .any(|item| item.contains("shared collaboration action family"))
        );
        assert!(
            plan.taxonomy
                .responsibilities
                .iter()
                .all(|item| !item.contains("append redaction-safe messaging audit records"))
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
                .any(|item| item.contains("append redaction-safe messaging audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_provider_and_generic_rest_inputs_into_messaging_boundary() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert_eq!(plan.taxonomy.providers, vec!["slack", "discord"]);
        assert_eq!(
            plan.taxonomy.action_families,
            vec![
                "message.send",
                "channel.invite",
                "permission.update",
                "file.upload",
            ]
        );
        assert_eq!(
            plan.taxonomy.upstream_provider_contract_fields,
            vec!["provider_id", "action_key", "target_hint"]
        );
        assert_eq!(
            plan.taxonomy.upstream_generic_rest_fields,
            vec![
                "method",
                "host",
                "path_template",
                "query_class",
                "oauth_scope_labels",
                "side_effect",
                "privilege_class",
            ]
        );
        assert_eq!(
            plan.taxonomy.messaging_contract_fields,
            vec![
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
            ]
        );
        assert_eq!(plan.taxonomy.providers, plan.policy.providers);
        assert_eq!(plan.policy.providers, plan.record.providers);
        assert_eq!(plan.taxonomy.action_families, plan.policy.action_families);
        assert_eq!(plan.policy.action_families, plan.record.action_families);
        assert_eq!(
            plan.policy.input_fields,
            plan.taxonomy.messaging_contract_fields
        );
        assert_eq!(plan.policy.decision_fields, plan.record.input_fields);
        assert_eq!(
            plan.record.record_fields,
            plan.record.handoff().record_fields
        );
    }

    #[test]
    fn bootstrap_plan_preserves_messaging_redaction_guardrails() {
        let plan = MessagingCollaborationGovernancePlan::bootstrap();

        assert_eq!(
            plan.taxonomy.provider_input().redaction_contract,
            "messaging seams carry action family, provider lineage, channel or conversation hints, target hints, membership or permission target classes, attachment-count hints, file target classes, delivery-scope hints, and docs-backed auth/risk descriptors only; raw message bodies, thread history, participant rosters, uploaded file bytes, preview URLs, invite links, and provider-specific opaque payloads must not cross the seam"
        );
        assert_eq!(
            plan.taxonomy.provider_input().redaction_contract,
            plan.taxonomy.handoff().redaction_contract
        );
        assert_eq!(
            plan.taxonomy.handoff().redaction_contract,
            plan.policy.handoff().redaction_contract
        );
        assert_eq!(
            plan.policy.handoff().redaction_contract,
            plan.record.redaction_contract
        );
    }
}
