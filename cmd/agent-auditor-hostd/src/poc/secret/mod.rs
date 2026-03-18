pub mod classify;
pub mod contract;
pub mod evaluate;
pub mod record;

use self::{classify::ClassifyPlan, evaluate::EvaluatePlan, record::RecordPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAccessPocPlan {
    pub classify: ClassifyPlan,
    pub evaluate: EvaluatePlan,
    pub record: RecordPlan,
}

impl SecretAccessPocPlan {
    pub fn bootstrap() -> Self {
        let classify = ClassifyPlan::default();
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let record = RecordPlan::from_evaluation_boundary(evaluate.handoff());

        Self {
            classify,
            evaluate,
            record,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{CollectorKind, PolicyDecisionKind, ResultStatus, Severity};
    use agenta_policy::{
        PolicyCoverageContext, PolicyEvaluator, PolicyInput, RegoPolicyEvaluator,
        apply_decision_to_event, approval_request_from_decision,
    };
    use serde_json::json;

    use super::SecretAccessPocPlan;
    use crate::poc::secret::contract::{
        BrokeredSecretRequest, ClassifiedSecretAccess, SecretPathAccess, SecretSignalSource,
    };

    #[test]
    fn bootstrap_plan_keeps_classify_evaluate_and_record_responsibilities_separate() {
        let plan = SecretAccessPocPlan::bootstrap();

        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("upstream collectors"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .all(|item| !item.contains("audit records"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-core secret access events"))
        );
        assert!(
            plan.evaluate
                .responsibilities
                .iter()
                .all(|item| !item.contains("upstream collectors"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .any(|item| item.contains("audit records"))
        );
        assert!(
            plan.record
                .responsibilities
                .iter()
                .all(|item| !item.contains("agenta-policy"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_secret_contracts_across_the_pipeline() {
        let plan = SecretAccessPocPlan::bootstrap();

        assert_eq!(
            plan.classify.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.evaluate.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.record.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.classify.input_fields,
            vec![
                "source_kind",
                "operation",
                "path",
                "mount_id",
                "secret_locator_hint",
                "broker_id",
                "broker_action",
            ]
        );
        assert_eq!(
            plan.classify.taxonomy_kinds,
            vec![
                crate::poc::secret::contract::SecretTaxonomyKind::SecretFile,
                crate::poc::secret::contract::SecretTaxonomyKind::MountedSecret,
                crate::poc::secret::contract::SecretTaxonomyKind::BrokeredSecretRequest,
            ]
        );
        assert_eq!(
            plan.evaluate.classification_fields,
            vec![
                "source_kind",
                "operation",
                "taxonomy_kind",
                "taxonomy_variant",
                "locator_hint",
                "classifier_labels",
                "classifier_reasons",
                "plaintext_retained",
            ]
        );
        assert_eq!(
            plan.record.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            plan.record.redaction_contract,
            "plaintext secret material must not cross the classify boundary"
        );
    }

    #[test]
    fn secret_pipeline_allows_unmatched_env_file_access() {
        let session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = SecretAccessPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/workspace/.env.production".to_owned(),
                mount_id: Some(18),
            })
            .expect("env file should classify");
        let event = plan
            .evaluate
            .normalize_classified_access(&classified, &session);
        let input = PolicyInput::from_event(&event);

        assert_eq!(event.source.collector, CollectorKind::Fanotify);
        assert_eq!(
            input.context.coverage,
            Some(PolicyCoverageContext {
                collector: Some("fanotify".to_owned()),
                enforce_capable: false,
            })
        );

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("default.allow"));
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(decision.reason.as_deref(), Some("no matching rule"));
    }

    #[test]
    fn secret_pipeline_requires_approval_for_brokered_secret_requests() {
        let session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = SecretAccessPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_broker_request(&BrokeredSecretRequest {
                operation: "fetch".to_owned(),
                broker_id: "vault".to_owned(),
                broker_action: "read".to_owned(),
                secret_locator_hint: "kv/prod/db/password".to_owned(),
            });
        let event = plan
            .evaluate
            .normalize_classified_access(&classified, &session);
        let input = PolicyInput::from_event(&event);

        assert_eq!(event.source.collector, CollectorKind::ControlPlane);
        assert_eq!(
            input.context.coverage,
            Some(PolicyCoverageContext {
                collector: Some("control_plane".to_owned()),
                enforce_capable: false,
            })
        );

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("secret.brokered.requires_approval")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("brokered secret retrieval requires approval")
        );
    }

    #[test]
    fn secret_pipeline_denies_kubernetes_service_account_access() {
        let session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = SecretAccessPocPlan::bootstrap();
        let classified = plan
            .classify
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
                mount_id: Some(23),
            })
            .expect("service account token should classify");
        let event = plan
            .evaluate
            .normalize_classified_access(&classified, &session);
        let input = PolicyInput::from_event(&event);

        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .expect("secret rego should evaluate");

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(
            decision.rule_id.as_deref(),
            Some("secret.mounted.kubernetes_service_account.denied")
        );
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(
            decision.reason.as_deref(),
            Some("kubernetes service account secret access is denied")
        );
    }

    #[test]
    fn allow_decision_is_reflected_in_secret_event_metadata() {
        let (event, decision, approval_request) = preview_secret_policy(sample_env_file_access());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(event.result.status, ResultStatus::Observed);
        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert_eq!(enriched.result.reason.as_deref(), Some("no matching rule"));
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Allow)
        );
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("default.allow")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.severity),
            Some(Severity::Low)
        );
        assert!(approval_request.is_none());
    }

    #[test]
    fn require_approval_decision_is_reflected_in_secret_event_metadata() {
        let (event, decision, approval_request) =
            preview_secret_policy(sample_brokered_secret_request());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(event.result.status, ResultStatus::Observed);
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched.result.reason.as_deref(),
            Some("brokered secret retrieval requires approval")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::RequireApproval)
        );
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("secret.brokered.requires_approval")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.severity),
            Some(Severity::High)
        );
        assert!(approval_request.is_some());
    }

    #[test]
    fn require_approval_pipeline_generates_pending_secret_approval_request() {
        let (observed, enriched, decision, approval_request) =
            preview_secret_policy_from_classified(sample_brokered_secret_request());
        let request = approval_request.expect("require_approval should yield approval request");

        assert_eq!(observed.result.status, ResultStatus::Observed);
        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("secret.brokered.requires_approval")
        );
        assert_eq!(
            request.approval_id,
            "apr_poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference"
        );
        assert_eq!(request.status, agenta_core::ApprovalStatus::Pending);
        assert_eq!(
            request.event_id.as_deref(),
            Some("poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference")
        );
        assert_eq!(
            request.request.action_class,
            agenta_core::ActionClass::Secret
        );
        assert_eq!(request.request.action_verb, "fetch");
        assert_eq!(
            request.request.target.as_deref(),
            Some("kv/prod/db/password")
        );
        assert_eq!(
            request.request.summary.as_deref(),
            Some("brokered secret retrieval requires approval")
        );
        assert_eq!(request.policy.rule_id, "secret.brokered.requires_approval");
        assert_eq!(
            request.policy.scope,
            Some(agenta_core::ApprovalScope::SingleAction)
        );
        assert_eq!(request.policy.ttl_seconds, Some(1200));
        assert_eq!(
            request.policy.reviewer_hint.as_deref(),
            Some("security-oncall")
        );
        assert_eq!(
            request
                .requester_context
                .as_ref()
                .and_then(|context| context.agent_reason.as_deref()),
            Some("brokered secret retrieval requires approval")
        );
        assert!(request.expires_at.is_some());
    }

    #[test]
    fn require_approval_secret_audit_record_contains_enriched_policy_metadata() {
        let (_, enriched, decision, approval_request) =
            preview_secret_policy_from_classified(sample_brokered_secret_request());
        let audit_record = serde_json::to_value(&enriched)
            .expect("enriched secret event should serialize as an audit record");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert!(approval_request.is_some());
        assert_eq!(audit_record["result"]["status"], json!("approval_required"));
        assert_eq!(
            audit_record["result"]["reason"],
            json!("brokered secret retrieval requires approval")
        );
        assert_eq!(
            audit_record["policy"]["decision"],
            json!("require_approval")
        );
        assert_eq!(
            audit_record["policy"]["rule_id"],
            json!("secret.brokered.requires_approval")
        );
        assert_eq!(audit_record["policy"]["severity"], json!("high"));
    }

    #[test]
    fn deny_decision_is_reflected_in_secret_event_metadata() {
        let (event, decision, approval_request) =
            preview_secret_policy(sample_kubernetes_service_account_access());
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(event.result.status, ResultStatus::Observed);
        assert_eq!(enriched.result.status, ResultStatus::Denied);
        assert_eq!(
            enriched.result.reason.as_deref(),
            Some("kubernetes service account secret access is denied")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.decision),
            Some(PolicyDecisionKind::Deny)
        );
        assert_eq!(
            enriched
                .policy
                .as_ref()
                .and_then(|policy| policy.rule_id.as_deref()),
            Some("secret.mounted.kubernetes_service_account.denied")
        );
        assert_eq!(
            enriched.policy.as_ref().and_then(|policy| policy.severity),
            Some(Severity::High)
        );
        assert!(approval_request.is_none());
    }

    fn preview_secret_policy(
        classified: ClassifiedSecretAccess,
    ) -> (
        agenta_core::EventEnvelope,
        agenta_core::PolicyDecision,
        Option<agenta_core::ApprovalRequest>,
    ) {
        let session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = SecretAccessPocPlan::bootstrap();
        let event = plan
            .evaluate
            .normalize_classified_access(&classified, &session);
        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&PolicyInput::from_event(&event))
            .expect("secret rego should evaluate");
        let approval_request = approval_request_from_decision(&event, &decision);

        (event, decision, approval_request)
    }

    fn preview_secret_policy_from_classified(
        classified: ClassifiedSecretAccess,
    ) -> (
        agenta_core::EventEnvelope,
        agenta_core::EventEnvelope,
        agenta_core::PolicyDecision,
        Option<agenta_core::ApprovalRequest>,
    ) {
        let session =
            agenta_core::SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = SecretAccessPocPlan::bootstrap();
        let observed = plan
            .evaluate
            .normalize_classified_access(&classified, &session);
        let decision = RegoPolicyEvaluator::secret_access_example()
            .evaluate(&PolicyInput::from_event(&observed))
            .expect("secret rego should evaluate");
        let enriched = apply_decision_to_event(&observed, &decision);
        let approval_request = approval_request_from_decision(&enriched, &decision);

        (observed, enriched, decision, approval_request)
    }

    fn sample_env_file_access() -> ClassifiedSecretAccess {
        let plan = SecretAccessPocPlan::bootstrap();
        plan.classify
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/workspace/.env.production".to_owned(),
                mount_id: Some(18),
            })
            .expect("env file should classify")
    }

    fn sample_brokered_secret_request() -> ClassifiedSecretAccess {
        let plan = SecretAccessPocPlan::bootstrap();
        plan.classify
            .classify_broker_request(&BrokeredSecretRequest {
                operation: "fetch".to_owned(),
                broker_id: "vault".to_owned(),
                broker_action: "read".to_owned(),
                secret_locator_hint: "kv/prod/db/password".to_owned(),
            })
    }

    fn sample_kubernetes_service_account_access() -> ClassifiedSecretAccess {
        let plan = SecretAccessPocPlan::bootstrap();
        plan.classify
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
                mount_id: Some(23),
            })
            .expect("service account token should classify")
    }
}
