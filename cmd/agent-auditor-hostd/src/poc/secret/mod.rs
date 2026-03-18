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
    use super::SecretAccessPocPlan;
    use crate::poc::secret::contract::SecretSignalSource;

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
            plan.evaluate.classification_fields,
            vec![
                "source_kind",
                "operation",
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
}
