use super::contract::{ClassificationBoundary, RecordBoundary, SecretSignalSource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatePlan {
    pub sources: Vec<SecretSignalSource>,
    pub classification_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: RecordBoundary,
}

impl EvaluatePlan {
    pub fn from_classification_boundary(boundary: ClassificationBoundary) -> Self {
        Self {
            sources: boundary.sources.clone(),
            classification_fields: boundary.classification_fields,
            responsibilities: vec![
                "normalize classified secret candidates toward agenta-core secret access events",
                "bridge secret access inputs into agenta-policy without re-running classification heuristics",
                "project allow / deny / require_approval outcomes plus approval-request candidates for the record stage",
                "carry the redaction contract forward so downstream storage never needs plaintext secret values",
            ],
            stages: vec!["normalize", "policy", "approval_projection"],
            handoff: RecordBoundary {
                sources: boundary.sources,
                record_fields: vec![
                    "normalized_event",
                    "policy_decision",
                    "approval_request",
                    "redaction_status",
                ],
                redaction_contract: boundary.redaction_contract,
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

        format!(
            "sources={} classification_fields={} stages={}",
            sources,
            self.classification_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::EvaluatePlan;
    use crate::poc::secret::{classify::ClassifyPlan, contract::SecretSignalSource};

    #[test]
    fn evaluate_plan_threads_upstream_sources_and_fields() {
        let plan = EvaluatePlan::from_classification_boundary(ClassifyPlan::default().handoff());

        assert_eq!(
            plan.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.classification_fields,
            vec![
                "source_kind",
                "operation",
                "locator_hint",
                "classifier_labels",
                "classifier_reasons",
                "plaintext_retained",
            ]
        );
    }

    #[test]
    fn evaluate_plan_handoff_prepares_record_stage_inputs() {
        let plan = EvaluatePlan::from_classification_boundary(ClassifyPlan::default().handoff());
        let handoff = plan.handoff();

        assert_eq!(
            handoff.record_fields,
            vec![
                "normalized_event",
                "policy_decision",
                "approval_request",
                "redaction_status",
            ]
        );
        assert_eq!(
            handoff.redaction_contract,
            "plaintext secret material must not cross the classify boundary"
        );
    }
}
