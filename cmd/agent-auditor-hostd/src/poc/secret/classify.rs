use super::contract::{ClassificationBoundary, SecretSignalSource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub sources: Vec<SecretSignalSource>,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub stages: Vec<&'static str>,
    handoff: ClassificationBoundary,
}

impl Default for ClassifyPlan {
    fn default() -> Self {
        Self {
            sources: vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter,
            ],
            input_fields: vec![
                "source_kind",
                "operation",
                "path",
                "mount_id",
                "secret_locator_hint",
                "broker_id",
                "broker_action",
            ],
            responsibilities: vec![
                "accept path-like and broker-request signals from upstream collectors",
                "attach redaction-safe locator hints and classifier-owned rationale without retaining plaintext secret values",
                "preserve enough source context for policy without choosing policy outcomes",
                "handoff classified secret access candidates to evaluation without writing durable records",
            ],
            stages: vec!["ingest", "label", "handoff"],
            handoff: ClassificationBoundary {
                sources: vec![
                    SecretSignalSource::Fanotify,
                    SecretSignalSource::BrokerAdapter,
                ],
                classification_fields: vec![
                    "source_kind",
                    "operation",
                    "locator_hint",
                    "classifier_labels",
                    "classifier_reasons",
                    "plaintext_retained",
                ],
                redaction_contract: "plaintext secret material must not cross the classify boundary",
            },
        }
    }
}

impl ClassifyPlan {
    pub fn handoff(&self) -> ClassificationBoundary {
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
            "sources={} input_fields={} stages={}",
            sources,
            self.input_fields.join(","),
            self.stages.join("->")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ClassifyPlan;
    use crate::poc::secret::contract::SecretSignalSource;

    #[test]
    fn classify_plan_accepts_fanotify_and_broker_inputs() {
        let plan = ClassifyPlan::default();

        assert_eq!(
            plan.sources,
            vec![
                SecretSignalSource::Fanotify,
                SecretSignalSource::BrokerAdapter
            ]
        );
        assert_eq!(
            plan.input_fields,
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
    }

    #[test]
    fn classify_plan_handoff_is_redaction_safe() {
        let plan = ClassifyPlan::default();
        let handoff = plan.handoff();

        assert_eq!(
            handoff.classification_fields,
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
            handoff.redaction_contract,
            "plaintext secret material must not cross the classify boundary"
        );
    }
}
