use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{
    ClassificationBoundary, ClassifiedSecretAccess, RecordBoundary, SecretSignalSource,
};

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

    pub fn normalize_classified_access(
        &self,
        access: &ClassifiedSecretAccess,
        session: &SessionRecord,
    ) -> EventEnvelope {
        let taxonomy_kind = access.taxonomy.kind();
        let taxonomy_variant = access.taxonomy.variant_label();
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!(access.source.to_string()));
        attributes.insert("taxonomy_kind".to_owned(), json!(taxonomy_kind.to_string()));
        attributes.insert("taxonomy_variant".to_owned(), json!(taxonomy_variant));
        attributes.insert("locator_hint".to_owned(), json!(access.locator_hint));
        attributes.insert(
            "classifier_labels".to_owned(),
            json!(access.classifier_labels),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(access.classifier_reasons),
        );
        attributes.insert(
            "plaintext_retained".to_owned(),
            json!(access.plaintext_retained),
        );

        if let Some(path) = &access.path {
            attributes.insert("path".to_owned(), json!(path));
        }

        if let Some(mount_id) = access.mount_id {
            attributes.insert("mount_id".to_owned(), json!(mount_id));
        }

        if let Some(broker_id) = &access.broker_id {
            attributes.insert("broker_id".to_owned(), json!(broker_id));
        }

        if let Some(broker_action) = &access.broker_action {
            attributes.insert("broker_action".to_owned(), json!(broker_action));
        }

        EventEnvelope::new(
            format!(
                "poc_secret_access_{}_{}_{}_{}",
                access.source, access.operation, taxonomy_kind, taxonomy_variant
            ),
            EventType::SecretAccess,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Secret,
                verb: Some(access.operation.clone()),
                target: Some(access.locator_hint.clone()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd secret access PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(access.source),
        )
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

fn session_ref_from_record(session: &SessionRecord) -> SessionRef {
    SessionRef {
        session_id: session.session_id.clone(),
        agent_id: Some(session.agent_id.clone()),
        initiator_id: session.initiator_id.clone(),
        workspace_id: session
            .workspace
            .as_ref()
            .and_then(|workspace| workspace.workspace_id.clone()),
        policy_bundle_version: session.policy_bundle_version.clone(),
        environment: None,
    }
}

fn hostd_actor() -> Actor {
    Actor {
        kind: ActorKind::System,
        id: Some("agent-auditor-hostd".to_owned()),
        display_name: Some("agent-auditor-hostd PoC".to_owned()),
    }
}

fn source_info(source: SecretSignalSource) -> SourceInfo {
    SourceInfo {
        collector: collector_for_source(source),
        host_id: Some("hostd-poc".to_owned()),
        container_id: None,
        pod_uid: None,
        pid: None,
        ppid: None,
    }
}

fn collector_for_source(source: SecretSignalSource) -> CollectorKind {
    match source {
        SecretSignalSource::Fanotify => CollectorKind::Fanotify,
        SecretSignalSource::BrokerAdapter => CollectorKind::ControlPlane,
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, ActorKind, CollectorKind, EventType, ResultStatus, SessionRecord,
    };
    use serde_json::json;

    use super::EvaluatePlan;
    use crate::poc::secret::{
        classify::ClassifyPlan,
        contract::{BrokeredSecretRequest, SecretSignalSource, SecretTaxonomyKind},
    };

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
                "taxonomy_kind",
                "taxonomy_variant",
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

    #[test]
    fn normalize_path_classified_access_uses_agenta_core_secret_shape() {
        let classify = ClassifyPlan::default();
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let classified = classify
            .classify_path_access(&crate::poc::secret::contract::SecretPathAccess {
                operation: "read".to_owned(),
                path: "/home/agent/.ssh/id_ed25519".to_owned(),
                mount_id: Some(17),
            })
            .expect("ssh material should classify");
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");

        let envelope = evaluate.normalize_classified_access(&classified, &session);

        assert_eq!(
            envelope.event_id,
            "poc_secret_access_fanotify_read_secret_file_ssh_material"
        );
        assert_eq!(envelope.event_type, EventType::SecretAccess);
        assert_eq!(envelope.session.session_id, "sess_bootstrap_hostd");
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Secret);
        assert_eq!(envelope.action.verb.as_deref(), Some("read"));
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("/home/agent/.ssh/id_ed25519")
        );
        assert_eq!(
            envelope.action.attributes.get("source_kind"),
            Some(&json!("fanotify"))
        );
        assert_eq!(
            envelope.action.attributes.get("taxonomy_kind"),
            Some(&json!(SecretTaxonomyKind::SecretFile.to_string()))
        );
        assert_eq!(
            envelope.action.attributes.get("taxonomy_variant"),
            Some(&json!("ssh_material"))
        );
        assert_eq!(
            envelope.action.attributes.get("path"),
            Some(&json!("/home/agent/.ssh/id_ed25519"))
        );
        assert_eq!(envelope.action.attributes.get("mount_id"), Some(&json!(17)));
        assert_eq!(
            envelope.action.attributes.get("plaintext_retained"),
            Some(&json!(false))
        );
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(
            envelope.result.reason.as_deref(),
            Some("observed by hostd secret access PoC")
        );
        assert_eq!(envelope.source.collector, CollectorKind::Fanotify);
        assert_eq!(envelope.source.pid, None);
    }

    #[test]
    fn normalize_brokered_secret_request_uses_control_plane_source() {
        let classify = ClassifyPlan::default();
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let classified = classify.classify_broker_request(&BrokeredSecretRequest {
            operation: "fetch".to_owned(),
            broker_id: "vault".to_owned(),
            broker_action: "read".to_owned(),
            secret_locator_hint: "kv/prod/db/password".to_owned(),
        });
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");

        let envelope = evaluate.normalize_classified_access(&classified, &session);

        assert_eq!(
            envelope.event_id,
            "poc_secret_access_broker_adapter_fetch_brokered_secret_request_secret_reference"
        );
        assert_eq!(envelope.event_type, EventType::SecretAccess);
        assert_eq!(envelope.action.class, ActionClass::Secret);
        assert_eq!(envelope.action.verb.as_deref(), Some("fetch"));
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("kv/prod/db/password")
        );
        assert_eq!(
            envelope.action.attributes.get("source_kind"),
            Some(&json!("broker_adapter"))
        );
        assert_eq!(
            envelope.action.attributes.get("broker_id"),
            Some(&json!("vault"))
        );
        assert_eq!(
            envelope.action.attributes.get("broker_action"),
            Some(&json!("read"))
        );
        assert!(envelope.action.attributes.get("path").is_none());
        assert!(envelope.action.attributes.get("mount_id").is_none());
        assert_eq!(envelope.source.collector, CollectorKind::ControlPlane);
    }
}
