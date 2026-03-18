use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{ClassificationBoundary, ClassifiedNetworkConnect, NetworkCollector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitPlan {
    pub collector: NetworkCollector,
    pub semantic_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub sinks: Vec<&'static str>,
    pub stages: Vec<&'static str>,
}

impl EmitPlan {
    pub fn from_classification_boundary(boundary: ClassificationBoundary) -> Self {
        Self {
            collector: boundary.collector,
            semantic_fields: boundary.semantic_fields,
            responsibilities: vec![
                "normalize classified outbound-connect candidates toward agenta-core event shapes",
                "fan out network connect events to logs and later control-plane sinks",
                "preserve destination classifier metadata for downstream policy, audit, and approval stages",
            ],
            sinks: vec!["structured_log", "control_plane"],
            stages: vec!["normalize", "publish"],
        }
    }

    pub fn normalize_classified_connect(
        &self,
        connect: &ClassifiedNetworkConnect,
        session: &SessionRecord,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("pid".to_owned(), json!(connect.pid));
        attributes.insert("sock_fd".to_owned(), json!(connect.sock_fd));
        attributes.insert("destination_ip".to_owned(), json!(connect.destination_ip));
        attributes.insert(
            "destination_port".to_owned(),
            json!(connect.destination_port),
        );
        attributes.insert("transport".to_owned(), json!(connect.transport));
        attributes.insert("address_family".to_owned(), json!(connect.address_family));
        attributes.insert(
            "destination_scope".to_owned(),
            json!(connect.destination_scope.to_string()),
        );
        attributes.insert(
            "domain_candidate".to_owned(),
            json!(connect.domain_candidate),
        );
        attributes.insert(
            "domain_attribution_source".to_owned(),
            json!(connect.domain_attribution_source),
        );

        EventEnvelope::new(
            format!(
                "poc_network_connect_{}_{}_{}",
                connect.pid, connect.sock_fd, connect.transport
            ),
            EventType::NetworkConnect,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Network,
                verb: Some("connect".to_owned()),
                target: Some(format!(
                    "{}:{}",
                    connect.destination_ip, connect.destination_port
                )),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd network PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(connect.pid),
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} semantic_fields={} stages={} sinks={}",
            self.collector,
            self.semantic_fields.join(","),
            self.stages.join("->"),
            self.sinks.join(",")
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

fn source_info(pid: u32) -> SourceInfo {
    SourceInfo {
        collector: CollectorKind::Ebpf,
        host_id: Some("hostd-poc".to_owned()),
        container_id: None,
        pod_uid: None,
        pid: Some(pid as i32),
        ppid: None,
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{
        ActionClass, ActorKind, CollectorKind, EventType, ResultStatus, SessionRecord,
    };
    use serde_json::json;

    use super::EmitPlan;
    use crate::poc::network::{
        classify::ClassifyPlan,
        contract::{DestinationScope, ObserveBoundary},
        observe::ObservePlan,
    };

    #[test]
    fn normalize_classified_connect_uses_agenta_core_network_shape() {
        let observe = ObservePlan::default();
        let delivered = observe
            .preview_connect_delivery()
            .expect("fixture connect delivery should succeed");
        let classify = ClassifyPlan::from_observe_boundary(ObserveBoundary::outbound_connect_poc());
        let emit = EmitPlan::from_classification_boundary(classify.handoff());
        let connect = classify.classify_connect(&delivered.event);
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");

        let envelope = emit.normalize_classified_connect(&connect, &session);

        assert_eq!(envelope.event_id, "poc_network_connect_4242_7_tcp");
        assert_eq!(envelope.event_type, EventType::NetworkConnect);
        assert_eq!(envelope.session.session_id, "sess_bootstrap_hostd");
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Network);
        assert_eq!(envelope.action.verb.as_deref(), Some("connect"));
        assert_eq!(envelope.action.target.as_deref(), Some("93.184.216.34:443"));
        assert_eq!(
            envelope.action.attributes.get("destination_ip"),
            Some(&json!("93.184.216.34"))
        );
        assert_eq!(
            envelope.action.attributes.get("destination_port"),
            Some(&json!(443))
        );
        assert_eq!(
            envelope.action.attributes.get("transport"),
            Some(&json!("tcp"))
        );
        assert_eq!(
            envelope.action.attributes.get("address_family"),
            Some(&json!("inet"))
        );
        assert_eq!(
            envelope.action.attributes.get("destination_scope"),
            Some(&json!(DestinationScope::Public.to_string()))
        );
        assert_eq!(
            envelope.action.attributes.get("domain_candidate"),
            Some(&json!("example.com"))
        );
        assert_eq!(
            envelope.action.attributes.get("domain_attribution_source"),
            Some(&json!("dns_answer_cache_exact_ip"))
        );
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(
            envelope.result.reason.as_deref(),
            Some("observed by hostd network PoC")
        );
        assert_eq!(envelope.source.collector, CollectorKind::Ebpf);
        assert_eq!(envelope.source.pid, Some(4242));
        assert_eq!(envelope.source.ppid, None);
    }
}
