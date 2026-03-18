use agenta_core::{
    Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
    ResultInfo, ResultStatus, SessionRecord, SessionRef, SourceInfo,
};
use serde_json::json;

use super::contract::{ClassificationBoundary, ClassifiedFilesystemAccess, FilesystemCollector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitPlan {
    pub collector: FilesystemCollector,
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
                "normalize classified filesystem access candidates toward agenta-core event shapes",
                "fan out filesystem events to logs and later control-plane sinks",
                "preserve classifier metadata for downstream policy, audit, and approval stages",
            ],
            sinks: vec!["structured_log", "control_plane"],
            stages: vec!["normalize", "publish"],
        }
    }

    pub fn normalize_classified_access(
        &self,
        access: &ClassifiedFilesystemAccess,
        session: &SessionRecord,
    ) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("pid".to_owned(), json!(access.pid));
        attributes.insert("mount_id".to_owned(), json!(access.mount_id));
        attributes.insert("path".to_owned(), json!(access.path));
        attributes.insert("access_verb".to_owned(), json!(access.access_verb));
        attributes.insert(
            "sensitivity_tags".to_owned(),
            json!(access.classification.tags()),
        );
        attributes.insert(
            "classifier_reason".to_owned(),
            json!(access.classification.reasons()),
        );
        attributes.insert(
            "sensitive".to_owned(),
            json!(access.classification.is_sensitive()),
        );

        EventEnvelope::new(
            format!(
                "poc_filesystem_access_{}_{}_{}",
                access.pid, access.mount_id, access.access_verb
            ),
            EventType::FilesystemAccess,
            session_ref_from_record(session),
            hostd_actor(),
            Action {
                class: ActionClass::Filesystem,
                verb: Some(access.access_verb.clone()),
                target: Some(access.path.clone()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("observed by hostd filesystem PoC".to_owned()),
                exit_code: None,
                error: None,
            },
            source_info(access.pid),
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
        collector: CollectorKind::Fanotify,
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
    use crate::poc::filesystem::{
        classify::ClassifyPlan,
        contract::{FilesystemCollector, WatchBoundary},
    };

    #[test]
    fn normalize_classified_access_uses_agenta_core_filesystem_shape() {
        let classify = ClassifyPlan::from_watch_boundary(WatchBoundary::fanotify_poc());
        let emit = EmitPlan::from_classification_boundary(classify.handoff());
        let access = classify.classify_access(4242, 17, "read", "/home/agent/.ssh/id_ed25519");
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");

        let envelope = emit.normalize_classified_access(&access, &session);

        assert_eq!(envelope.event_id, "poc_filesystem_access_4242_17_read");
        assert_eq!(envelope.event_type, EventType::FilesystemAccess);
        assert_eq!(envelope.session.session_id, "sess_bootstrap_hostd");
        assert_eq!(envelope.actor.kind, ActorKind::System);
        assert_eq!(envelope.action.class, ActionClass::Filesystem);
        assert_eq!(envelope.action.verb.as_deref(), Some("read"));
        assert_eq!(
            envelope.action.target.as_deref(),
            Some("/home/agent/.ssh/id_ed25519")
        );
        assert_eq!(
            envelope.action.attributes.get("sensitivity_tags"),
            Some(&json!(["ssh"]))
        );
        assert_eq!(
            envelope.action.attributes.get("classifier_reason"),
            Some(&json!(["path is inside a .ssh directory"]))
        );
        assert_eq!(
            envelope.action.attributes.get("sensitive"),
            Some(&json!(true))
        );
        assert_eq!(envelope.result.status, ResultStatus::Observed);
        assert_eq!(
            envelope.result.reason.as_deref(),
            Some("observed by hostd filesystem PoC")
        );
        assert_eq!(envelope.source.collector, CollectorKind::Fanotify);
        assert_eq!(envelope.source.pid, Some(4242));
        assert_eq!(envelope.source.ppid, None);
    }

    #[test]
    fn filesystem_log_line_surfaces_classifier_metadata() {
        let classify = ClassifyPlan::from_watch_boundary(WatchBoundary::fanotify_poc());
        let access = classify.preview_sensitive_access();

        assert_eq!(
            access.log_line(FilesystemCollector::Fanotify),
            "event=filesystem.access collector=fanotify pid=4242 mount_id=17 verb=read target=/home/agent/.ssh/id_ed25519 sensitive=true tags=ssh reasons=path is inside a .ssh directory"
        );
    }
}
