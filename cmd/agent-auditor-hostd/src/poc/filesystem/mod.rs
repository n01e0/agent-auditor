pub mod classify;
pub mod contract;
pub mod emit;
pub mod persist;
pub mod watch;

use self::{classify::ClassifyPlan, emit::EmitPlan, watch::WatchPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemPocPlan {
    pub watch: WatchPlan,
    pub classify: ClassifyPlan,
    pub emit: EmitPlan,
}

impl FilesystemPocPlan {
    pub fn bootstrap() -> Self {
        let watch = WatchPlan::default();
        let classify = ClassifyPlan::from_watch_boundary(watch.handoff());
        let emit = EmitPlan::from_classification_boundary(classify.handoff());

        Self {
            watch,
            classify,
            emit,
        }
    }
}

#[cfg(test)]
mod tests {
    use agenta_core::{CollectorKind, PolicyDecisionKind, ResultStatus, SessionRecord, Severity};
    use agenta_policy::{
        PolicyCoverageContext, PolicyEvaluator, PolicyInput, RegoPolicyEvaluator,
        apply_decision_to_event, approval_request_from_decision,
    };
    use serde_json::json;

    use super::{FilesystemPocPlan, contract::FilesystemCollector};

    const FILESYSTEM_POLICY_ENTRYPOINT: &str = "data.agentauditor.authz.decision";
    const DENY_POLICY_MODULE: &str = r#"
        package agentauditor.authz

        decision := {
          "decision": "deny",
          "rule_id": "fs.deny.demo",
          "severity": "critical",
          "reason": "blocked for test",
          "approval": null,
          "tags": ["filesystem", "deny"]
        }
    "#;

    #[test]
    fn bootstrap_plan_keeps_watch_classify_and_emit_responsibilities_separate() {
        let plan = FilesystemPocPlan::bootstrap();

        assert!(
            plan.watch
                .responsibilities
                .iter()
                .any(|item| item.contains("fanotify instance"))
        );
        assert!(
            plan.watch
                .responsibilities
                .iter()
                .all(|item| !item.contains("classifier-owned tags"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .any(|item| item.contains("sensitive-path rules"))
        );
        assert!(
            plan.classify
                .responsibilities
                .iter()
                .all(|item| !item.contains("control-plane sinks"))
        );
        assert!(
            plan.emit
                .responsibilities
                .iter()
                .any(|item| item.contains("agenta-core event shapes"))
        );
        assert!(
            plan.emit
                .responsibilities
                .iter()
                .all(|item| !item.contains("fanotify instance"))
        );
    }

    #[test]
    fn bootstrap_plan_threads_fanotify_contracts_across_the_pipeline() {
        let plan = FilesystemPocPlan::bootstrap();

        assert_eq!(plan.watch.collector, FilesystemCollector::Fanotify);
        assert_eq!(plan.classify.collector, FilesystemCollector::Fanotify);
        assert_eq!(plan.emit.collector, FilesystemCollector::Fanotify);
        assert_eq!(
            plan.classify.input_fields,
            vec!["pid", "fd_path", "access_mask", "mount_id"]
        );
        assert_eq!(
            plan.emit.semantic_fields,
            vec![
                "path",
                "access_verb",
                "sensitivity_tags",
                "classifier_reason"
            ]
        );
        assert_eq!(
            plan.watch.handoff().raw_access_kinds,
            vec!["open", "access", "modify", "close_write"]
        );
        assert_eq!(plan.classify.handoff().emitted_verbs, vec!["read", "write"]);
    }

    #[test]
    fn fanotify_pipeline_requires_approval_for_sensitive_reads() {
        let event = normalized_filesystem_event("/home/agent/.ssh/id_ed25519", "read");
        let input = PolicyInput::from_event(&event);

        assert_eq!(event.source.collector, CollectorKind::Fanotify);
        assert_eq!(
            input.context.coverage,
            Some(PolicyCoverageContext {
                collector: Some("fanotify".to_owned()),
                enforce_capable: false,
            })
        );
        assert_eq!(
            event.action.attributes.get("sensitivity_tags"),
            Some(&json!(["ssh"]))
        );

        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("filesystem rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);
        let request = approval_request_from_decision(&enriched, &decision)
            .expect("sensitive read should produce approval request");

        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(decision.rule_id.as_deref(), Some("fs.sensitive.read"));
        assert_eq!(decision.severity, Some(Severity::High));
        assert_eq!(enriched.result.status, ResultStatus::ApprovalRequired);
        assert_eq!(
            enriched.result.reason.as_deref(),
            Some("sensitive path access requires approval")
        );
        assert_eq!(
            request.request.target.as_deref(),
            Some("/home/agent/.ssh/id_ed25519")
        );
    }

    #[test]
    fn fanotify_pipeline_allows_non_sensitive_reads_without_approval() {
        let event = normalized_filesystem_event("/workspace/src/main.rs", "read");
        let input = PolicyInput::from_event(&event);

        assert_eq!(
            event.action.attributes.get("sensitive"),
            Some(&json!(false))
        );

        let decision = RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .expect("filesystem rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("default.allow"));
        assert_eq!(decision.severity, Some(Severity::Low));
        assert_eq!(enriched.result.status, ResultStatus::Allowed);
        assert_eq!(enriched.result.reason.as_deref(), Some("no matching rule"));
        assert!(approval_request_from_decision(&enriched, &decision).is_none());
    }

    #[test]
    fn fanotify_pipeline_surfaces_deny_outcomes_from_policy_modules() {
        let event = normalized_filesystem_event("/tmp/blocked", "read");
        let input = PolicyInput::from_event(&event);
        let evaluator = RegoPolicyEvaluator::new(
            FILESYSTEM_POLICY_ENTRYPOINT,
            vec![("deny.rego".to_owned(), DENY_POLICY_MODULE.to_owned())],
        );

        let decision = evaluator
            .evaluate(&input)
            .expect("deny rego should evaluate");
        let enriched = apply_decision_to_event(&event, &decision);

        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("fs.deny.demo"));
        assert_eq!(decision.severity, Some(Severity::Critical));
        assert_eq!(enriched.result.status, ResultStatus::Denied);
        assert_eq!(enriched.result.reason.as_deref(), Some("blocked for test"));
        assert!(approval_request_from_decision(&enriched, &decision).is_none());
    }

    fn normalized_filesystem_event(path: &str, verb: &str) -> agenta_core::EventEnvelope {
        let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
        let plan = FilesystemPocPlan::bootstrap();
        let access = plan.classify.classify_access(4242, 17, verb, path);

        plan.emit.normalize_classified_access(&access, &session)
    }
}
