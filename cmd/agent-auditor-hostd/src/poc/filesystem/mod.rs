pub mod classify;
pub mod contract;
pub mod emit;
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
    use super::{FilesystemPocPlan, contract::FilesystemCollector};

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
}
