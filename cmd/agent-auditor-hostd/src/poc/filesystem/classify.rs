use super::contract::{ClassificationBoundary, WatchBoundary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub collector: super::contract::FilesystemCollector,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    handoff: ClassificationBoundary,
}

impl ClassifyPlan {
    pub fn from_watch_boundary(boundary: WatchBoundary) -> Self {
        Self {
            collector: boundary.collector,
            input_fields: boundary.raw_fields,
            responsibilities: vec![
                "translate raw fanotify access masks into provisional read / write intent",
                "match accessed paths against hostd sensitive-path rules and mounted-secret heuristics",
                "attach classifier-owned tags and rationale for downstream policy evaluation",
                "handoff semantic filesystem access candidates without normalizing or publishing them",
            ],
            handoff: ClassificationBoundary {
                collector: boundary.collector,
                semantic_fields: vec![
                    "path",
                    "access_verb",
                    "sensitivity_tags",
                    "classifier_reason",
                ],
                emitted_verbs: vec!["read", "write"],
            },
        }
    }

    pub fn handoff(&self) -> ClassificationBoundary {
        self.handoff.clone()
    }

    pub fn summary(&self) -> String {
        format!(
            "collector={} input_fields={} semantic_fields={} verbs={}",
            self.collector,
            self.input_fields.join(","),
            self.handoff.semantic_fields.join(","),
            self.handoff.emitted_verbs.join(",")
        )
    }
}
