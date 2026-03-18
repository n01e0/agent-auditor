use super::contract::{
    ClassificationBoundary, FilesystemCollector, SensitivePathClassification, SensitivePathKind,
    SensitivePathMatch, WatchBoundary,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathClassifier {
    kinds: Vec<SensitivePathKind>,
}

impl Default for SensitivePathClassifier {
    fn default() -> Self {
        Self {
            kinds: vec![
                SensitivePathKind::SshMaterial,
                SensitivePathKind::EnvFile,
                SensitivePathKind::MountedSecret,
            ],
        }
    }
}

impl SensitivePathClassifier {
    pub fn classify(&self, path: impl Into<String>) -> SensitivePathClassification {
        let path = path.into();
        let mut matches = Vec::new();

        for kind in &self.kinds {
            if kind.matches(&path) {
                matches.push(SensitivePathMatch::new(*kind));
            }
        }

        SensitivePathClassification { path, matches }
    }

    pub fn configured_kinds(&self) -> &[SensitivePathKind] {
        &self.kinds
    }
}

impl SensitivePathKind {
    pub fn matches(self, path: &str) -> bool {
        match self {
            Self::SshMaterial => matches_ssh_material(path),
            Self::EnvFile => matches_env_file(path),
            Self::MountedSecret => matches_mounted_secret(path),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub collector: FilesystemCollector,
    pub input_fields: Vec<&'static str>,
    pub responsibilities: Vec<&'static str>,
    pub classifier: SensitivePathClassifier,
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
            classifier: SensitivePathClassifier::default(),
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

    pub fn classify(&self, path: impl Into<String>) -> SensitivePathClassification {
        self.classifier.classify(path)
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

fn matches_ssh_material(path: &str) -> bool {
    path_components(path).any(|component| component == ".ssh")
}

fn matches_env_file(path: &str) -> bool {
    let basename = basename(path);
    basename == ".env" || basename.starts_with(".env.")
}

fn matches_mounted_secret(path: &str) -> bool {
    const SECRET_PREFIXES: [&str; 2] = ["/var/run/secrets", "/run/secrets"];

    SECRET_PREFIXES.iter().any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }) || path.contains("/kubernetes.io/serviceaccount/")
}

fn path_components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|component| !component.is_empty())
}

fn basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|component| !component.is_empty())
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::{
        ClassifyPlan, SensitivePathClassifier, basename, matches_env_file, matches_mounted_secret,
        matches_ssh_material,
    };
    use crate::poc::filesystem::contract::{SensitivePathKind, WatchBoundary};

    #[test]
    fn classifier_marks_ssh_material_as_sensitive() {
        let classification =
            SensitivePathClassifier::default().classify("/home/agent/.ssh/id_ed25519");

        assert!(classification.is_sensitive());
        assert_eq!(classification.tags(), vec!["ssh"]);
        assert_eq!(
            classification.reasons(),
            vec!["path is inside a .ssh directory"]
        );
    }

    #[test]
    fn classifier_marks_env_files_as_sensitive() {
        let classification =
            SensitivePathClassifier::default().classify("/workspace/.env.production");

        assert!(classification.is_sensitive());
        assert_eq!(classification.tags(), vec!["env_file"]);
        assert_eq!(
            classification.reasons(),
            vec!["path targets a .env file or variant"]
        );
    }

    #[test]
    fn classifier_marks_mounted_secrets_as_sensitive() {
        let classification = SensitivePathClassifier::default()
            .classify("/var/run/secrets/kubernetes.io/serviceaccount/token");

        assert!(classification.is_sensitive());
        assert_eq!(classification.tags(), vec!["mounted_secret"]);
        assert_eq!(
            classification.reasons(),
            vec!["path is inside a mounted secret directory"]
        );
    }

    #[test]
    fn classifier_leaves_non_sensitive_paths_unmatched() {
        let classification = SensitivePathClassifier::default().classify("/workspace/src/main.rs");

        assert!(!classification.is_sensitive());
        assert!(classification.tags().is_empty());
        assert!(classification.reasons().is_empty());
    }

    #[test]
    fn classify_plan_exposes_provisional_sensitive_target_kinds() {
        let plan = ClassifyPlan::from_watch_boundary(WatchBoundary::fanotify_poc());

        assert_eq!(
            plan.classifier.configured_kinds(),
            &[
                SensitivePathKind::SshMaterial,
                SensitivePathKind::EnvFile,
                SensitivePathKind::MountedSecret,
            ]
        );
        assert!(plan.classify("/run/secrets/demo/key").is_sensitive());
    }

    #[test]
    fn ssh_matching_requires_a_dot_ssh_path_component() {
        assert!(matches_ssh_material("/tmp/.ssh/config"));
        assert!(!matches_ssh_material("/tmp/.ssh-config"));
    }

    #[test]
    fn env_matching_supports_dot_env_variants_only() {
        assert!(matches_env_file("/workspace/.env"));
        assert!(matches_env_file("/workspace/.env.local"));
        assert!(!matches_env_file("/workspace/.envrc"));
        assert!(!matches_env_file("/workspace/config.env"));
    }

    #[test]
    fn mounted_secret_matching_tracks_current_prefixes_and_service_account_paths() {
        assert!(matches_mounted_secret("/run/secrets"));
        assert!(matches_mounted_secret("/run/secrets/db/password"));
        assert!(matches_mounted_secret(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ));
        assert!(!matches_mounted_secret("/var/run/secretless/token"));
    }

    #[test]
    fn basename_ignores_trailing_slashes() {
        assert_eq!(basename("/workspace/.env/"), ".env");
    }
}
