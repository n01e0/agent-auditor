use super::contract::{
    BrokeredSecretRequest, BrokeredSecretRequestKind, ClassificationBoundary,
    ClassifiedSecretAccess, MountedSecretKind, SecretFileKind, SecretPathAccess, SecretSignal,
    SecretSignalSource, SecretTaxonomy, SecretTaxonomyKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyPlan {
    pub sources: Vec<SecretSignalSource>,
    pub input_fields: Vec<&'static str>,
    pub taxonomy_kinds: Vec<SecretTaxonomyKind>,
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
            taxonomy_kinds: vec![
                SecretTaxonomyKind::SecretFile,
                SecretTaxonomyKind::MountedSecret,
                SecretTaxonomyKind::BrokeredSecretRequest,
            ],
            responsibilities: vec![
                "accept path-like and broker-request signals from upstream collectors",
                "identify secret file, mounted secret, and brokered secret request taxonomy without retaining plaintext secret values",
                "attach redaction-safe locator hints and classifier-owned rationale without retaining plaintext secret values",
                "preserve enough source context for policy without choosing policy outcomes",
                "handoff classified secret access candidates to evaluation without writing durable records",
            ],
            stages: vec!["ingest", "taxonomy", "label", "handoff"],
            handoff: ClassificationBoundary {
                sources: vec![
                    SecretSignalSource::Fanotify,
                    SecretSignalSource::BrokerAdapter,
                ],
                classification_fields: vec![
                    "source_kind",
                    "operation",
                    "taxonomy_kind",
                    "taxonomy_variant",
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

    pub fn classify_signal(&self, signal: &SecretSignal) -> Option<ClassifiedSecretAccess> {
        match signal {
            SecretSignal::Path(access) => self.classify_path_access(access),
            SecretSignal::Broker(request) => Some(self.classify_broker_request(request)),
        }
    }

    pub fn classify_path_access(
        &self,
        access: &SecretPathAccess,
    ) -> Option<ClassifiedSecretAccess> {
        let taxonomy = classify_path_taxonomy(&access.path)?;

        Some(ClassifiedSecretAccess {
            source: SecretSignalSource::Fanotify,
            operation: access.operation.clone(),
            taxonomy,
            locator_hint: access.path.clone(),
            path: Some(access.path.clone()),
            mount_id: access.mount_id,
            broker_id: None,
            broker_action: None,
            classifier_labels: taxonomy.classifier_labels(),
            classifier_reasons: vec![taxonomy.reason()],
            plaintext_retained: false,
        })
    }

    pub fn classify_broker_request(
        &self,
        request: &BrokeredSecretRequest,
    ) -> ClassifiedSecretAccess {
        let taxonomy =
            SecretTaxonomy::BrokeredSecretRequest(BrokeredSecretRequestKind::SecretReference);
        let locator_hint = if request.secret_locator_hint.is_empty() {
            format!("{}:{}", request.broker_id, request.broker_action)
        } else {
            request.secret_locator_hint.clone()
        };

        ClassifiedSecretAccess {
            source: SecretSignalSource::BrokerAdapter,
            operation: request.operation.clone(),
            taxonomy,
            locator_hint,
            path: None,
            mount_id: None,
            broker_id: Some(request.broker_id.clone()),
            broker_action: Some(request.broker_action.clone()),
            classifier_labels: taxonomy.classifier_labels(),
            classifier_reasons: vec![taxonomy.reason()],
            plaintext_retained: false,
        }
    }

    pub fn summary(&self) -> String {
        let sources = self
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let taxonomy = self
            .taxonomy_kinds
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "sources={} input_fields={} taxonomy={} stages={}",
            sources,
            self.input_fields.join(","),
            taxonomy,
            self.stages.join("->")
        )
    }
}

fn classify_path_taxonomy(path: &str) -> Option<SecretTaxonomy> {
    if matches_kubernetes_service_account(path) {
        return Some(SecretTaxonomy::MountedSecret(
            MountedSecretKind::KubernetesServiceAccount,
        ));
    }

    if matches_mounted_secret(path) {
        return Some(SecretTaxonomy::MountedSecret(
            MountedSecretKind::ContainerRuntime,
        ));
    }

    if matches_ssh_material(path) {
        return Some(SecretTaxonomy::SecretFile(SecretFileKind::SshMaterial));
    }

    if matches_env_file(path) {
        return Some(SecretTaxonomy::SecretFile(SecretFileKind::EnvFile));
    }

    None
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
    })
}

fn matches_kubernetes_service_account(path: &str) -> bool {
    path.contains("/kubernetes.io/serviceaccount/")
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
        BrokeredSecretRequest, ClassifyPlan, SecretPathAccess, SecretSignal, basename,
        matches_env_file, matches_kubernetes_service_account, matches_mounted_secret,
        matches_ssh_material,
    };
    use crate::poc::secret::contract::{
        BrokeredSecretRequestKind, MountedSecretKind, SecretFileKind, SecretSignalSource,
        SecretTaxonomy, SecretTaxonomyKind,
    };

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
            plan.taxonomy_kinds,
            vec![
                SecretTaxonomyKind::SecretFile,
                SecretTaxonomyKind::MountedSecret,
                SecretTaxonomyKind::BrokeredSecretRequest,
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
                "taxonomy_kind",
                "taxonomy_variant",
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

    #[test]
    fn classify_path_access_identifies_secret_file_taxonomy() {
        let plan = ClassifyPlan::default();
        let classified = plan
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/home/agent/.ssh/id_ed25519".to_owned(),
                mount_id: Some(17),
            })
            .expect("ssh material should classify as secret file");

        assert_eq!(classified.source, SecretSignalSource::Fanotify);
        assert_eq!(classified.operation, "read");
        assert_eq!(
            classified.taxonomy,
            SecretTaxonomy::SecretFile(SecretFileKind::SshMaterial)
        );
        assert_eq!(classified.locator_hint, "/home/agent/.ssh/id_ed25519");
        assert_eq!(
            classified.path.as_deref(),
            Some("/home/agent/.ssh/id_ed25519")
        );
        assert_eq!(classified.mount_id, Some(17));
        assert_eq!(
            classified.classifier_labels,
            vec!["secret_file", "ssh_material"]
        );
        assert_eq!(
            classified.classifier_reasons,
            vec!["path is inside a .ssh directory"]
        );
        assert!(!classified.plaintext_retained);
    }

    #[test]
    fn classify_path_access_identifies_mounted_secret_taxonomy() {
        let plan = ClassifyPlan::default();
        let classified = plan
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
                mount_id: Some(23),
            })
            .expect("service account token should classify as mounted secret");

        assert_eq!(
            classified.taxonomy,
            SecretTaxonomy::MountedSecret(MountedSecretKind::KubernetesServiceAccount)
        );
        assert_eq!(classified.classifier_labels[0], "mounted_secret");
        assert_eq!(
            classified.classifier_labels[1],
            "kubernetes_service_account"
        );
        assert_eq!(
            classified.classifier_reasons,
            vec!["path targets a Kubernetes service account mounted secret"]
        );
    }

    #[test]
    fn mounted_secret_taxonomy_takes_precedence_over_secret_file_heuristics() {
        let plan = ClassifyPlan::default();
        let classified = plan
            .classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/run/secrets/.env".to_owned(),
                mount_id: Some(99),
            })
            .expect("mounted secret path should classify");

        assert_eq!(
            classified.taxonomy,
            SecretTaxonomy::MountedSecret(MountedSecretKind::ContainerRuntime)
        );
    }

    #[test]
    fn classify_broker_request_identifies_brokered_secret_taxonomy() {
        let plan = ClassifyPlan::default();
        let classified = plan.classify_broker_request(&BrokeredSecretRequest {
            operation: "fetch".to_owned(),
            broker_id: "vault".to_owned(),
            broker_action: "read".to_owned(),
            secret_locator_hint: "kv/prod/db/password".to_owned(),
        });

        assert_eq!(classified.source, SecretSignalSource::BrokerAdapter);
        assert_eq!(classified.operation, "fetch");
        assert_eq!(
            classified.taxonomy,
            SecretTaxonomy::BrokeredSecretRequest(BrokeredSecretRequestKind::SecretReference)
        );
        assert_eq!(classified.locator_hint, "kv/prod/db/password");
        assert_eq!(classified.broker_id.as_deref(), Some("vault"));
        assert_eq!(classified.broker_action.as_deref(), Some("read"));
        assert_eq!(
            classified.classifier_labels,
            vec!["brokered_secret_request", "secret_reference"]
        );
        assert_eq!(
            classified.classifier_reasons,
            vec!["request came from a broker adapter with a redaction-safe locator hint"]
        );
        assert!(!classified.plaintext_retained);
    }

    #[test]
    fn classify_signal_routes_path_and_broker_variants() {
        let plan = ClassifyPlan::default();
        let from_path = plan.classify_signal(&SecretSignal::Path(SecretPathAccess {
            operation: "read".to_owned(),
            path: "/workspace/.env.production".to_owned(),
            mount_id: Some(7),
        }));
        let from_broker = plan.classify_signal(&SecretSignal::Broker(BrokeredSecretRequest {
            operation: "fetch".to_owned(),
            broker_id: "aws-secretsmanager".to_owned(),
            broker_action: "get-secret-value".to_owned(),
            secret_locator_hint: "prod/app/api-key".to_owned(),
        }));

        assert_eq!(
            from_path.as_ref().map(|classified| classified.taxonomy),
            Some(SecretTaxonomy::SecretFile(SecretFileKind::EnvFile))
        );
        assert_eq!(
            from_broker.as_ref().map(|classified| classified.taxonomy),
            Some(SecretTaxonomy::BrokeredSecretRequest(
                BrokeredSecretRequestKind::SecretReference,
            ))
        );
    }

    #[test]
    fn classify_path_access_returns_none_for_non_secret_paths() {
        let plan = ClassifyPlan::default();

        assert!(
            plan.classify_path_access(&SecretPathAccess {
                operation: "read".to_owned(),
                path: "/workspace/src/main.rs".to_owned(),
                mount_id: Some(3),
            })
            .is_none()
        );
    }

    #[test]
    fn broker_request_uses_broker_and_action_fallback_when_locator_hint_missing() {
        let plan = ClassifyPlan::default();
        let classified = plan.classify_broker_request(&BrokeredSecretRequest {
            operation: "fetch".to_owned(),
            broker_id: "vault".to_owned(),
            broker_action: "read".to_owned(),
            secret_locator_hint: String::new(),
        });

        assert_eq!(classified.locator_hint, "vault:read");
    }

    #[test]
    fn classified_secret_log_line_surfaces_taxonomy() {
        let plan = ClassifyPlan::default();
        let classified = plan.classify_broker_request(&BrokeredSecretRequest {
            operation: "fetch".to_owned(),
            broker_id: "vault".to_owned(),
            broker_action: "read".to_owned(),
            secret_locator_hint: "kv/prod/db/password".to_owned(),
        });

        assert_eq!(
            classified.log_line(),
            "event=secret.access source=broker_adapter operation=fetch taxonomy_kind=brokered_secret_request taxonomy_variant=secret_reference locator_hint=kv/prod/db/password plaintext_retained=false"
        );
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
    fn mounted_secret_matching_tracks_current_prefixes() {
        assert!(matches_mounted_secret("/run/secrets"));
        assert!(matches_mounted_secret("/run/secrets/db/password"));
        assert!(!matches_mounted_secret("/var/run/secretless/token"));
    }

    #[test]
    fn kubernetes_service_account_matching_is_more_specific() {
        assert!(matches_kubernetes_service_account(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ));
        assert!(!matches_kubernetes_service_account("/run/secrets/demo/key"));
    }

    #[test]
    fn basename_ignores_trailing_slashes() {
        assert_eq!(basename("/workspace/.env/"), ".env");
    }
}
