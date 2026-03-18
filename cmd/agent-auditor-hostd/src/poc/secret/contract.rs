use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSignalSource {
    Fanotify,
    BrokerAdapter,
}

impl fmt::Display for SecretSignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Fanotify => "fanotify",
            Self::BrokerAdapter => "broker_adapter",
        };

        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretTaxonomyKind {
    SecretFile,
    MountedSecret,
    BrokeredSecretRequest,
}

impl SecretTaxonomyKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::SecretFile => "secret_file",
            Self::MountedSecret => "mounted_secret",
            Self::BrokeredSecretRequest => "brokered_secret_request",
        }
    }
}

impl fmt::Display for SecretTaxonomyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFileKind {
    SshMaterial,
    EnvFile,
}

impl SecretFileKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::SshMaterial => "ssh_material",
            Self::EnvFile => "env_file",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::SshMaterial => "path is inside a .ssh directory",
            Self::EnvFile => "path targets a .env file or variant",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountedSecretKind {
    ContainerRuntime,
    KubernetesServiceAccount,
}

impl MountedSecretKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ContainerRuntime => "container_runtime_secret",
            Self::KubernetesServiceAccount => "kubernetes_service_account",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ContainerRuntime => "path is inside a mounted secret directory",
            Self::KubernetesServiceAccount => {
                "path targets a Kubernetes service account mounted secret"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokeredSecretRequestKind {
    SecretReference,
}

impl BrokeredSecretRequestKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::SecretReference => "secret_reference",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::SecretReference => {
                "request came from a broker adapter with a redaction-safe locator hint"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretTaxonomy {
    SecretFile(SecretFileKind),
    MountedSecret(MountedSecretKind),
    BrokeredSecretRequest(BrokeredSecretRequestKind),
}

impl SecretTaxonomy {
    pub fn kind(self) -> SecretTaxonomyKind {
        match self {
            Self::SecretFile(_) => SecretTaxonomyKind::SecretFile,
            Self::MountedSecret(_) => SecretTaxonomyKind::MountedSecret,
            Self::BrokeredSecretRequest(_) => SecretTaxonomyKind::BrokeredSecretRequest,
        }
    }

    pub fn variant_label(self) -> &'static str {
        match self {
            Self::SecretFile(kind) => kind.label(),
            Self::MountedSecret(kind) => kind.label(),
            Self::BrokeredSecretRequest(kind) => kind.label(),
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::SecretFile(kind) => kind.reason(),
            Self::MountedSecret(kind) => kind.reason(),
            Self::BrokeredSecretRequest(kind) => kind.reason(),
        }
    }

    pub fn classifier_labels(self) -> Vec<&'static str> {
        vec![self.kind().label(), self.variant_label()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretPathAccess {
    pub operation: String,
    pub path: String,
    pub mount_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokeredSecretRequest {
    pub operation: String,
    pub broker_id: String,
    pub broker_action: String,
    pub secret_locator_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSignal {
    Path(SecretPathAccess),
    Broker(BrokeredSecretRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedSecretAccess {
    pub source: SecretSignalSource,
    pub operation: String,
    pub taxonomy: SecretTaxonomy,
    pub locator_hint: String,
    pub path: Option<String>,
    pub mount_id: Option<u32>,
    pub broker_id: Option<String>,
    pub broker_action: Option<String>,
    pub classifier_labels: Vec<&'static str>,
    pub classifier_reasons: Vec<&'static str>,
    pub plaintext_retained: bool,
}

impl ClassifiedSecretAccess {
    pub fn log_line(&self) -> String {
        format!(
            "event=secret.access source={} operation={} taxonomy_kind={} taxonomy_variant={} locator_hint={} plaintext_retained={}",
            self.source,
            self.operation,
            self.taxonomy.kind(),
            self.taxonomy.variant_label(),
            self.locator_hint,
            self.plaintext_retained,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationBoundary {
    pub sources: Vec<SecretSignalSource>,
    pub classification_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBoundary {
    pub sources: Vec<SecretSignalSource>,
    pub record_fields: Vec<&'static str>,
    pub redaction_contract: &'static str,
}
