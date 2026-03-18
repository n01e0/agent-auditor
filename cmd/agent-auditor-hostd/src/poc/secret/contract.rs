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
