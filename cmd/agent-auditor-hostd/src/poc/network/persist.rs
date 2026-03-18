use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use agenta_core::EventEnvelope;
use thiserror::Error;

const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("failed to prepare persistence root `{path}`: {source}")]
    PrepareRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to append record to `{path}`: {source}")]
    Append {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read record from `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize record for `{path}`: {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to deserialize record from `{path}`: {source}")]
    Deserialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistencePaths {
    pub root: PathBuf,
    pub audit_log: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPocStore {
    paths: PersistencePaths,
}

impl NetworkPocStore {
    pub fn bootstrap() -> Result<Self, PersistenceError> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-auditor-hostd-network-poc-store");
        Self::fresh(root)
    }

    pub fn fresh(root: impl Into<PathBuf>) -> Result<Self, PersistenceError> {
        let root = root.into();
        if root.exists() {
            fs::remove_dir_all(&root).map_err(|source| PersistenceError::PrepareRoot {
                path: root.clone(),
                source,
            })?;
        }
        fs::create_dir_all(&root).map_err(|source| PersistenceError::PrepareRoot {
            path: root.clone(),
            source,
        })?;

        Ok(Self {
            paths: PersistencePaths {
                audit_log: root.join(AUDIT_LOG_FILENAME),
                root,
            },
        })
    }

    pub fn paths(&self) -> &PersistencePaths {
        &self.paths
    }

    pub fn append_audit_record(&self, event: &EventEnvelope) -> Result<(), PersistenceError> {
        append_json_line(&self.paths.audit_log, event)
    }

    pub fn latest_audit_record(&self) -> Result<Option<EventEnvelope>, PersistenceError> {
        read_last_json_line(&self.paths.audit_log)
    }
}

fn append_json_line<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), PersistenceError> {
    let json = serde_json::to_string(value).map_err(|source| PersistenceError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| PersistenceError::Append {
            path: path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{json}").map_err(|source| PersistenceError::Append {
        path: path.to_path_buf(),
        source,
    })
}

fn read_last_json_line<T: for<'de> serde::Deserialize<'de>>(
    path: &Path,
) -> Result<Option<T>, PersistenceError> {
    if !path.exists() {
        return Ok(None);
    }

    let file =
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| PersistenceError::Read {
                path: path.to_path_buf(),
                source,
            })?;
    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader.lines() {
        let line = line.map_err(|source| PersistenceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if !line.trim().is_empty() {
            last = Some(line);
        }
    }

    match last {
        Some(line) => {
            serde_json::from_str(&line)
                .map(Some)
                .map_err(|source| PersistenceError::Deserialize {
                    path: path.to_path_buf(),
                    source,
                })
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, CollectorKind, EventEnvelope, EventType, JsonMap,
        PolicyDecisionKind, PolicyMetadata, ResultInfo, ResultStatus, SessionRef, Severity,
        SourceInfo,
    };
    use serde_json::json;

    use super::NetworkPocStore;

    #[test]
    fn store_appends_and_reads_back_network_audit_records() {
        let store = NetworkPocStore::fresh(unique_test_root()).expect("store should init");
        let event = fixture_event();

        store
            .append_audit_record(&event)
            .expect("audit record should append");

        assert_eq!(
            store
                .latest_audit_record()
                .expect("audit record should read"),
            Some(event)
        );
    }

    #[test]
    fn fresh_store_clears_old_network_records_before_bootstrap() {
        let root = unique_test_root();
        let first = NetworkPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = NetworkPocStore::fresh(&root).expect("second store should reset");

        assert_eq!(
            second
                .latest_audit_record()
                .expect("audit read should work"),
            None
        );
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-network-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("pid".to_owned(), json!(4242));
        attributes.insert("sock_fd".to_owned(), json!(7));
        attributes.insert("destination_ip".to_owned(), json!("93.184.216.34"));
        attributes.insert("destination_port".to_owned(), json!(443));
        attributes.insert("transport".to_owned(), json!("tcp"));
        attributes.insert("address_family".to_owned(), json!("inet"));
        attributes.insert("destination_scope".to_owned(), json!("public"));
        attributes.insert("domain_candidate".to_owned(), json!("example.com"));
        attributes.insert(
            "domain_attribution_source".to_owned(),
            json!("dns_answer_cache_exact_ip"),
        );

        let mut event = EventEnvelope::new(
            "evt_net_1",
            EventType::NetworkConnect,
            SessionRef {
                session_id: "sess_bootstrap_hostd".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            Action {
                class: ActionClass::Network,
                verb: Some("connect".to_owned()),
                target: Some("93.184.216.34:443".to_owned()),
                attributes,
            },
            ResultInfo {
                status: ResultStatus::Allowed,
                reason: Some("allowlisted public TLS destination".to_owned()),
                exit_code: None,
                error: None,
            },
            SourceInfo {
                collector: CollectorKind::Ebpf,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(4242),
                ppid: None,
            },
        );
        event.policy = Some(PolicyMetadata {
            decision: Some(PolicyDecisionKind::Allow),
            rule_id: Some("net.public.allowlisted_tls_domain".to_owned()),
            severity: Some(Severity::Low),
            explanation: Some("allowlisted public TLS destination".to_owned()),
        });
        event
    }
}
