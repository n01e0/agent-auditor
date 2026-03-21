use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use agenta_core::{ApprovalRequest, EventEnvelope};
use thiserror::Error;

const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";
const APPROVAL_LOG_FILENAME: &str = "approval-requests.jsonl";

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
    pub approval_log: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubPocStore {
    paths: PersistencePaths,
}

impl GitHubPocStore {
    pub fn bootstrap() -> Result<Self, PersistenceError> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-auditor-hostd-github-poc-store");
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
                approval_log: root.join(APPROVAL_LOG_FILENAME),
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

    pub fn append_approval_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<(), PersistenceError> {
        append_json_line(&self.paths.approval_log, request)
    }

    pub fn latest_audit_record(&self) -> Result<Option<EventEnvelope>, PersistenceError> {
        read_last_json_line(&self.paths.audit_log)
    }

    pub fn latest_approval_request(&self) -> Result<Option<ApprovalRequest>, PersistenceError> {
        read_last_json_line(&self.paths.approval_log)
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
        Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest,
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EnforcementDirective,
        EnforcementInfo, EnforcementStatus, EventEnvelope, EventType, JsonMap, PolicyDecisionKind,
        PolicyMetadata, ResultInfo, ResultStatus, SessionRef, Severity, SourceInfo,
    };
    use serde_json::json;

    use super::GitHubPocStore;

    #[test]
    fn store_appends_and_reads_back_github_audit_and_approval_records() {
        let store = GitHubPocStore::fresh(unique_test_root()).expect("store should init");
        let event = fixture_event();
        let request = fixture_request();

        store
            .append_audit_record(&event)
            .expect("audit record should append");
        store
            .append_approval_request(&request)
            .expect("approval request should append");

        assert_eq!(
            store
                .latest_audit_record()
                .expect("audit record should read"),
            Some(event)
        );
        assert_eq!(
            store
                .latest_approval_request()
                .expect("approval request should read"),
            Some(request)
        );
    }

    #[test]
    fn fresh_store_clears_old_github_records_before_bootstrap() {
        let root = unique_test_root();
        let first = GitHubPocStore::fresh(&root).expect("first store should init");
        first
            .append_audit_record(&fixture_event())
            .expect("audit record should append");

        let second = GitHubPocStore::fresh(&root).expect("second store should reset");

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
        env::temp_dir().join(format!("agent-auditor-hostd-github-store-test-{nonce}"))
    }

    fn fixture_event() -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("source_kind".to_owned(), json!("api_observation"));
        attributes.insert(
            "request_id".to_owned(),
            json!("req_github_repos_update_visibility_preview"),
        );
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("semantic_surface".to_owned(), json!("github.repos"));
        attributes.insert("provider_id".to_owned(), json!("github"));
        attributes.insert("action_key".to_owned(), json!("repos.update_visibility"));
        attributes.insert(
            "provider_action_id".to_owned(),
            json!("github:repos.update_visibility"),
        );
        attributes.insert(
            "semantic_action_label".to_owned(),
            json!("repos.update_visibility"),
        );
        attributes.insert(
            "target_hint".to_owned(),
            json!("repos/n01e0/agent-auditor/visibility"),
        );
        attributes.insert(
            "classifier_labels".to_owned(),
            json!(["github.repos", "repos.update_visibility"]),
        );
        attributes.insert(
            "classifier_reasons".to_owned(),
            json!(["policy preview for GitHub record persistence test"]),
        );
        attributes.insert("content_retained".to_owned(), json!(false));

        EventEnvelope {
            event_id: "evt_github_visibility_record".to_owned(),
            event_type: EventType::GithubAction,
            timestamp: chrono::Utc::now(),
            session: SessionRef {
                session_id: "sess_github_persist".to_owned(),
                agent_id: Some("openclaw-main".to_owned()),
                initiator_id: None,
                workspace_id: Some("ws_github_persist".to_owned()),
                policy_bundle_version: Some("bundle-bootstrap".to_owned()),
                environment: Some("dev".to_owned()),
            },
            actor: Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("agent-auditor-hostd PoC".to_owned()),
            },
            action: Action {
                class: ActionClass::Github,
                verb: Some("repos.update_visibility".to_owned()),
                target: Some("repos/n01e0/agent-auditor/visibility".to_owned()),
                attributes,
            },
            result: ResultInfo {
                status: ResultStatus::ApprovalRequired,
                reason: Some("Repository visibility changes require approval".to_owned()),
                exit_code: None,
                error: None,
            },
            source: SourceInfo {
                collector: CollectorKind::RuntimeHint,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: None,
                ppid: None,
            },
            policy: Some(PolicyMetadata {
                decision: Some(PolicyDecisionKind::RequireApproval),
                rule_id: Some("github.repos.update_visibility.requires_approval".to_owned()),
                severity: Some(Severity::High),
                explanation: Some("Repository visibility changes require approval".to_owned()),
            }),
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Repository visibility changes require approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_github_visibility_record".to_owned()),
                expires_at: None,
            }),
            integrity: None,
        }
    }

    fn fixture_request() -> ApprovalRequest {
        ApprovalRequest {
            approval_id: "apr_evt_github_visibility_record".to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess_github_persist".to_owned(),
            event_id: Some("evt_github_visibility_record".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Github,
                action_verb: "repos.update_visibility".to_owned(),
                target: Some("repos/n01e0/agent-auditor/visibility".to_owned()),
                summary: Some("Repository visibility changes require approval".to_owned()),
                attributes: fixture_event().action.attributes,
            },
            policy: ApprovalPolicy {
                rule_id: "github.repos.update_visibility.requires_approval".to_owned(),
                severity: Some(Severity::High),
                reason: Some("Repository visibility changes require approval".to_owned()),
                scope: Some(agenta_core::ApprovalScope::SingleAction),
                ttl_seconds: Some(1800),
                reviewer_hint: Some("security-oncall".to_owned()),
            },
            requester_context: None,
            decision: None,
            enforcement: Some(EnforcementInfo {
                directive: EnforcementDirective::Hold,
                status: EnforcementStatus::Held,
                status_reason: Some("Repository visibility changes require approval".to_owned()),
                enforced: true,
                coverage_gap: None,
                approval_id: Some("apr_evt_github_visibility_record".to_owned()),
                expires_at: None,
            }),
        }
    }
}
