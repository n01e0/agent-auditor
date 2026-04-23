use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use agenta_core::{
    ApprovalRequest, EventEnvelope,
    controlplane::{
        ApprovalLocalJsonlInspectionRecord, ApprovalQueueItem,
        ObservationLocalJsonlInspectionRecord,
    },
};
use chrono::{DateTime, Utc};
use serde_json::json;
use thiserror::Error;

const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";
const APPROVAL_LOG_FILENAME: &str = "approval-requests.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRecordKind {
    Audit,
    Approval,
    All,
}

impl AuditRecordKind {
    pub fn parse(value: &str) -> Result<Self, AuditCliError> {
        match value {
            "audit" => Ok(Self::Audit),
            "approval" => Ok(Self::Approval),
            "all" => Ok(Self::All),
            _ => Err(AuditCliError::InvalidKind(value.to_owned())),
        }
    }

    fn matches(self, entry_kind: EntryKind) -> bool {
        match self {
            Self::Audit => entry_kind == EntryKind::Audit,
            Self::Approval => entry_kind == EntryKind::Approval,
            Self::All => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditCommand {
    List {
        state_dir: PathBuf,
        kind: AuditRecordKind,
    },
    Tail {
        state_dir: PathBuf,
        kind: AuditRecordKind,
        count: usize,
    },
    Show {
        state_dir: PathBuf,
        id: String,
    },
}

#[derive(Debug, Error)]
pub enum AuditCliError {
    #[error("unknown audit subcommand `{0}`; use `audit list`, `audit tail`, or `audit show`")]
    UnknownSubcommand(String),
    #[error("missing audit subcommand; use `audit list`, `audit tail`, or `audit show`")]
    MissingSubcommand,
    #[error("missing value for `--state-dir`")]
    MissingStateDir,
    #[error("missing value for `--count`")]
    MissingCount,
    #[error("missing record id; use `audit show --state-dir <path> <event_id|approval_id>`")]
    MissingShowId,
    #[error("unknown audit flag `{0}`")]
    UnknownFlag(String),
    #[error("invalid audit kind `{0}`; use `audit`, `approval`, or `all`")]
    InvalidKind(String),
    #[error("invalid `--count` value `{value}`: {reason}")]
    InvalidCount { value: String, reason: String },
    #[error("`audit {subcommand}` requires `--state-dir <path>`")]
    MissingStateDirForSubcommand { subcommand: &'static str },
    #[error("state dir `{0}` does not exist or is not a directory")]
    InvalidStateDir(PathBuf),
    #[error("failed to read state dir `{path}`: {source}")]
    ReadStateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read log file `{path}`: {source}")]
    ReadLog {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to decode audit record in `{path}` line {line}: {source}")]
    DecodeAuditRecord {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode approval record in `{path}` line {line}: {source}")]
    DecodeApprovalRecord {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("record `{0}` was not found in the durable audit store")]
    RecordNotFound(String),
    #[error("failed to serialize record output: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EntryKind {
    Audit,
    Approval,
}

#[derive(Debug, Clone)]
struct ParsedFlags {
    state_dir: Option<PathBuf>,
    kind: AuditRecordKind,
    count: Option<usize>,
    positionals: Vec<String>,
}

#[derive(Debug, Clone)]
struct RecordEntry {
    kind: EntryKind,
    store: String,
    source_path: PathBuf,
    line_number: usize,
    when: DateTime<Utc>,
    id: String,
    summary: String,
    payload: RecordPayload,
}

#[derive(Debug, Clone)]
enum RecordPayload {
    Audit(EventEnvelope),
    Approval(ApprovalRequest),
}

pub fn parse_command<I>(args: I) -> Result<AuditCommand, AuditCliError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(subcommand) = args.next() else {
        return Err(AuditCliError::MissingSubcommand);
    };

    match subcommand.as_str() {
        "list" => {
            let flags = parse_common_flags(args)?;
            if !flags.positionals.is_empty() {
                return Err(AuditCliError::UnknownFlag(flags.positionals[0].clone()));
            }
            Ok(AuditCommand::List {
                state_dir: flags
                    .state_dir
                    .ok_or(AuditCliError::MissingStateDirForSubcommand { subcommand: "list" })?,
                kind: flags.kind,
            })
        }
        "tail" => {
            let flags = parse_common_flags(args)?;
            if !flags.positionals.is_empty() {
                return Err(AuditCliError::UnknownFlag(flags.positionals[0].clone()));
            }
            Ok(AuditCommand::Tail {
                state_dir: flags
                    .state_dir
                    .ok_or(AuditCliError::MissingStateDirForSubcommand { subcommand: "tail" })?,
                kind: flags.kind,
                count: flags.count.unwrap_or(10),
            })
        }
        "show" => {
            let flags = parse_common_flags(args)?;
            let ParsedFlags {
                state_dir,
                positionals,
                ..
            } = flags;
            let id = positionals
                .into_iter()
                .next()
                .ok_or(AuditCliError::MissingShowId)?;
            Ok(AuditCommand::Show {
                state_dir: state_dir
                    .ok_or(AuditCliError::MissingStateDirForSubcommand { subcommand: "show" })?,
                id,
            })
        }
        _ => Err(AuditCliError::UnknownSubcommand(subcommand)),
    }
}

pub fn run(command: AuditCommand) -> Result<(), AuditCliError> {
    match command {
        AuditCommand::List { state_dir, kind } => {
            for entry in load_entries(&state_dir, kind)? {
                println!("{}", entry.summary);
            }
        }
        AuditCommand::Tail {
            state_dir,
            kind,
            count,
        } => {
            for entry in load_entries(&state_dir, kind)?.into_iter().take(count) {
                println!("{}", entry.summary);
            }
        }
        AuditCommand::Show { state_dir, id } => {
            let entry = load_entries(&state_dir, AuditRecordKind::All)?
                .into_iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| AuditCliError::RecordNotFound(id.clone()))?;
            match entry.payload {
                RecordPayload::Audit(record) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "kind": "audit",
                            "store": entry.store,
                            "path": entry.source_path,
                            "line": entry.line_number,
                            "record": record,
                            "observation_local_inspection": ObservationLocalJsonlInspectionRecord::from_event(&record),
                        }))?
                    );
                }
                RecordPayload::Approval(record) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "kind": "approval",
                            "store": entry.store,
                            "path": entry.source_path,
                            "line": entry.line_number,
                            "record": record,
                            "local_inspection": ApprovalLocalJsonlInspectionRecord::derive(
                                &ApprovalQueueItem::from_request(&record),
                            ),
                            "observation_local_inspection": ObservationLocalJsonlInspectionRecord::from_request(&record),
                        }))?
                    );
                }
            }
        }
    }

    Ok(())
}

fn parse_common_flags<I>(args: I) -> Result<ParsedFlags, AuditCliError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut state_dir = None;
    let mut kind = AuditRecordKind::All;
    let mut count = None;
    let mut positionals = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state-dir" => {
                let value = args.next().ok_or(AuditCliError::MissingStateDir)?;
                state_dir = Some(PathBuf::from(value));
            }
            "--kind" => {
                let value = args
                    .next()
                    .ok_or_else(|| AuditCliError::UnknownFlag("--kind".to_owned()))?;
                kind = AuditRecordKind::parse(&value)?;
            }
            "--count" => {
                let value = args.next().ok_or(AuditCliError::MissingCount)?;
                let parsed =
                    value
                        .parse::<usize>()
                        .map_err(|error| AuditCliError::InvalidCount {
                            value: value.clone(),
                            reason: error.to_string(),
                        })?;
                if parsed == 0 {
                    return Err(AuditCliError::InvalidCount {
                        value,
                        reason: "must be greater than zero".to_owned(),
                    });
                }
                count = Some(parsed);
            }
            value if value.starts_with('-') => {
                return Err(AuditCliError::UnknownFlag(value.to_owned()));
            }
            value => positionals.push(value.to_owned()),
        }
    }

    Ok(ParsedFlags {
        state_dir,
        kind,
        count,
        positionals,
    })
}

fn load_entries(
    state_dir: &Path,
    kind: AuditRecordKind,
) -> Result<Vec<RecordEntry>, AuditCliError> {
    if !state_dir.is_dir() {
        return Err(AuditCliError::InvalidStateDir(state_dir.to_path_buf()));
    }

    let mut entries = Vec::new();
    for store_dir in fs::read_dir(state_dir).map_err(|source| AuditCliError::ReadStateDir {
        path: state_dir.to_path_buf(),
        source,
    })? {
        let store_dir = store_dir.map_err(|source| AuditCliError::ReadStateDir {
            path: state_dir.to_path_buf(),
            source,
        })?;
        let store_path = store_dir.path();
        if !store_path.is_dir() {
            continue;
        }
        let store_name = store_dir.file_name().to_string_lossy().into_owned();
        if kind.matches(EntryKind::Audit) {
            for log_path in discover_log_paths(&store_path, AUDIT_LOG_FILENAME)? {
                entries.extend(read_audit_entries(&store_name, &log_path)?);
            }
        }
        if kind.matches(EntryKind::Approval) {
            for log_path in discover_log_paths(&store_path, APPROVAL_LOG_FILENAME)? {
                entries.extend(read_approval_entries(&store_name, &log_path)?);
            }
        }
    }

    entries.sort_by(|left, right| {
        right
            .when
            .cmp(&left.when)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.store.cmp(&right.store))
            .then_with(|| left.line_number.cmp(&right.line_number))
    });
    Ok(entries)
}

fn discover_log_paths(store_path: &Path, active_name: &str) -> Result<Vec<PathBuf>, AuditCliError> {
    let mut logs = Vec::new();
    for entry in fs::read_dir(store_path).map_err(|source| AuditCliError::ReadStateDir {
        path: store_path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| AuditCliError::ReadStateDir {
            path: store_path.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if is_log_path(&path, active_name) {
            logs.push(path);
        }
    }
    logs.sort_by_key(|path| archive_sort_key(path, active_name));
    Ok(logs)
}

fn is_log_path(path: &Path, active_name: &str) -> bool {
    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    if file_name == active_name {
        return true;
    }
    let Some(stem) = active_name.strip_suffix(".jsonl") else {
        return false;
    };
    file_name
        .strip_prefix(&format!("{stem}."))
        .and_then(|suffix| suffix.strip_suffix(".jsonl"))
        .and_then(|index| index.parse::<usize>().ok())
        .is_some()
}

fn archive_sort_key(path: &Path, active_name: &str) -> usize {
    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return usize::MAX;
    };
    if file_name == active_name {
        return usize::MAX;
    }
    let stem = active_name.strip_suffix(".jsonl").unwrap_or(active_name);
    file_name
        .strip_prefix(&format!("{stem}."))
        .and_then(|suffix| suffix.strip_suffix(".jsonl"))
        .and_then(|index| index.parse::<usize>().ok())
        .map(|index| usize::MAX.saturating_sub(index))
        .unwrap_or(usize::MAX)
}

fn read_audit_entries(store: &str, path: &Path) -> Result<Vec<RecordEntry>, AuditCliError> {
    let file = File::open(path).map_err(|source| AuditCliError::ReadLog {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| AuditCliError::ReadLog {
            path: path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: EventEnvelope =
            serde_json::from_str(&line).map_err(|source| AuditCliError::DecodeAuditRecord {
                path: path.to_path_buf(),
                line: line_number,
                source,
            })?;
        entries.push(RecordEntry {
            kind: EntryKind::Audit,
            store: store.to_owned(),
            source_path: path.to_path_buf(),
            line_number,
            when: record.timestamp,
            id: record.event_id.clone(),
            summary: format!(
                "kind=audit when={} store={} id={} event_type={} action={} target={}",
                record.timestamp.to_rfc3339(),
                store,
                record.event_id,
                event_type_label(&record),
                record.action.verb.as_deref().unwrap_or("unknown"),
                record.action.target.as_deref().unwrap_or("-")
            ),
            payload: RecordPayload::Audit(record),
        });
    }

    Ok(entries)
}

fn read_approval_entries(store: &str, path: &Path) -> Result<Vec<RecordEntry>, AuditCliError> {
    let file = File::open(path).map_err(|source| AuditCliError::ReadLog {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| AuditCliError::ReadLog {
            path: path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: ApprovalRequest =
            serde_json::from_str(&line).map_err(|source| AuditCliError::DecodeApprovalRecord {
                path: path.to_path_buf(),
                line: line_number,
                source,
            })?;
        let inspection =
            ApprovalLocalJsonlInspectionRecord::derive(&ApprovalQueueItem::from_request(&record));
        entries.push(RecordEntry {
            kind: EntryKind::Approval,
            store: store.to_owned(),
            source_path: path.to_path_buf(),
            line_number,
            when: record.requested_at,
            id: record.approval_id.clone(),
            summary: format!(
                "kind=approval when={} store={} id={} status={:?} action={} target={} rule={} summary={}",
                record.requested_at.to_rfc3339(),
                store,
                record.approval_id,
                record.status,
                record.request.action_verb,
                record.request.target.as_deref().unwrap_or("-"),
                record.policy.rule_id,
                inspection.explanation_summary,
            ),
            payload: RecordPayload::Approval(record),
        });
    }

    Ok(entries)
}

fn event_type_label(record: &EventEnvelope) -> &'static str {
    match record.event_type {
        agenta_core::EventType::SessionLifecycle => "session_lifecycle",
        agenta_core::EventType::ProcessExec => "process_exec",
        agenta_core::EventType::ProcessExit => "process_exit",
        agenta_core::EventType::FilesystemAccess => "filesystem_access",
        agenta_core::EventType::NetworkConnect => "network_connect",
        agenta_core::EventType::SecretAccess => "secret_access",
        agenta_core::EventType::GwsAction => "gws_action",
        agenta_core::EventType::GithubAction => "github_action",
        agenta_core::EventType::PolicyDecision => "policy_decision",
        agenta_core::EventType::ApprovalRequested => "approval_requested",
        agenta_core::EventType::ApprovalResolved => "approval_resolved",
        agenta_core::EventType::AlertRaised => "alert_raised",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest,
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EventEnvelope, EventType,
        RequesterContext, ResultInfo, ResultStatus, SessionRef, SourceInfo,
    };
    use chrono::TimeZone;

    use super::{AuditCommand, AuditRecordKind, load_entries, parse_command};

    #[test]
    fn parse_list_tail_and_show_commands() {
        assert_eq!(
            parse_command(vec![
                "list".to_owned(),
                "--state-dir".to_owned(),
                "/tmp/hostd-state".to_owned(),
                "--kind".to_owned(),
                "approval".to_owned(),
            ])
            .unwrap(),
            AuditCommand::List {
                state_dir: "/tmp/hostd-state".into(),
                kind: AuditRecordKind::Approval,
            }
        );

        assert_eq!(
            parse_command(vec![
                "tail".to_owned(),
                "--state-dir".to_owned(),
                "/tmp/hostd-state".to_owned(),
                "--count".to_owned(),
                "5".to_owned(),
            ])
            .unwrap(),
            AuditCommand::Tail {
                state_dir: "/tmp/hostd-state".into(),
                kind: AuditRecordKind::All,
                count: 5,
            }
        );

        assert_eq!(
            parse_command(vec![
                "show".to_owned(),
                "--state-dir".to_owned(),
                "/tmp/hostd-state".to_owned(),
                "evt-123".to_owned(),
            ])
            .unwrap(),
            AuditCommand::Show {
                state_dir: "/tmp/hostd-state".into(),
                id: "evt-123".to_owned(),
            }
        );
    }

    #[test]
    fn load_entries_reads_active_and_rotated_audit_and_approval_logs() {
        let state_dir = unique_state_dir();
        let store_dir = state_dir.join("agent-auditor-hostd-poc-store");
        fs::create_dir_all(&store_dir).expect("store dir should exist");

        fs::write(
            store_dir.join("audit-records.1.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&sample_audit_record("evt-old", 1)).unwrap()
            ),
        )
        .expect("rotated audit log should be written");
        fs::write(
            store_dir.join("audit-records.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&sample_audit_record("evt-new", 2)).unwrap()
            ),
        )
        .expect("active audit log should be written");
        fs::write(
            store_dir.join("approval-requests.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&sample_approval_record("apr-1", 3)).unwrap()
            ),
        )
        .expect("approval log should be written");

        let entries = load_entries(&state_dir, AuditRecordKind::All).expect("entries should load");
        let ids = entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["apr-1", "evt-new", "evt-old"]);
        assert!(entries[0].summary.contains("kind=approval"));
        assert!(entries[1].summary.contains("kind=audit"));
        assert!(entries[1].summary.contains("event_type=filesystem_access"));
    }

    fn sample_audit_record(event_id: &str, second: i64) -> EventEnvelope {
        EventEnvelope {
            event_id: event_id.to_owned(),
            timestamp: chrono::Utc
                .timestamp_opt(1_700_000_000 + second, 0)
                .unwrap(),
            event_type: EventType::FilesystemAccess,
            session: SessionRef {
                session_id: "sess-test".to_owned(),
                agent_id: Some("agent-test".to_owned()),
                initiator_id: None,
                workspace_id: None,
                policy_bundle_version: None,
                environment: None,
            },
            actor: Actor {
                kind: ActorKind::System,
                id: Some("agent-auditor-hostd".to_owned()),
                display_name: Some("hostd".to_owned()),
            },
            action: Action {
                class: ActionClass::Filesystem,
                verb: Some("read".to_owned()),
                target: Some("/tmp/file.txt".to_owned()),
                attributes: Default::default(),
            },
            result: ResultInfo {
                status: ResultStatus::Observed,
                reason: Some("fixture".to_owned()),
                exit_code: None,
                error: None,
            },
            policy: None,
            enforcement: None,
            source: SourceInfo {
                collector: CollectorKind::Fanotify,
                host_id: Some("hostd-poc".to_owned()),
                container_id: None,
                pod_uid: None,
                pid: Some(42),
                ppid: Some(7),
            },
            integrity: None,
        }
    }

    fn sample_approval_record(approval_id: &str, second: i64) -> ApprovalRequest {
        ApprovalRequest {
            approval_id: approval_id.to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc
                .timestamp_opt(1_700_000_000 + second, 0)
                .unwrap(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess-test".to_owned(),
            event_id: Some("evt-new".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Filesystem,
                action_verb: "read".to_owned(),
                target: Some("/tmp/file.txt".to_owned()),
                summary: Some("read /tmp/file.txt".to_owned()),
                attributes: Default::default(),
            },
            policy: ApprovalPolicy {
                rule_id: "rule.fs.approval".to_owned(),
                severity: None,
                reason: Some("Needs review".to_owned()),
                scope: None,
                ttl_seconds: Some(600),
                reviewer_hint: Some("check the path".to_owned()),
            },
            presentation: None,
            requester_context: Some(RequesterContext {
                agent_reason: Some("agent requested file read".to_owned()),
                human_request: Some("inspect the fixture".to_owned()),
            }),
            decision: None,
            enforcement: None,
        }
    }

    fn unique_state_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-cli-audit-test-{nonce}"))
    }
}
