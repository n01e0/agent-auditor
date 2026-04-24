use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use agenta_core::{
    ApprovalRequest, EventEnvelope, IntegrityCheckpointKind, IntegrityCheckpointRecord,
    IntegrityInfo,
};
use chrono::Utc;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::runtime;

pub const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";
pub const APPROVAL_LOG_FILENAME: &str = "approval-requests.jsonl";
pub const AUDIT_INTEGRITY_LOG_FILENAME: &str = "audit-records.integrity.jsonl";
pub const APPROVAL_INTEGRITY_LOG_FILENAME: &str = "approval-requests.integrity.jsonl";
pub const DEFAULT_ROTATION_MAX_BYTES: u64 = 256 * 1024;
pub const DEFAULT_RETAINED_ARCHIVES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotationPolicy {
    pub max_bytes: u64,
    pub retained_archives: usize,
}

impl Default for LogRotationPolicy {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_ROTATION_MAX_BYTES,
            retained_archives: DEFAULT_RETAINED_ARCHIVES,
        }
    }
}

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
    #[error("failed to rotate record log `{path}`: {source}")]
    Rotate {
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
    #[error("durable record in `{path}` is missing integrity.hash")]
    MissingIntegrityHash { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistencePaths {
    pub root: PathBuf,
    pub audit_log: PathBuf,
    pub approval_log: PathBuf,
    pub audit_integrity_log: PathBuf,
    pub approval_integrity_log: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableStreamKind {
    Audit,
    Approval,
}

impl DurableStreamKind {
    fn label(self) -> &'static str {
        match self {
            Self::Audit => "audit-records",
            Self::Approval => "approval-requests",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SegmentSummary {
    segment_id: String,
    record_count: u64,
    first_record_hash: Option<String>,
    last_record_hash: Option<String>,
}

pub fn bootstrap_paths(store_dir_name: &str) -> Result<PersistencePaths, PersistenceError> {
    let root = runtime::runtime_store_root(store_dir_name);
    durable_paths(root)
}

pub fn fresh_paths(root: impl Into<PathBuf>) -> Result<PersistencePaths, PersistenceError> {
    let root = root.into();
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|source| PersistenceError::PrepareRoot {
            path: root.clone(),
            source,
        })?;
    }
    durable_paths(root)
}

pub fn durable_paths(root: impl Into<PathBuf>) -> Result<PersistencePaths, PersistenceError> {
    let root = root.into();
    fs::create_dir_all(&root).map_err(|source| PersistenceError::PrepareRoot {
        path: root.clone(),
        source,
    })?;

    Ok(PersistencePaths {
        audit_log: root.join(AUDIT_LOG_FILENAME),
        approval_log: root.join(APPROVAL_LOG_FILENAME),
        audit_integrity_log: root.join(AUDIT_INTEGRITY_LOG_FILENAME),
        approval_integrity_log: root.join(APPROVAL_INTEGRITY_LOG_FILENAME),
        root,
    })
}

pub fn append_json_line<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), PersistenceError> {
    append_json_line_with_policy(path, value, LogRotationPolicy::default())
}

pub fn append_durable_audit_record(
    path: &Path,
    integrity_path: &Path,
    value: &EventEnvelope,
) -> Result<EventEnvelope, PersistenceError> {
    append_durable_record(
        path,
        integrity_path,
        value,
        LogRotationPolicy::default(),
        DurableStreamKind::Audit,
    )
}

pub fn append_durable_approval_request(
    path: &Path,
    integrity_path: &Path,
    value: &ApprovalRequest,
) -> Result<ApprovalRequest, PersistenceError> {
    append_durable_record(
        path,
        integrity_path,
        value,
        LogRotationPolicy::default(),
        DurableStreamKind::Approval,
    )
}

fn append_json_line_with_policy<T: serde::Serialize>(
    path: &Path,
    value: &T,
    policy: LogRotationPolicy,
) -> Result<(), PersistenceError> {
    let json = serde_json::to_string(value).map_err(|source| PersistenceError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    append_serialized_json_line(path, &json, policy)
}

fn append_durable_record<T>(
    path: &Path,
    integrity_path: &Path,
    value: &T,
    policy: LogRotationPolicy,
    stream: DurableStreamKind,
) -> Result<T, PersistenceError>
where
    T: DurableRecord,
{
    let previous_record = read_last_json_line::<T>(path)?;
    let prev_hash = previous_record
        .as_ref()
        .map(last_integrity_hash)
        .transpose()?
        .flatten();

    let with_integrity = materialize_durable_record(value, prev_hash, path, stream)?;
    let json =
        serde_json::to_string(&with_integrity).map_err(|source| PersistenceError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;

    let rotated_segment = if log_rotation_needed(path, &json, policy)? {
        let summary = read_segment_summary::<T>(path, stream)?;
        rotate_log_if_needed(path, &json, policy)?;
        summary
    } else {
        None
    };

    let mut prev_checkpoint_hash =
        read_last_json_line::<IntegrityCheckpointRecord>(integrity_path)?
            .map(|checkpoint| checkpoint.checkpoint_hash);

    if let Some(summary) = rotated_segment {
        let checkpoint = checkpoint_record(
            stream,
            IntegrityCheckpointKind::Seal,
            &summary,
            prev_checkpoint_hash.clone(),
            None,
            None,
        )?;
        append_json_line_with_policy(integrity_path, &checkpoint, policy)?;
        prev_checkpoint_hash = Some(checkpoint.checkpoint_hash.clone());
    }

    append_serialized_json_line(path, &json, policy)?;

    if let Some(summary) = read_segment_summary::<T>(path, stream)? {
        let checkpoint = checkpoint_record(
            stream,
            IntegrityCheckpointKind::Head,
            &summary,
            prev_checkpoint_hash,
            None,
            None,
        )?;
        append_json_line_with_policy(integrity_path, &checkpoint, policy)?;
    }

    Ok(with_integrity)
}

fn materialize_durable_record<T>(
    value: &T,
    prev_hash: Option<String>,
    path: &Path,
    stream: DurableStreamKind,
) -> Result<T, PersistenceError>
where
    T: DurableRecord,
{
    let payload = canonical_record_payload(value, path)?;
    let hash = chain_hash(stream, prev_hash.as_deref(), &payload);
    Ok(value.with_integrity(IntegrityInfo {
        hash: Some(hash),
        prev_hash,
        signature: None,
    }))
}

fn checkpoint_record(
    stream: DurableStreamKind,
    checkpoint_kind: IntegrityCheckpointKind,
    summary: &SegmentSummary,
    prev_checkpoint_hash: Option<String>,
    signature: Option<String>,
    signing_key_id: Option<String>,
) -> Result<IntegrityCheckpointRecord, PersistenceError> {
    let mut checkpoint = IntegrityCheckpointRecord {
        stream: stream.label().to_owned(),
        checkpoint_kind,
        segment_id: summary.segment_id.clone(),
        record_count: summary.record_count,
        first_record_hash: summary.first_record_hash.clone(),
        last_record_hash: summary.last_record_hash.clone(),
        checkpointed_at: Utc::now(),
        prev_checkpoint_hash,
        checkpoint_hash: String::new(),
        signature,
        signing_key_id,
    };

    let payload = canonical_checkpoint_payload(&checkpoint, Path::new(stream.label()))?;
    checkpoint.checkpoint_hash = prefixed_sha256(&payload);
    Ok(checkpoint)
}

fn canonical_record_payload<T>(value: &T, path: &Path) -> Result<Vec<u8>, PersistenceError>
where
    T: Serialize,
{
    let mut payload =
        serde_json::to_value(value).map_err(|source| PersistenceError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(object) = payload.as_object_mut() else {
        return serde_json::to_vec(&payload).map_err(|source| PersistenceError::Serialize {
            path: path.to_path_buf(),
            source,
        });
    };
    object.remove("integrity");
    serde_json::to_vec(&payload).map_err(|source| PersistenceError::Serialize {
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_checkpoint_payload(
    checkpoint: &IntegrityCheckpointRecord,
    path: &Path,
) -> Result<Vec<u8>, PersistenceError> {
    let mut payload =
        serde_json::to_value(checkpoint).map_err(|source| PersistenceError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(object) = payload.as_object_mut() else {
        return serde_json::to_vec(&payload).map_err(|source| PersistenceError::Serialize {
            path: path.to_path_buf(),
            source,
        });
    };
    object.remove("checkpoint_hash");
    object.remove("signature");
    serde_json::to_vec(&payload).map_err(|source| PersistenceError::Serialize {
        path: path.to_path_buf(),
        source,
    })
}

fn chain_hash(stream: DurableStreamKind, prev_hash: Option<&str>, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(stream.label().as_bytes());
    hasher.update([0]);
    hasher.update(prev_hash.unwrap_or("GENESIS").as_bytes());
    hasher.update([0]);
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn prefixed_sha256(payload: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(payload))
}

fn last_integrity_hash<T>(value: &T) -> Result<Option<String>, PersistenceError>
where
    T: DurableRecord,
{
    Ok(value
        .integrity()
        .and_then(|integrity| integrity.hash.clone()))
}

fn read_segment_summary<T>(
    path: &Path,
    stream: DurableStreamKind,
) -> Result<Option<SegmentSummary>, PersistenceError>
where
    T: DurableRecord,
{
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
    let mut first: Option<T> = None;
    let mut last: Option<T> = None;
    let mut count = 0_u64;

    for line in reader.lines() {
        let line = line.map_err(|source| PersistenceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record =
            serde_json::from_str::<T>(&line).map_err(|source| PersistenceError::Deserialize {
                path: path.to_path_buf(),
                source,
            })?;
        if first.is_none() {
            first = Some(record.clone());
        }
        last = Some(record);
        count += 1;
    }

    let Some(first) = first else {
        return Ok(None);
    };
    let Some(last) = last else {
        return Ok(None);
    };

    let first_hash =
        last_integrity_hash(&first)?.ok_or_else(|| PersistenceError::MissingIntegrityHash {
            path: path.to_path_buf(),
        })?;
    let last_hash =
        last_integrity_hash(&last)?.ok_or_else(|| PersistenceError::MissingIntegrityHash {
            path: path.to_path_buf(),
        })?;

    Ok(Some(SegmentSummary {
        segment_id: format!("{}:{}", stream.label(), first_hash),
        record_count: count,
        first_record_hash: Some(first_hash),
        last_record_hash: Some(last_hash),
    }))
}

fn append_serialized_json_line(
    path: &Path,
    json: &str,
    policy: LogRotationPolicy,
) -> Result<(), PersistenceError> {
    rotate_log_if_needed(path, json, policy)?;

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
    })?;
    file.sync_data().map_err(|source| PersistenceError::Append {
        path: path.to_path_buf(),
        source,
    })
}

fn log_rotation_needed(
    path: &Path,
    next_json: &str,
    policy: LogRotationPolicy,
) -> Result<bool, PersistenceError> {
    let current_size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(PersistenceError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let next_len = next_json.len() as u64 + 1;
    Ok(current_size.saturating_add(next_len) > policy.max_bytes)
}

fn rotate_log_if_needed(
    path: &Path,
    next_json: &str,
    policy: LogRotationPolicy,
) -> Result<bool, PersistenceError> {
    if !log_rotation_needed(path, next_json, policy)? {
        return Ok(false);
    }

    if policy.retained_archives == 0 {
        fs::remove_file(path).map_err(|source| PersistenceError::Rotate {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(true);
    }

    let oldest_archive = rotated_path(path, policy.retained_archives);
    if oldest_archive.exists() {
        fs::remove_file(&oldest_archive).map_err(|source| PersistenceError::Rotate {
            path: oldest_archive.clone(),
            source,
        })?;
    }

    for archive_idx in (1..=policy.retained_archives).rev() {
        let source_path = if archive_idx == 1 {
            path.to_path_buf()
        } else {
            rotated_path(path, archive_idx - 1)
        };

        if !source_path.exists() {
            continue;
        }

        let destination_path = rotated_path(path, archive_idx);
        fs::rename(&source_path, &destination_path).map_err(|source| PersistenceError::Rotate {
            path: source_path,
            source,
        })?;
    }

    Ok(true)
}

fn rotated_path(path: &Path, archive_idx: usize) -> PathBuf {
    let file_name = path
        .file_name()
        .expect("log paths should always have a file name")
        .to_string_lossy();
    let rotated_name = match file_name.strip_suffix(".jsonl") {
        Some(stem) => format!("{stem}.{archive_idx}.jsonl"),
        None => format!("{file_name}.{archive_idx}"),
    };
    path.with_file_name(rotated_name)
}

pub fn read_last_json_line<T: for<'de> serde::Deserialize<'de>>(
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

trait DurableRecord: Serialize + DeserializeOwned + Clone {
    fn with_integrity(&self, integrity: IntegrityInfo) -> Self;
    fn integrity(&self) -> Option<&IntegrityInfo>;
}

impl DurableRecord for EventEnvelope {
    fn with_integrity(&self, integrity: IntegrityInfo) -> Self {
        let mut cloned = self.clone();
        cloned.integrity = Some(integrity);
        cloned
    }

    fn integrity(&self) -> Option<&IntegrityInfo> {
        self.integrity.as_ref()
    }
}

impl DurableRecord for ApprovalRequest {
    fn with_integrity(&self, integrity: IntegrityInfo) -> Self {
        let mut cloned = self.clone();
        cloned.integrity = Some(integrity);
        cloned
    }

    fn integrity(&self) -> Option<&IntegrityInfo> {
        self.integrity.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use agenta_core::{
        Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest,
        ApprovalRequestAction, ApprovalStatus, CollectorKind, EventEnvelope, EventType,
        IntegrityCheckpointRecord, JsonMap, RequesterContext, ResultInfo, ResultStatus, SessionRef,
        SourceInfo,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::{
        LogRotationPolicy, append_durable_approval_request, append_durable_audit_record,
        append_json_line_with_policy, durable_paths, fresh_paths, read_last_json_line,
        rotated_path,
    };

    #[test]
    fn durable_paths_keep_existing_records_for_restart_safe_bootstrap() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("test root should be created");
        let active = root.join("audit-records.jsonl");
        let archive = root.join("audit-records.1.jsonl");
        fs::write(&active, "{\"seq\":2}\n").expect("active log should be writable");
        fs::write(&archive, "{\"seq\":1}\n").expect("archive log should be writable");

        let paths = durable_paths(&root).expect("durable bootstrap should preserve existing logs");

        assert_eq!(paths.audit_log, active);
        assert_eq!(
            paths.audit_integrity_log,
            root.join("audit-records.integrity.jsonl")
        );
        assert_eq!(
            fs::read_to_string(paths.audit_log).expect("active log should still exist"),
            "{\"seq\":2}\n"
        );
        assert_eq!(
            fs::read_to_string(archive).expect("archive log should still exist"),
            "{\"seq\":1}\n"
        );
    }

    #[test]
    fn fresh_paths_remove_existing_logs_for_test_reset_helpers() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("test root should be created");
        fs::write(root.join("audit-records.jsonl"), "old\n").expect("active log should exist");
        fs::write(root.join("audit-records.1.jsonl"), "older\n").expect("rotated log should exist");
        fs::write(root.join("audit-records.integrity.jsonl"), "old\n")
            .expect("integrity log should exist");

        let paths = fresh_paths(&root).expect("fresh paths should reset test roots");

        assert!(!paths.root.join("audit-records.1.jsonl").exists());
        assert!(!paths.audit_log.exists());
        assert!(!paths.audit_integrity_log.exists());
    }

    #[test]
    fn append_rotation_moves_the_previous_active_log_into_archive() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("test root should be created");
        let path = root.join("audit-records.jsonl");
        let policy = LogRotationPolicy {
            max_bytes: 32,
            retained_archives: 2,
        };

        append_json_line_with_policy(&path, &json!({"seq": 1, "pad": "aaaaaaaaaa"}), policy)
            .expect("first append should succeed");
        append_json_line_with_policy(&path, &json!({"seq": 2, "pad": "bbbbbbbbbb"}), policy)
            .expect("second append should rotate");

        assert_eq!(
            fs::read_to_string(rotated_path(&path, 1)).expect("first archive should exist"),
            "{\"pad\":\"aaaaaaaaaa\",\"seq\":1}\n"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("active log should exist"),
            "{\"pad\":\"bbbbbbbbbb\",\"seq\":2}\n"
        );
    }

    #[test]
    fn append_rotation_applies_retention_and_discards_oldest_archive() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("test root should be created");
        let path = root.join("approval-requests.jsonl");
        let policy = LogRotationPolicy {
            max_bytes: 24,
            retained_archives: 2,
        };

        for seq in 1..=4 {
            append_json_line_with_policy(&path, &json!({"seq": seq, "pad": "zzzzzzzzzz"}), policy)
                .expect("append should succeed");
        }

        assert!(!rotated_path(&path, 3).exists());
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 2)).expect("second archive should exist"),
            "{\"pad\":\"zzzzzzzzzz\",\"seq\":2}\n"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&path, 1)).expect("first archive should exist"),
            "{\"pad\":\"zzzzzzzzzz\",\"seq\":3}\n"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("active log should exist"),
            "{\"pad\":\"zzzzzzzzzz\",\"seq\":4}\n"
        );
    }

    #[test]
    fn durable_appends_chain_audit_and_approval_records_and_emit_head_checkpoints() {
        let root = unique_test_root();
        let paths = durable_paths(&root).expect("paths should init");

        let first_audit = append_durable_audit_record(
            &paths.audit_log,
            &paths.audit_integrity_log,
            &fixture_event("evt-1"),
        )
        .expect("first audit append should succeed");
        let second_audit = append_durable_audit_record(
            &paths.audit_log,
            &paths.audit_integrity_log,
            &fixture_event("evt-2"),
        )
        .expect("second audit append should succeed");
        let first_approval = append_durable_approval_request(
            &paths.approval_log,
            &paths.approval_integrity_log,
            &fixture_request("apr-1"),
        )
        .expect("approval append should succeed");

        let first_audit_hash = first_audit
            .integrity
            .as_ref()
            .and_then(|integrity| integrity.hash.as_ref())
            .cloned()
            .expect("first audit hash should exist");
        let second_audit_integrity = second_audit
            .integrity
            .as_ref()
            .expect("integrity should exist");
        assert_eq!(
            second_audit_integrity.prev_hash.as_deref(),
            Some(first_audit_hash.as_str())
        );
        assert!(second_audit_integrity.hash.is_some());

        let first_approval_integrity = first_approval
            .integrity
            .as_ref()
            .expect("approval integrity should exist");
        assert!(first_approval_integrity.hash.is_some());
        assert!(first_approval_integrity.prev_hash.is_none());

        let audit_checkpoint =
            read_last_json_line::<IntegrityCheckpointRecord>(&paths.audit_integrity_log)
                .expect("checkpoint log should read")
                .expect("checkpoint should exist");
        assert_eq!(audit_checkpoint.stream, "audit-records");
        assert_eq!(
            audit_checkpoint.checkpoint_kind,
            agenta_core::IntegrityCheckpointKind::Head
        );
        assert_eq!(audit_checkpoint.record_count, 2);
        assert_eq!(
            audit_checkpoint.last_record_hash,
            second_audit
                .integrity
                .as_ref()
                .and_then(|integrity| integrity.hash.clone())
        );

        let approval_checkpoint =
            read_last_json_line::<IntegrityCheckpointRecord>(&paths.approval_integrity_log)
                .expect("approval checkpoint log should read")
                .expect("approval checkpoint should exist");
        assert_eq!(approval_checkpoint.stream, "approval-requests");
        assert_eq!(approval_checkpoint.record_count, 1);
    }

    #[test]
    fn durable_rotation_emits_seal_then_head_checkpoint_chain() {
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("test root should exist");
        let audit_log = root.join("audit-records.jsonl");
        let audit_integrity_log = root.join("audit-records.integrity.jsonl");
        let policy = LogRotationPolicy {
            max_bytes: 512,
            retained_archives: 2,
        };

        let first = fixture_event("evt-1");
        let second = fixture_event("evt-2");
        let third = fixture_event("evt-3");

        super::append_durable_record(
            &audit_log,
            &audit_integrity_log,
            &first,
            policy,
            super::DurableStreamKind::Audit,
        )
        .expect("first append should succeed");
        super::append_durable_record(
            &audit_log,
            &audit_integrity_log,
            &second,
            policy,
            super::DurableStreamKind::Audit,
        )
        .expect("second append should succeed");

        let original_size = fs::metadata(&audit_log)
            .expect("audit log should exist")
            .len();
        let oversized_policy = LogRotationPolicy {
            max_bytes: original_size + 1,
            retained_archives: 2,
        };
        super::append_durable_record(
            &audit_log,
            &audit_integrity_log,
            &third,
            oversized_policy,
            super::DurableStreamKind::Audit,
        )
        .expect("third append should rotate and succeed");

        let checkpoints =
            read_all_rotated_json_lines::<IntegrityCheckpointRecord>(&audit_integrity_log);
        assert!(
            checkpoints
                .iter()
                .any(|checkpoint| checkpoint.checkpoint_kind
                    == agenta_core::IntegrityCheckpointKind::Seal),
            "rotation should emit a seal checkpoint"
        );
        assert_eq!(
            checkpoints
                .last()
                .map(|checkpoint| checkpoint.checkpoint_kind.clone()),
            Some(agenta_core::IntegrityCheckpointKind::Head)
        );
        assert!(rotated_path(&audit_log, 1).exists());
    }

    fn read_all_json_lines<T: for<'de> serde::Deserialize<'de>>(path: &std::path::Path) -> Vec<T> {
        fs::read_to_string(path)
            .expect("file should read")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("line should decode"))
            .collect()
    }

    fn read_all_rotated_json_lines<T: for<'de> serde::Deserialize<'de>>(
        path: &std::path::Path,
    ) -> Vec<T> {
        let mut inputs = Vec::new();
        let mut archive_idx = 1;
        while rotated_path(path, archive_idx).exists() {
            archive_idx += 1;
        }
        for idx in (1..archive_idx).rev() {
            inputs.extend(read_all_json_lines(&rotated_path(path, idx)));
        }
        if path.exists() {
            inputs.extend(read_all_json_lines(path));
        }
        inputs
    }

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-persistence-test-{nonce}"))
    }

    fn fixture_event(event_id: &str) -> EventEnvelope {
        let mut attributes = JsonMap::new();
        attributes.insert("request_id".to_owned(), json!(format!("req-{event_id}")));
        attributes.insert("transport".to_owned(), json!("https"));
        attributes.insert("target_hint".to_owned(), json!("repo.example/target"));

        EventEnvelope {
            event_id: event_id.to_owned(),
            timestamp: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
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
                target: Some(format!("/tmp/{event_id}.txt")),
                attributes,
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

    fn fixture_request(approval_id: &str) -> ApprovalRequest {
        let mut attributes = JsonMap::new();
        attributes.insert("target_hint".to_owned(), json!("repo.example/target"));

        ApprovalRequest {
            approval_id: approval_id.to_owned(),
            status: ApprovalStatus::Pending,
            requested_at: chrono::Utc.timestamp_opt(1_700_000_005, 0).unwrap(),
            resolved_at: None,
            expires_at: None,
            session_id: "sess-test".to_owned(),
            event_id: Some("evt-1".to_owned()),
            request: ApprovalRequestAction {
                action_class: ActionClass::Filesystem,
                action_verb: "read".to_owned(),
                target: Some("/tmp/file.txt".to_owned()),
                summary: Some("read /tmp/file.txt".to_owned()),
                attributes,
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
            integrity: None,
        }
    }
}
