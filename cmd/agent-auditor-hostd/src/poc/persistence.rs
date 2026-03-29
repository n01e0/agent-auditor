use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::runtime;

pub const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";
pub const APPROVAL_LOG_FILENAME: &str = "approval-requests.jsonl";
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistencePaths {
    pub root: PathBuf,
    pub audit_log: PathBuf,
    pub approval_log: PathBuf,
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
        root,
    })
}

pub fn append_json_line<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), PersistenceError> {
    append_json_line_with_policy(path, value, LogRotationPolicy::default())
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

fn rotate_log_if_needed(
    path: &Path,
    next_json: &str,
    policy: LogRotationPolicy,
) -> Result<(), PersistenceError> {
    let current_size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(PersistenceError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let next_len = next_json.len() as u64 + 1;
    if current_size.saturating_add(next_len) <= policy.max_bytes {
        return Ok(());
    }

    if policy.retained_archives == 0 {
        fs::remove_file(path).map_err(|source| PersistenceError::Rotate {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(());
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

    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::{
        LogRotationPolicy, append_json_line_with_policy, durable_paths, fresh_paths, rotated_path,
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

        let paths = fresh_paths(&root).expect("fresh paths should reset test roots");

        assert!(!paths.root.join("audit-records.1.jsonl").exists());
        assert!(!paths.audit_log.exists());
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

    fn unique_test_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        env::temp_dir().join(format!("agent-auditor-hostd-persistence-test-{nonce}"))
    }
}
