use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::runtime;

pub const AUDIT_LOG_FILENAME: &str = "audit-records.jsonl";
pub const APPROVAL_LOG_FILENAME: &str = "approval-requests.jsonl";

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

pub fn bootstrap_paths(store_dir_name: &str) -> Result<PersistencePaths, PersistenceError> {
    let root = runtime::runtime_store_root(store_dir_name);
    if runtime::configured_state_dir().is_some() {
        durable_paths(root)
    } else {
        fresh_paths(root)
    }
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
