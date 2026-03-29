use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use thiserror::Error;

static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigureStateDirError {
    #[error(
        "hostd runtime state dir already configured as `{existing}` and cannot change to `{attempted}`"
    )]
    Conflict {
        existing: PathBuf,
        attempted: PathBuf,
    },
}

pub fn configure_state_dir(state_dir: Option<PathBuf>) -> Result<(), ConfigureStateDirError> {
    let Some(state_dir) = state_dir else {
        return Ok(());
    };

    if let Some(existing) = STATE_DIR.get() {
        if existing == &state_dir {
            return Ok(());
        }
        return Err(ConfigureStateDirError::Conflict {
            existing: existing.clone(),
            attempted: state_dir,
        });
    }

    let _ = STATE_DIR.set(state_dir);
    Ok(())
}

pub fn configured_state_dir() -> Option<&'static Path> {
    STATE_DIR.get().map(PathBuf::as_path)
}

pub fn runtime_store_root(store_dir_name: &str) -> PathBuf {
    match configured_state_dir() {
        Some(state_dir) => state_dir.join(store_dir_name),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(store_dir_name),
    }
}
