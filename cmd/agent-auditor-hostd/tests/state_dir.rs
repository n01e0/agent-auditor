mod common;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use common::keyed_lines;

#[test]
fn hostd_state_dir_routes_runtime_stores_and_keeps_records_durable() {
    let state_dir = unique_state_dir();

    let first = run_hostd_with_state_dir(&state_dir);
    let first_lines = keyed_lines(&first);
    assert_eq!(
        first_lines.get("runtime_state_dir").map(String::as_str),
        Some(state_dir.to_str().expect("state dir should be utf-8"))
    );
    assert_eq!(
        first_lines.get("filesystem_store_root").map(String::as_str),
        Some(
            state_dir
                .join("agent-auditor-hostd-poc-store")
                .to_str()
                .expect("filesystem store root should be utf-8")
        )
    );

    let filesystem_audit_log = state_dir
        .join("agent-auditor-hostd-poc-store")
        .join("audit-records.jsonl");
    let filesystem_approval_log = state_dir
        .join("agent-auditor-hostd-poc-store")
        .join("approval-requests.jsonl");
    let first_audit_lines = nonempty_line_count(&filesystem_audit_log);
    let first_approval_lines = nonempty_line_count(&filesystem_approval_log);
    assert!(
        first_audit_lines > 0,
        "first run should write audit records"
    );
    assert!(
        first_approval_lines > 0,
        "first run should write approval requests"
    );

    let second = run_hostd_with_state_dir(&state_dir);
    let second_lines = keyed_lines(&second);
    assert_eq!(
        second_lines.get("runtime_state_dir").map(String::as_str),
        Some(state_dir.to_str().expect("state dir should be utf-8"))
    );
    assert_eq!(
        nonempty_line_count(&filesystem_audit_log),
        first_audit_lines * 2,
        "second run should append to the durable audit log instead of wiping it"
    );
    assert_eq!(
        nonempty_line_count(&filesystem_approval_log),
        first_approval_lines * 2,
        "second run should append to the durable approval log instead of wiping it"
    );
}

fn run_hostd_with_state_dir(state_dir: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-auditor-hostd"))
        .args([
            "--state-dir",
            state_dir.to_str().expect("state dir should be utf-8"),
        ])
        .output()
        .expect("hostd binary should run with state dir");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("stdout should be utf-8")
}

fn nonempty_line_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn unique_state_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should advance")
        .as_nanos();
    std::env::temp_dir().join(format!("agent-auditor-hostd-runtime-state-test-{nonce}"))
}
