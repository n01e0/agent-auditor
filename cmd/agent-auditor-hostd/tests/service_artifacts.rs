use std::{fs, path::PathBuf};

#[test]
fn systemd_service_uses_installed_binary_and_state_dir_outside_source_tree() {
    let service = read_deploy_file("agent-auditor-hostd.service");

    assert!(service.contains("ExecStart=${AGENT_AUDITOR_HOSTD_BIN} daemon --foreground --state-dir ${AGENT_AUDITOR_HOSTD_STATE_DIR}"));
    assert!(service.contains("StateDirectory=agent-auditor-hostd"));
    assert!(
        service.contains("Environment=AGENT_AUDITOR_HOSTD_BIN=/usr/local/bin/agent-auditor-hostd")
    );
    assert!(service.contains("Environment=AGENT_AUDITOR_HOSTD_STATE_DIR=%S/agent-auditor-hostd"));
    assert!(!service.contains("cargo run"));
    assert!(!service.contains("/home/shioriko/src"));
}

#[test]
fn sample_env_documents_source_tree_independent_state_dir_override() {
    let env_sample = read_deploy_file("agent-auditor-hostd.env.sample");

    assert!(env_sample.contains("AGENT_AUDITOR_HOSTD_BIN=/usr/local/bin/agent-auditor-hostd"));
    assert!(env_sample.contains("AGENT_AUDITOR_HOSTD_STATE_DIR=/var/lib/agent-auditor-hostd"));
    assert!(env_sample.contains("AGENT_AUDITOR_HOSTD_POLL_INTERVAL_MS=250"));
}

fn read_deploy_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/systemd")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}
