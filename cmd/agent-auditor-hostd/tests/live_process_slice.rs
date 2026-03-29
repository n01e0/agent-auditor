use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use agent_auditor_hostd::poc::{
    event_path::{ExecEvent, ExitEvent, OpenClawLineage},
    filesystem::persist::FilesystemPocStore,
    process_live::{FixtureProcessEventSource, LiveProcessEvent, LiveProcessRecorder},
};
use agenta_core::{CollectorKind, EventType, SessionRecord};

#[test]
fn synthetic_live_process_source_flows_through_normalize_and_persist() {
    let root = unique_test_root();
    let store = FilesystemPocStore::fresh(&root).expect("store should init");
    let mut recorder = LiveProcessRecorder::new(
        SessionRecord::placeholder("openclaw-main", "sess_live_process_integration"),
        store.clone(),
        CollectorKind::RuntimeHint,
        "host-integration",
    );
    let mut source = FixtureProcessEventSource::new([
        LiveProcessEvent::Exec(ExecEvent {
            pid: 5151,
            ppid: 2020,
            uid: 1000,
            gid: 1000,
            command: "sleep".to_owned(),
            filename: "/usr/bin/sleep".to_owned(),
            exe: "/usr/bin/sleep".to_owned(),
            argv: vec!["/usr/bin/sleep".to_owned(), "5".to_owned()],
            cwd: "/tmp/live-process-integration".to_owned(),
            openclaw_lineage: Some(OpenClawLineage {
                agent_id: "openclaw-main".to_owned(),
                session_id: "sess_live_process_integration".to_owned(),
                request_id: Some("req_live_process_sleep".to_owned()),
            }),
        }),
        LiveProcessEvent::Exit(ExitEvent {
            pid: 5151,
            ppid: 2020,
            exit_code: 0,
        }),
    ]);

    let envelopes = recorder
        .drain_available(&mut source)
        .expect("synthetic source should drain");

    assert_eq!(envelopes.len(), 2);
    assert_eq!(envelopes[0].event_type, EventType::ProcessExec);
    assert_eq!(envelopes[1].event_type, EventType::ProcessExit);
    assert_eq!(
        envelopes[0].source.host_id.as_deref(),
        Some("host-integration")
    );
    assert_eq!(
        envelopes[1]
            .action
            .attributes
            .get("filename")
            .and_then(|value| value.as_str()),
        Some("/usr/bin/sleep")
    );
    assert_eq!(
        envelopes[0]
            .action
            .attributes
            .get("exe")
            .and_then(|value| value.as_str()),
        Some("/usr/bin/sleep")
    );
    assert_eq!(
        envelopes[0]
            .action
            .attributes
            .get("cwd")
            .and_then(|value| value.as_str()),
        Some("/tmp/live-process-integration")
    );
    assert_eq!(
        envelopes[0].action.attributes.get("argv"),
        Some(&serde_json::json!(["/usr/bin/sleep", "5"]))
    );
    assert_eq!(
        envelopes[0].action.attributes.get("lineage_agent_id"),
        Some(&serde_json::json!("openclaw-main"))
    );
    assert_eq!(
        envelopes[0].action.attributes.get("lineage_session_id"),
        Some(&serde_json::json!("sess_live_process_integration"))
    );
    assert_eq!(
        envelopes[0].action.attributes.get("lineage_request_id"),
        Some(&serde_json::json!("req_live_process_sleep"))
    );
    assert_eq!(
        envelopes[1].action.attributes.get("lineage_request_id"),
        Some(&serde_json::json!("req_live_process_sleep"))
    );
    assert_eq!(
        envelopes[0].source.host_id.as_deref(),
        Some("host-integration")
    );

    let audit_log = fs::read_to_string(store.paths().audit_log.clone())
        .expect("audit log should be readable after persistence");
    let lines: Vec<_> = audit_log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"process_exec\""));
    assert!(lines[1].contains("\"process_exit\""));
}

fn unique_test_root() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should advance")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "agent-auditor-hostd-live-process-integration-{nonce}"
    ))
}
