use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use agenta_core::{
    Action, ActionClass, Actor, ActorKind, ApprovalPolicy, ApprovalRequest, ApprovalRequestAction,
    ApprovalStatus, CollectorKind, EventEnvelope, EventType, RequesterContext, ResultInfo,
    ResultStatus, SessionRef, SourceInfo,
};
use chrono::TimeZone;
use serde_json::json;

#[test]
fn audit_list_tail_and_show_read_durable_store_records() {
    let state_dir = unique_state_dir();
    let store_dir = state_dir.join("agent-auditor-hostd-poc-store");
    fs::create_dir_all(&store_dir).expect("store dir should exist");

    fs::write(
        store_dir.join("audit-records.1.jsonl"),
        format!(
            "{}\n",
            serde_json::to_string(&sample_audit_record("evt-older", 1)).unwrap()
        ),
    )
    .expect("rotated audit log should exist");
    fs::write(
        store_dir.join("audit-records.jsonl"),
        format!(
            "{}\n",
            serde_json::to_string(&sample_audit_record("evt-newer", 2)).unwrap()
        ),
    )
    .expect("active audit log should exist");
    fs::write(
        store_dir.join("approval-requests.jsonl"),
        format!(
            "{}\n",
            serde_json::to_string(&sample_approval_record("apr-1", 3)).unwrap()
        ),
    )
    .expect("approval log should exist");

    let list_output = run_cli([
        "audit",
        "list",
        "--state-dir",
        state_dir.to_str().expect("state dir should be utf-8"),
    ]);
    assert!(list_output.contains("kind=approval"));
    assert!(list_output.contains("id=apr-1"));
    assert!(list_output.contains("id=evt-newer"));
    assert!(list_output.contains("id=evt-older"));

    let tail_output = run_cli([
        "audit",
        "tail",
        "--state-dir",
        state_dir.to_str().expect("state dir should be utf-8"),
        "--kind",
        "audit",
        "--count",
        "1",
    ]);
    assert!(tail_output.contains("id=evt-newer"));
    assert!(!tail_output.contains("id=evt-older"));
    assert!(!tail_output.contains("id=apr-1"));

    let show_output = run_cli([
        "audit",
        "show",
        "--state-dir",
        state_dir.to_str().expect("state dir should be utf-8"),
        "apr-1",
    ]);
    assert!(show_output.contains("\"kind\": \"approval\""));
    assert!(show_output.contains("\"approval_id\": \"apr-1\""));
    assert!(show_output.contains("\"local_inspection\""));
    assert!(show_output.contains("\"observation_local_inspection\""));
    assert!(show_output.contains("\"evidence_tier\": \"fixture_preview\""));

    let audit_show_output = run_cli([
        "audit",
        "show",
        "--state-dir",
        state_dir.to_str().expect("state dir should be utf-8"),
        "evt-newer",
    ]);
    assert!(audit_show_output.contains("\"kind\": \"audit\""));
    assert!(audit_show_output.contains("\"observation_local_inspection\""));
    assert!(audit_show_output.contains("\"validation_status\": \"validated_observation\""));
    assert!(audit_show_output.contains("\"observation_provenance\": \"observed_request\""));
}

fn run_cli<const N: usize>(args: [&str; N]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-auditor-cli"))
        .args(args)
        .output()
        .expect("cli should run");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("stdout should be utf-8")
}

fn sample_audit_record(event_id: &str, second: i64) -> EventEnvelope {
    let mut attributes = agenta_core::JsonMap::new();
    attributes.insert(
        "live_request_source_kind".to_owned(),
        json!("live_proxy_observed"),
    );
    attributes.insert(
        "validation_status".to_owned(),
        json!("validated_observation"),
    );
    attributes.insert(
        "validation_capture_source".to_owned(),
        json!("forward_proxy_observed_runtime_path"),
    );
    attributes.insert(
        "session_correlation_status".to_owned(),
        json!("runtime_path_confirmed"),
    );

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

fn sample_approval_record(approval_id: &str, second: i64) -> ApprovalRequest {
    let mut attributes = agenta_core::JsonMap::new();
    attributes.insert(
        "observation_provenance".to_owned(),
        json!("fixture_preview"),
    );
    attributes.insert("validation_status".to_owned(), json!("fixture_preview"));
    attributes.insert(
        "session_correlation_status".to_owned(),
        json!("fixture_lineage"),
    );

    ApprovalRequest {
        approval_id: approval_id.to_owned(),
        status: ApprovalStatus::Pending,
        requested_at: chrono::Utc
            .timestamp_opt(1_700_000_000 + second, 0)
            .unwrap(),
        resolved_at: None,
        expires_at: None,
        session_id: "sess-test".to_owned(),
        event_id: Some("evt-newer".to_owned()),
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
    }
}

fn unique_state_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should advance")
        .as_nanos();
    std::env::temp_dir().join(format!("agent-auditor-cli-integration-test-{nonce}"))
}
