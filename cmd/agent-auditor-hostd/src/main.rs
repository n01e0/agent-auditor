use agent_auditor_hostd::poc::{HostdPocPlan, filesystem::persist::FilesystemPocStore};
use agenta_core::SessionRecord;
use agenta_policy::{
    PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
    approval_request_from_decision,
};

fn main() {
    let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
    let plan = HostdPocPlan::bootstrap();

    println!("agent-auditor-hostd bootstrap");
    println!(
        "session_id={} agent_id={}",
        session.session_id, session.agent_id
    );
    println!("loader={}", plan.loader.summary());
    match plan.loader.load_embedded_object() {
        Ok(loaded) => println!("loader_runtime={}", loaded.summary()),
        Err(error) => {
            eprintln!("loader_runtime_error={error}");
            std::process::exit(1);
        }
    }
    println!("event_path={}", plan.event_path.summary());
    println!("filesystem_watch={}", plan.filesystem.watch.summary());
    println!("filesystem_classify={}", plan.filesystem.classify.summary());
    println!("filesystem_emit={}", plan.filesystem.emit.summary());

    let exec_delivery = match plan.event_path.preview_exec_delivery() {
        Ok(delivered) => delivered,
        Err(error) => {
            eprintln!("event_log_exec_error={error}");
            std::process::exit(1);
        }
    };
    println!("event_log_exec={}", exec_delivery.log_line);

    let exit_delivery = match plan.event_path.preview_exit_delivery() {
        Ok(delivered) => delivered,
        Err(error) => {
            eprintln!("event_log_exit_error={error}");
            std::process::exit(1);
        }
    };
    println!("event_log_exit={}", exit_delivery.log_line);

    let lifecycle_record = match plan.event_path.preview_exec_exit_lifecycle() {
        Ok(record) => record,
        Err(error) => {
            eprintln!("lifecycle_log_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "lifecycle_log={}",
        lifecycle_record.summary_line(plan.event_path.transport)
    );

    let normalized_exec = plan
        .event_path
        .normalize_exec_event(&exec_delivery.event, &session);
    match serde_json::to_string(&normalized_exec) {
        Ok(json) => println!("normalized_exec={json}"),
        Err(error) => {
            eprintln!("normalized_exec_error={error}");
            std::process::exit(1);
        }
    }

    let normalized_exit = plan.event_path.normalize_exit_event(
        &exit_delivery.event,
        Some(&lifecycle_record),
        &session,
    );
    match serde_json::to_string(&normalized_exit) {
        Ok(json) => println!("normalized_exit={json}"),
        Err(error) => {
            eprintln!("normalized_exit_error={error}");
            std::process::exit(1);
        }
    }

    let filesystem_access = plan.filesystem.classify.preview_sensitive_access();
    println!(
        "event_log_filesystem={}",
        filesystem_access.log_line(plan.filesystem.emit.collector)
    );

    let preview_filesystem_policy = |access: &_| {
        let normalized = plan
            .filesystem
            .emit
            .normalize_classified_access(access, &session);
        let input = PolicyInput::from_event(&normalized);
        RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .map(|decision| {
                let normalized = apply_decision_to_event(&normalized, &decision);
                let approval_request = approval_request_from_decision(&normalized, &decision);
                (normalized, decision, approval_request)
            })
    };

    let (normalized_filesystem, filesystem_policy_decision, approval_request) =
        match preview_filesystem_policy(&filesystem_access) {
            Ok(preview) => preview,
            Err(error) => {
                eprintln!("filesystem_policy_error={error}");
                std::process::exit(1);
            }
        };

    match serde_json::to_string(&normalized_filesystem) {
        Ok(json) => println!("normalized_filesystem={json}"),
        Err(error) => {
            eprintln!("normalized_filesystem_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&filesystem_policy_decision) {
        Ok(json) => println!("filesystem_policy_decision={json}"),
        Err(error) => {
            eprintln!("filesystem_policy_decision_error={error}");
            std::process::exit(1);
        }
    }

    let filesystem_access_allow =
        plan.filesystem
            .classify
            .classify_access(4343, 18, "read", "/workspace/src/main.rs");
    println!(
        "event_log_filesystem_allow={}",
        filesystem_access_allow.log_line(plan.filesystem.emit.collector)
    );

    let (normalized_filesystem_allow, filesystem_policy_decision_allow, approval_request_allow) =
        match preview_filesystem_policy(&filesystem_access_allow) {
            Ok(preview) => preview,
            Err(error) => {
                eprintln!("filesystem_policy_allow_error={error}");
                std::process::exit(1);
            }
        };

    match serde_json::to_string(&normalized_filesystem_allow) {
        Ok(json) => println!("normalized_filesystem_allow={json}"),
        Err(error) => {
            eprintln!("normalized_filesystem_allow_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&filesystem_policy_decision_allow) {
        Ok(json) => println!("filesystem_policy_decision_allow={json}"),
        Err(error) => {
            eprintln!("filesystem_policy_decision_allow_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&approval_request_allow) {
        Ok(json) => println!("filesystem_approval_request_allow={json}"),
        Err(error) => {
            eprintln!("filesystem_approval_request_allow_error={error}");
            std::process::exit(1);
        }
    }

    let store = match FilesystemPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("filesystem_store_error={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = store.append_audit_record(&normalized_filesystem) {
        eprintln!("persisted_audit_record_error={error}");
        std::process::exit(1);
    }
    if let Some(request) = &approval_request
        && let Err(error) = store.append_approval_request(request)
    {
        eprintln!("persisted_approval_request_error={error}");
        std::process::exit(1);
    }

    match store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_audit_record={json}"),
            Err(error) => {
                eprintln!("persisted_audit_record_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!("persisted_audit_record_error=missing persisted audit record");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_audit_record_error={error}");
            std::process::exit(1);
        }
    }

    match (approval_request, store.latest_approval_request()) {
        (Some(_), Ok(Some(record))) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_approval_request={json}"),
            Err(error) => {
                eprintln!("persisted_approval_request_error={error}");
                std::process::exit(1);
            }
        },
        (Some(_), Ok(None)) => {
            eprintln!("persisted_approval_request_error=missing persisted approval request");
            std::process::exit(1);
        }
        (Some(_), Err(error)) => {
            eprintln!("persisted_approval_request_error={error}");
            std::process::exit(1);
        }
        (None, _) => {}
    }
}
