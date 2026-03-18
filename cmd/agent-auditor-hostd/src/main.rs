use agent_auditor_hostd::poc::HostdPocPlan;
use agenta_core::SessionRecord;

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
}
