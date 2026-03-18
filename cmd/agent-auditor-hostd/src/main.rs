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
    match plan.event_path.preview_exec_delivery() {
        Ok(delivered) => println!("event_log={}", delivered.log_line),
        Err(error) => {
            eprintln!("event_log_error={error}");
            std::process::exit(1);
        }
    }
}
