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
    println!("event_path={}", plan.event_path.summary());
}
