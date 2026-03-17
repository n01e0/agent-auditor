use agenta_core::SessionRecord;

fn main() {
    let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
    let aya_type = std::any::type_name::<aya::Ebpf>();

    println!("agent-auditor-hostd bootstrap");
    println!(
        "session_id={} agent_id={}",
        session.session_id, session.agent_id
    );
    println!("ebpf_stack={aya_type}");
}
