use agenta_core::{CoverageLevel, SessionRecord};

fn main() {
    let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_cli");
    let process_coverage = session
        .coverage
        .as_ref()
        .and_then(|coverage| coverage.process)
        .unwrap_or(CoverageLevel::None);

    println!("agent-auditor-cli bootstrap");
    println!(
        "session={} process_coverage={process_coverage:?}",
        session.session_id
    );
}
