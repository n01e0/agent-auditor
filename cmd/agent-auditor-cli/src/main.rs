mod audit;

use agenta_core::{CoverageLevel, SessionRecord};

fn main() {
    let mut args = std::env::args().skip(1);
    if matches!(args.next().as_deref(), Some("audit")) {
        match audit::parse_command(args) {
            Ok(command) => {
                if let Err(error) = audit::run(command) {
                    eprintln!("audit_error={error}");
                    std::process::exit(1);
                }
                return;
            }
            Err(error) => {
                eprintln!("cli_error={error}");
                std::process::exit(2);
            }
        }
    }

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
