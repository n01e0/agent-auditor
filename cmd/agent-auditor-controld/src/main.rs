use agenta_core::{Action, ActionClass, Actor, ActorKind, SessionRef};
use agenta_policy::PolicyInput;
use std::collections::BTreeMap;

fn main() {
    let input = PolicyInput::new(
        "req_bootstrap_controld",
        SessionRef {
            session_id: "sess_bootstrap_controld".to_owned(),
            agent_id: Some("openclaw-main".to_owned()),
            initiator_id: Some("user:n01e0".to_owned()),
            workspace_id: None,
            policy_bundle_version: Some("bundle-bootstrap".to_owned()),
            environment: Some("dev".to_owned()),
        },
        Actor {
            kind: ActorKind::Agent,
            id: Some("openclaw-main".to_owned()),
            display_name: Some("OpenClaw Main".to_owned()),
        },
        Action {
            class: ActionClass::Filesystem,
            verb: Some("read".to_owned()),
            target: Some("/var/run/secrets/demo".to_owned()),
            attributes: BTreeMap::new(),
        },
    );

    println!("agent-auditor-controld bootstrap");
    println!(
        "request_id={} action_class={:?}",
        input.request_id, input.action.class
    );
}
