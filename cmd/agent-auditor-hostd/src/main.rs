use agent_auditor_hostd::poc::{
    HostdPocPlan,
    filesystem::persist::FilesystemPocStore,
    network::{
        contract::{ClassifiedNetworkConnect, DestinationScope},
        persist::NetworkPocStore,
    },
    secret::{
        contract::{BrokeredSecretRequest, ClassifiedSecretAccess, SecretPathAccess},
        persist::SecretPocStore,
    },
};
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
    println!("network_observe={}", plan.network.observe.summary());
    println!("network_classify={}", plan.network.classify.summary());
    println!("network_emit={}", plan.network.emit.summary());
    println!("secret_classify={}", plan.secret.classify.summary());
    println!("secret_evaluate={}", plan.secret.evaluate.summary());
    println!("secret_record={}", plan.secret.record.summary());
    println!(
        "enforcement_decision={}",
        plan.enforcement.decision.summary()
    );
    println!("enforcement_hold={}", plan.enforcement.hold.summary());
    println!("enforcement_deny={}", plan.enforcement.deny.summary());
    println!("enforcement_audit={}", plan.enforcement.audit.summary());

    let network_delivery = match plan.network.observe.preview_connect_delivery() {
        Ok(delivered) => delivered,
        Err(error) => {
            eprintln!("event_log_network_error={error}");
            std::process::exit(1);
        }
    };
    println!("event_log_network={}", network_delivery.log_line);

    let classified_network = plan
        .network
        .classify
        .classify_connect(&network_delivery.event);

    let preview_network_policy = |classified: &ClassifiedNetworkConnect| {
        let normalized = plan
            .network
            .emit
            .normalize_classified_connect(classified, &session);
        let input = PolicyInput::from_event(&normalized);
        RegoPolicyEvaluator::network_destination_example()
            .evaluate(&input)
            .map(|decision| {
                let enriched = apply_decision_to_event(&normalized, &decision);
                let approval_request = approval_request_from_decision(&enriched, &decision);
                (normalized, enriched, decision, approval_request)
            })
    };

    let (
        normalized_network_observed,
        normalized_network,
        network_policy_decision,
        network_approval_request,
    ) = match preview_network_policy(&classified_network) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("network_policy_error={error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string(&normalized_network_observed) {
        Ok(json) => println!("normalized_network_observed={json}"),
        Err(error) => {
            eprintln!("normalized_network_observed_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&normalized_network) {
        Ok(json) => println!("normalized_network={json}"),
        Err(error) => {
            eprintln!("normalized_network_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_policy_decision) {
        Ok(json) => println!("network_policy_decision={json}"),
        Err(error) => {
            eprintln!("network_policy_decision_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_approval_request) {
        Ok(json) => println!("network_approval_request={json}"),
        Err(error) => {
            eprintln!("network_approval_request_error={error}");
            std::process::exit(1);
        }
    }

    let network_require_approval = ClassifiedNetworkConnect {
        pid: 5252,
        sock_fd: 8,
        destination_ip: "203.0.113.10".to_owned(),
        destination_port: 443,
        transport: "tcp".to_owned(),
        address_family: "inet".to_owned(),
        destination_scope: DestinationScope::Public,
        domain_candidate: None,
        domain_attribution_source: None,
    };
    let (
        _,
        normalized_network_require_approval,
        network_policy_decision_require_approval,
        network_approval_request_require_approval,
    ) = match preview_network_policy(&network_require_approval) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("network_policy_require_approval_error={error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string(&normalized_network_require_approval) {
        Ok(json) => println!("normalized_network_require_approval={json}"),
        Err(error) => {
            eprintln!("normalized_network_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_policy_decision_require_approval) {
        Ok(json) => println!("network_policy_decision_require_approval={json}"),
        Err(error) => {
            eprintln!("network_policy_decision_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_approval_request_require_approval) {
        Ok(json) => println!("network_approval_request_require_approval={json}"),
        Err(error) => {
            eprintln!("network_approval_request_require_approval_error={error}");
            std::process::exit(1);
        }
    }

    let network_deny = ClassifiedNetworkConnect {
        pid: 6262,
        sock_fd: 9,
        destination_ip: "198.51.100.25".to_owned(),
        destination_port: 25,
        transport: "tcp".to_owned(),
        address_family: "inet".to_owned(),
        destination_scope: DestinationScope::Public,
        domain_candidate: None,
        domain_attribution_source: None,
    };
    let (_, normalized_network_deny, network_policy_decision_deny, network_approval_request_deny) =
        match preview_network_policy(&network_deny) {
            Ok(preview) => preview,
            Err(error) => {
                eprintln!("network_policy_deny_error={error}");
                std::process::exit(1);
            }
        };
    match serde_json::to_string(&normalized_network_deny) {
        Ok(json) => println!("normalized_network_deny={json}"),
        Err(error) => {
            eprintln!("normalized_network_deny_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_policy_decision_deny) {
        Ok(json) => println!("network_policy_decision_deny={json}"),
        Err(error) => {
            eprintln!("network_policy_decision_deny_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&network_approval_request_deny) {
        Ok(json) => println!("network_approval_request_deny={json}"),
        Err(error) => {
            eprintln!("network_approval_request_deny_error={error}");
            std::process::exit(1);
        }
    }

    let network_store = match NetworkPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("network_store_error={error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = network_store.append_audit_record(&normalized_network) {
        eprintln!("persisted_network_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match network_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_network_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_network_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_network_audit_record_allow_error=missing persisted network audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_network_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }

    if let Err(error) = network_store.append_audit_record(&normalized_network_require_approval) {
        eprintln!("persisted_network_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match network_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_network_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_network_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_network_audit_record_require_approval_error=missing persisted network audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_network_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }

    if let Err(error) = network_store.append_audit_record(&normalized_network_deny) {
        eprintln!("persisted_network_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match network_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_network_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_network_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_network_audit_record_deny_error=missing persisted network audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_network_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }

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
        let observed = plan
            .filesystem
            .emit
            .normalize_classified_access(access, &session);
        let input = PolicyInput::from_event(&observed);
        RegoPolicyEvaluator::sensitive_filesystem_example()
            .evaluate(&input)
            .and_then(|decision| {
                let normalized = apply_decision_to_event(&observed, &decision);
                let approval_request = approval_request_from_decision(&normalized, &decision);
                plan.enforcement
                    .preview_filesystem_outcome(&normalized, &decision, approval_request.as_ref())
                    .map(|enforcement| (normalized, decision, approval_request, enforcement))
                    .map_err(|error| {
                        agenta_policy::PolicyError::Evaluate(format!(
                            "filesystem enforcement preview failed: {error}"
                        ))
                    })
            })
    };

    let (
        normalized_filesystem,
        filesystem_policy_decision,
        approval_request,
        filesystem_enforcement,
    ) = match preview_filesystem_policy(&filesystem_access) {
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

    match serde_json::to_string(&filesystem_enforcement) {
        Ok(json) => println!("filesystem_enforcement={json}"),
        Err(error) => {
            eprintln!("filesystem_enforcement_error={error}");
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

    let (
        normalized_filesystem_allow,
        filesystem_policy_decision_allow,
        approval_request_allow,
        filesystem_enforcement_allow,
    ) = match preview_filesystem_policy(&filesystem_access_allow) {
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

    match serde_json::to_string(&filesystem_enforcement_allow) {
        Ok(json) => println!("filesystem_enforcement_allow={json}"),
        Err(error) => {
            eprintln!("filesystem_enforcement_allow_error={error}");
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

    let filesystem_access_deny =
        plan.filesystem
            .classify
            .classify_access(4444, 19, "write", "/home/agent/.ssh/config");
    println!(
        "event_log_filesystem_deny={}",
        filesystem_access_deny.log_line(plan.filesystem.emit.collector)
    );

    let (
        normalized_filesystem_deny,
        filesystem_policy_decision_deny,
        approval_request_deny,
        filesystem_enforcement_deny,
    ) = match preview_filesystem_policy(&filesystem_access_deny) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("filesystem_policy_deny_error={error}");
            std::process::exit(1);
        }
    };

    match serde_json::to_string(&normalized_filesystem_deny) {
        Ok(json) => println!("normalized_filesystem_deny={json}"),
        Err(error) => {
            eprintln!("normalized_filesystem_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&filesystem_policy_decision_deny) {
        Ok(json) => println!("filesystem_policy_decision_deny={json}"),
        Err(error) => {
            eprintln!("filesystem_policy_decision_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&filesystem_enforcement_deny) {
        Ok(json) => println!("filesystem_enforcement_deny={json}"),
        Err(error) => {
            eprintln!("filesystem_enforcement_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&approval_request_deny) {
        Ok(json) => println!("filesystem_approval_request_deny={json}"),
        Err(error) => {
            eprintln!("filesystem_approval_request_deny_error={error}");
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

    let preview_secret_policy = |classified: &ClassifiedSecretAccess| {
        let normalized = plan
            .secret
            .evaluate
            .normalize_classified_access(classified, &session);
        let input = PolicyInput::from_event(&normalized);
        RegoPolicyEvaluator::secret_access_example()
            .evaluate(&input)
            .map(|decision| {
                let enriched = apply_decision_to_event(&normalized, &decision);
                let approval_request = approval_request_from_decision(&enriched, &decision);
                (normalized, enriched, decision, approval_request)
            })
    };

    let secret_access_allow = match plan
        .secret
        .classify
        .classify_path_access(&SecretPathAccess {
            operation: "read".to_owned(),
            path: "/workspace/.env.production".to_owned(),
            mount_id: Some(18),
        }) {
        Some(classified) => classified,
        None => {
            eprintln!(
                "secret_allow_classification_error=expected env file secret access to classify"
            );
            std::process::exit(1);
        }
    };
    println!("event_log_secret_allow={}", secret_access_allow.log_line());

    let (
        normalized_secret_allow_observed,
        normalized_secret_allow,
        secret_policy_decision_allow,
        secret_approval_request_allow,
    ) = match preview_secret_policy(&secret_access_allow) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("secret_policy_allow_error={error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string(&normalized_secret_allow_observed) {
        Ok(json) => println!("normalized_secret_allow_observed={json}"),
        Err(error) => {
            eprintln!("normalized_secret_allow_observed_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&normalized_secret_allow) {
        Ok(json) => println!("normalized_secret_allow={json}"),
        Err(error) => {
            eprintln!("normalized_secret_allow_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_policy_decision_allow) {
        Ok(json) => println!("secret_policy_decision_allow={json}"),
        Err(error) => {
            eprintln!("secret_policy_decision_allow_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_approval_request_allow) {
        Ok(json) => println!("secret_approval_request_allow={json}"),
        Err(error) => {
            eprintln!("secret_approval_request_allow_error={error}");
            std::process::exit(1);
        }
    }

    let secret_access_require_approval =
        plan.secret
            .classify
            .classify_broker_request(&BrokeredSecretRequest {
                operation: "fetch".to_owned(),
                broker_id: "vault".to_owned(),
                broker_action: "read".to_owned(),
                secret_locator_hint: "kv/prod/db/password".to_owned(),
            });
    println!(
        "event_log_secret_require_approval={}",
        secret_access_require_approval.log_line()
    );

    let (
        normalized_secret_require_approval_observed,
        normalized_secret_require_approval,
        secret_policy_decision_require_approval,
        secret_approval_request_require_approval,
    ) = match preview_secret_policy(&secret_access_require_approval) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("secret_policy_require_approval_error={error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string(&normalized_secret_require_approval_observed) {
        Ok(json) => println!("normalized_secret_require_approval_observed={json}"),
        Err(error) => {
            eprintln!("normalized_secret_require_approval_observed_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&normalized_secret_require_approval) {
        Ok(json) => println!("normalized_secret_require_approval={json}"),
        Err(error) => {
            eprintln!("normalized_secret_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_policy_decision_require_approval) {
        Ok(json) => println!("secret_policy_decision_require_approval={json}"),
        Err(error) => {
            eprintln!("secret_policy_decision_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_approval_request_require_approval) {
        Ok(json) => println!("secret_approval_request_require_approval={json}"),
        Err(error) => {
            eprintln!("secret_approval_request_require_approval_error={error}");
            std::process::exit(1);
        }
    }

    let secret_access_deny = match plan
        .secret
        .classify
        .classify_path_access(&SecretPathAccess {
            operation: "read".to_owned(),
            path: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_owned(),
            mount_id: Some(23),
        }) {
        Some(classified) => classified,
        None => {
            eprintln!(
                "secret_deny_classification_error=expected kubernetes service account access to classify"
            );
            std::process::exit(1);
        }
    };
    println!("event_log_secret_deny={}", secret_access_deny.log_line());

    let (
        normalized_secret_deny_observed,
        normalized_secret_deny,
        secret_policy_decision_deny,
        secret_approval_request_deny,
    ) = match preview_secret_policy(&secret_access_deny) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("secret_policy_deny_error={error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string(&normalized_secret_deny_observed) {
        Ok(json) => println!("normalized_secret_deny_observed={json}"),
        Err(error) => {
            eprintln!("normalized_secret_deny_observed_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&normalized_secret_deny) {
        Ok(json) => println!("normalized_secret_deny={json}"),
        Err(error) => {
            eprintln!("normalized_secret_deny_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_policy_decision_deny) {
        Ok(json) => println!("secret_policy_decision_deny={json}"),
        Err(error) => {
            eprintln!("secret_policy_decision_deny_error={error}");
            std::process::exit(1);
        }
    }
    match serde_json::to_string(&secret_approval_request_deny) {
        Ok(json) => println!("secret_approval_request_deny={json}"),
        Err(error) => {
            eprintln!("secret_approval_request_deny_error={error}");
            std::process::exit(1);
        }
    }

    let secret_store = match SecretPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("secret_store_error={error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = secret_store.append_audit_record(&normalized_secret_allow) {
        eprintln!("persisted_secret_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match secret_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_secret_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_secret_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_secret_audit_record_allow_error=missing persisted secret audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_secret_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }

    if let Err(error) = secret_store.append_audit_record(&normalized_secret_require_approval) {
        eprintln!("persisted_secret_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match secret_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_secret_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_secret_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_secret_audit_record_require_approval_error=missing persisted secret audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_secret_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }

    if let Some(request) = &secret_approval_request_require_approval
        && let Err(error) = secret_store.append_approval_request(request)
    {
        eprintln!("persisted_secret_approval_request_error={error}");
        std::process::exit(1);
    }
    match (
        &secret_approval_request_require_approval,
        secret_store.latest_approval_request(),
    ) {
        (Some(_), Ok(Some(record))) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_secret_approval_request={json}"),
            Err(error) => {
                eprintln!("persisted_secret_approval_request_error={error}");
                std::process::exit(1);
            }
        },
        (Some(_), Ok(None)) => {
            eprintln!(
                "persisted_secret_approval_request_error=missing persisted secret approval request"
            );
            std::process::exit(1);
        }
        (Some(_), Err(error)) => {
            eprintln!("persisted_secret_approval_request_error={error}");
            std::process::exit(1);
        }
        (None, _) => {}
    }

    if let Err(error) = secret_store.append_audit_record(&normalized_secret_deny) {
        eprintln!("persisted_secret_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match secret_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_secret_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_secret_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_secret_audit_record_deny_error=missing persisted secret audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_secret_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }
}
