mod daemon;

use agent_auditor_hostd::{
    poc::{
        HostdPocPlan,
        enforcement::contract::{EnforcementOutcome, EnforcementScope},
        event_path::ExecEvent,
        filesystem::persist::FilesystemPocStore,
        github::persist::GitHubPocStore,
        gws::{
            contract::ApiRequestObservation, persist::GwsPocStore,
            preview_provider_metadata_catalog,
        },
        live_proxy::forward_proxy::{ForwardProxyIngressInbox, ForwardProxyIngressRuntime},
        messaging::persist::MessagingPocStore,
        network::{
            contract::{ClassifiedNetworkConnect, DestinationScope},
            persist::NetworkPocStore,
        },
        process_live::{
            LiveProcessRecorder, ProcConnectorSource, current_host_id,
            preview_fixture_process_slice,
        },
        rest::persist::GenericRestPocStore,
        secret::{
            contract::{BrokeredSecretRequest, ClassifiedSecretAccess, SecretPathAccess},
            persist::SecretPocStore,
        },
    },
    runtime,
};
use agenta_core::{
    Action, ActionClass, Actor, ActorKind, ApprovalRequest, CollectorKind, EventEnvelope,
    EventType, JsonMap, PolicyDecision, PolicyDecisionKind, ResultInfo, ResultStatus,
    SessionRecord, SessionRef, Severity, SourceInfo,
    controlplane::{ApprovalLocalJsonlInspectionRecord, ApprovalQueueItem},
    provider::{ProviderAbstractionPlan, ProviderMetadataCatalog},
};
use agenta_policy::{
    PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
    apply_enforcement_to_approval_request, apply_enforcement_to_event,
    approval_request_from_decision,
};

fn print_local_jsonl_inspection_line(key: &str, request: &ApprovalRequest) {
    let inspection =
        ApprovalLocalJsonlInspectionRecord::derive(&ApprovalQueueItem::from_request(request));
    println!(
        "{}={}",
        key,
        serde_json::to_string(&inspection)
            .expect("approval local jsonl inspection record should serialize")
    );
}

fn main() {
    let cli = match daemon::CliConfig::parse(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("cli_error={error}");
            std::process::exit(2);
        }
    };

    if let Err(error) = runtime::configure_state_dir(cli.state_dir.clone()) {
        eprintln!("runtime_state_dir_error={error}");
        std::process::exit(2);
    }

    match cli.mode {
        daemon::CliMode::Preview => run_preview_or_exit(),
        daemon::CliMode::Daemon(config) => {
            if let Err(error) = run_daemon_or_exit(config) {
                eprintln!("daemon_error={error}");
                std::process::exit(1);
            }
        }
    }
}

fn run_daemon_or_exit(
    config: daemon::ForegroundDaemonConfig,
) -> Result<(), daemon::DaemonRunError> {
    run_preview_or_exit();

    let forward_proxy =
        ForwardProxyIngressRuntime::bootstrap().map_err(daemon::DaemonRunError::tick)?;
    println!(
        "forward_proxy_ingress_source={}",
        ForwardProxyIngressInbox::SOURCE_LABEL
    );
    println!(
        "forward_proxy_ingress_store_root={}",
        forward_proxy.store().paths().root.display()
    );
    println!(
        "forward_proxy_ingress_inbox={}",
        forward_proxy.inbox().paths().inbox.display()
    );
    println!(
        "forward_proxy_ingress_cursor={}",
        forward_proxy.inbox().paths().cursor.display()
    );

    println!("live_process_source={}", ProcConnectorSource::SOURCE_LABEL);
    let source = match ProcConnectorSource::listen() {
        Ok(source) => {
            println!("live_process_source_status=enabled");
            Some(source)
        }
        Err(error) => {
            println!("live_process_source_status=disabled");
            println!("live_process_source_error={error}");
            None
        }
    };

    run_hostd_daemon(config, source, forward_proxy)
}

fn run_hostd_daemon(
    config: daemon::ForegroundDaemonConfig,
    mut source: Option<ProcConnectorSource>,
    forward_proxy: ForwardProxyIngressRuntime,
) -> Result<(), daemon::DaemonRunError> {
    let mut recorder = if source.is_some() {
        Some(LiveProcessRecorder::new(
            SessionRecord::placeholder("agent-auditor-hostd", "sess_live_process"),
            FilesystemPocStore::bootstrap().map_err(daemon::DaemonRunError::tick)?,
            CollectorKind::RuntimeHint,
            current_host_id(),
        ))
    } else {
        None
    };

    if let Some(recorder) = recorder.as_ref() {
        println!("live_process_host_id={}", recorder.host_id());
        println!(
            "live_process_store_root={}",
            recorder.store().paths().root.display()
        );
    }

    daemon::run_foreground_daemon(
        config,
        || {},
        || {
            for record in forward_proxy
                .drain_available()
                .map_err(daemon::DaemonRunError::tick)?
            {
                println!(
                    "forward_proxy_ingress_record={}",
                    serde_json::to_string(&record.reflection.audit_record)
                        .map_err(daemon::DaemonRunError::tick)?
                );
                if let Some(approval_request) = record.approval.approval_request.as_ref() {
                    println!(
                        "forward_proxy_ingress_approval_request={}",
                        serde_json::to_string(approval_request)
                            .map_err(daemon::DaemonRunError::tick)?
                    );
                }
            }

            if let (Some(recorder), Some(source)) = (recorder.as_mut(), source.as_mut()) {
                for envelope in recorder
                    .drain_available(source)
                    .map_err(daemon::DaemonRunError::tick)?
                {
                    println!(
                        "live_process_audit={}",
                        serde_json::to_string(&envelope).map_err(daemon::DaemonRunError::tick)?
                    );
                }
            }
            Ok(())
        },
    )
}

fn run_preview_or_exit() {
    let session = SessionRecord::placeholder("openclaw-main", "sess_bootstrap_hostd");
    let plan = HostdPocPlan::bootstrap();

    println!("agent-auditor-hostd bootstrap");
    println!(
        "session_id={} agent_id={}",
        session.session_id, session.agent_id
    );
    println!(
        "runtime_state_dir={}",
        runtime::configured_state_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_owned())
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
    let provider_abstraction_plan = ProviderAbstractionPlan::bootstrap();
    let provider_metadata_catalog = preview_provider_metadata_catalog();
    println!(
        "provider_abstraction_plan={}",
        provider_abstraction_plan_summary(&provider_abstraction_plan)
    );
    println!(
        "provider_abstraction_catalog={}",
        provider_metadata_catalog_summary(&provider_metadata_catalog)
    );
    println!(
        "generic_rest_normalize={}",
        plan.generic_rest.normalize.summary()
    );
    println!("generic_rest_policy={}", plan.generic_rest.policy.summary());
    println!("generic_rest_record={}", plan.generic_rest.record.summary());
    println!("messaging_taxonomy={}", plan.messaging.taxonomy.summary());
    println!("messaging_policy={}", plan.messaging.policy.summary());
    println!("messaging_record={}", plan.messaging.record.summary());
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
        "gws_session_linkage={}",
        plan.api_network_gws.session_linkage.summary()
    );
    println!(
        "gws_session_linked_api={}",
        plan.api_network_gws
            .session_linkage
            .preview_session_linked_api_action(&session)
            .log_line()
    );
    println!(
        "gws_session_linked_network={}",
        plan.api_network_gws
            .session_linkage
            .preview_session_linked_network_action(&session)
            .log_line()
    );
    println!("gws_classify={}", plan.api_network_gws.classify.summary());
    let gws_classified_api = match plan.api_network_gws.classify.classify_action(
        &plan
            .api_network_gws
            .session_linkage
            .preview_session_linked_api_action(&session),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("gws_classify_api_error=preview action did not classify");
            std::process::exit(1);
        }
    };
    println!("gws_classified_api={}", gws_classified_api.log_line());
    let gws_classified_network = match plan.api_network_gws.classify.classify_action(
        &plan
            .api_network_gws
            .session_linkage
            .preview_session_linked_network_action(&session),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("gws_classify_network_error=preview action did not classify");
            std::process::exit(1);
        }
    };
    println!(
        "gws_classified_network={}",
        gws_classified_network.log_line()
    );
    println!("gws_evaluate={}", plan.api_network_gws.evaluate.summary());
    let gws_normalized_api = plan
        .api_network_gws
        .evaluate
        .normalize_classified_action(&gws_classified_api, &session);
    println!(
        "gws_normalized_api={}",
        serde_json::to_string(&gws_normalized_api)
            .expect("gws normalized api preview should serialize")
    );
    let provider_abstraction_policy_input = PolicyInput::from_event(&gws_normalized_api);
    println!(
        "provider_abstraction_policy_input={}",
        serde_json::to_string(&provider_abstraction_policy_input)
            .expect("provider abstraction policy input preview should serialize")
    );
    let provider_abstraction_metadata_entry = provider_abstraction_policy_input
        .provider_action
        .as_ref()
        .and_then(|provider_action| provider_metadata_catalog.find(&provider_action.id()))
        .expect("preview catalog should contain metadata for the preview provider action");
    println!(
        "provider_abstraction_metadata_entry={}",
        serde_json::to_string(provider_abstraction_metadata_entry)
            .expect("provider abstraction metadata entry should serialize")
    );
    let gws_normalized_network = plan
        .api_network_gws
        .evaluate
        .normalize_classified_action(&gws_classified_network, &session);
    println!(
        "gws_normalized_network={}",
        serde_json::to_string(&gws_normalized_network)
            .expect("gws normalized network preview should serialize")
    );
    let preview_gws_policy = |normalized: &agenta_core::EventEnvelope| {
        let input = PolicyInput::from_event(normalized);
        RegoPolicyEvaluator::gws_action_example()
            .evaluate(&input)
            .map(|decision| {
                let decision_applied = apply_decision_to_event(normalized, &decision);
                let approval_request = approval_request_from_decision(&decision_applied, &decision);
                (decision_applied, decision, approval_request)
            })
    };
    let (gws_decision_applied_api, gws_policy_decision_api, gws_approval_request_api) =
        match preview_gws_policy(&gws_normalized_api) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("gws_policy_api_error={error}");
                std::process::exit(1);
            }
        };
    let gws_enforcement_api = match plan.api_network_gws.approval.apply(
        &gws_decision_applied_api,
        &gws_policy_decision_api,
        gws_approval_request_api.as_ref(),
    ) {
        Ok(enforcement) => enforcement,
        Err(error) => {
            eprintln!("gws_enforcement_api_error={error}");
            std::process::exit(1);
        }
    };
    let gws_enforcement_projection_api = gws_enforcement_api.record_projection();
    let gws_enriched_api =
        apply_enforcement_to_event(&gws_decision_applied_api, &gws_enforcement_projection_api);
    let gws_approval_request_api = gws_approval_request_api.as_ref().map(|request| {
        apply_enforcement_to_approval_request(request, &gws_enforcement_projection_api)
    });
    println!(
        "gws_enriched_api={}",
        serde_json::to_string(&gws_enriched_api)
            .expect("gws enriched api preview should serialize")
    );
    println!(
        "gws_policy_decision_api={}",
        serde_json::to_string(&gws_policy_decision_api)
            .expect("gws api policy decision should serialize")
    );
    match &gws_approval_request_api {
        Some(approval_request) => println!(
            "gws_approval_request_api={}",
            serde_json::to_string(approval_request)
                .expect("gws api approval request should serialize")
        ),
        None => println!("gws_approval_request_api=null"),
    }
    println!(
        "gws_enforcement_api={}",
        serde_json::to_string(&gws_enforcement_api)
            .expect("gws api enforcement preview should serialize")
    );
    let gws_admin_classified = match plan.api_network_gws.classify.classify_action(
        &plan.api_network_gws.session_linkage.link_api_observation(
            &ApiRequestObservation::preview_admin_reports_activities_list(),
            &session,
        ),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("gws_classify_admin_error=preview admin action did not classify");
            std::process::exit(1);
        }
    };
    let gws_normalized_admin = plan
        .api_network_gws
        .evaluate
        .normalize_classified_action(&gws_admin_classified, &session);
    let (gws_enriched_admin, gws_policy_decision_admin, gws_approval_request_admin) =
        match preview_gws_policy(&gws_normalized_admin) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("gws_policy_admin_error={error}");
                std::process::exit(1);
            }
        };
    println!(
        "gws_normalized_admin={}",
        serde_json::to_string(&gws_normalized_admin)
            .expect("gws normalized admin preview should serialize")
    );
    println!(
        "gws_enriched_admin={}",
        serde_json::to_string(&gws_enriched_admin)
            .expect("gws enriched admin preview should serialize")
    );
    println!(
        "gws_policy_decision_admin={}",
        serde_json::to_string(&gws_policy_decision_admin)
            .expect("gws admin policy decision should serialize")
    );
    match &gws_approval_request_admin {
        Some(approval_request) => println!(
            "gws_approval_request_admin={}",
            serde_json::to_string(approval_request)
                .expect("gws admin approval request should serialize")
        ),
        None => println!("gws_approval_request_admin=null"),
    }
    let gws_deny_classified = match plan.api_network_gws.classify.classify_action(
        &plan.api_network_gws.session_linkage.link_api_observation(
            &ApiRequestObservation::preview_gmail_users_messages_send(),
            &session,
        ),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("gws_classify_deny_error=preview gmail deny action did not classify");
            std::process::exit(1);
        }
    };
    let gws_normalized_deny = plan
        .api_network_gws
        .evaluate
        .normalize_classified_action(&gws_deny_classified, &session);
    let gws_policy_decision_deny = PolicyDecision {
        decision: PolicyDecisionKind::Deny,
        rule_id: Some("gws.gmail.users_messages_send.denied".to_owned()),
        severity: Some(Severity::High),
        reason: Some("Outbound Gmail send is denied by preview policy".to_owned()),
        explanation: None,
        rationale: None,
        reviewer_hint: None,
        approval: None,
        tags: vec!["gws".to_owned(), "gmail".to_owned(), "deny".to_owned()],
    };
    let gws_decision_applied_deny =
        apply_decision_to_event(&gws_normalized_deny, &gws_policy_decision_deny);
    let gws_approval_request_deny =
        approval_request_from_decision(&gws_decision_applied_deny, &gws_policy_decision_deny);
    let gws_enforcement_deny = EnforcementOutcome::denied(
        EnforcementScope::Gws,
        &gws_decision_applied_deny,
        &gws_policy_decision_deny,
    );
    let gws_enriched_deny = apply_enforcement_to_event(
        &gws_decision_applied_deny,
        &gws_enforcement_deny.record_projection(),
    );
    println!(
        "gws_normalized_deny={}",
        serde_json::to_string(&gws_normalized_deny)
            .expect("gws normalized deny preview should serialize")
    );
    println!(
        "gws_enriched_deny={}",
        serde_json::to_string(&gws_enriched_deny)
            .expect("gws enriched deny preview should serialize")
    );
    println!(
        "gws_policy_decision_deny={}",
        serde_json::to_string(&gws_policy_decision_deny)
            .expect("gws deny policy decision should serialize")
    );
    match &gws_approval_request_deny {
        Some(approval_request) => println!(
            "gws_approval_request_deny={}",
            serde_json::to_string(approval_request)
                .expect("gws deny approval request should serialize")
        ),
        None => println!("gws_approval_request_deny=null"),
    }
    println!(
        "gws_enforcement_deny={}",
        serde_json::to_string(&gws_enforcement_deny)
            .expect("gws deny enforcement preview should serialize")
    );
    let gws_store = match GwsPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("gws_store_error={error}");
            std::process::exit(1);
        }
    };
    println!("gws_store_root={}", gws_store.paths().root.display());
    if let Err(error) = gws_store.append_audit_record(&gws_enriched_api) {
        eprintln!("persisted_gws_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match gws_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_gws_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_gws_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_gws_audit_record_require_approval_error=missing persisted gws audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_gws_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    if let Some(request) = &gws_approval_request_api
        && let Err(error) = gws_store.append_approval_request(request)
    {
        eprintln!("persisted_gws_approval_request_error={error}");
        std::process::exit(1);
    }
    match (
        &gws_approval_request_api,
        gws_store.latest_approval_request(),
    ) {
        (Some(_), Ok(Some(record))) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_gws_approval_request={json}"),
            Err(error) => {
                eprintln!("persisted_gws_approval_request_error={error}");
                std::process::exit(1);
            }
        },
        (Some(_), Ok(None)) => {
            eprintln!(
                "persisted_gws_approval_request_error=missing persisted gws approval request"
            );
            std::process::exit(1);
        }
        (Some(_), Err(error)) => {
            eprintln!("persisted_gws_approval_request_error={error}");
            std::process::exit(1);
        }
        (None, _) => {}
    }
    if let Err(error) = gws_store.append_audit_record(&gws_enriched_admin) {
        eprintln!("persisted_gws_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match gws_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_gws_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_gws_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!("persisted_gws_audit_record_allow_error=missing persisted gws audit record");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_gws_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = gws_store.append_audit_record(&gws_enriched_deny) {
        eprintln!("persisted_gws_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match gws_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_gws_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_gws_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!("persisted_gws_audit_record_deny_error=missing persisted gws audit record");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_gws_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }
    println!("gws_record={}", plan.api_network_gws.record.summary());
    println!("github_taxonomy={}", plan.github.taxonomy.summary());
    println!("github_metadata={}", plan.github.metadata.summary());
    println!("github_policy={}", plan.github.policy.summary());
    let github_require_approval_classified = match plan.github.taxonomy.classify_signal(
        &agent_auditor_hostd::poc::github::contract::GitHubGovernanceObservation::preview_api_repos_update_visibility(),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("github_classify_require_approval_error=preview GitHub action did not classify");
            std::process::exit(1);
        }
    };
    println!(
        "github_classified_require_approval={}",
        github_require_approval_classified.log_line()
    );
    let github_normalized_require_approval = plan
        .github
        .policy
        .normalize_classified_action(&github_require_approval_classified, &session);
    println!(
        "github_normalized_require_approval={}",
        serde_json::to_string(&github_normalized_require_approval)
            .expect("github normalized require approval preview should serialize")
    );
    let preview_github_policy = |normalized: &agenta_core::EventEnvelope| {
        let input = PolicyInput::from_event(normalized);
        RegoPolicyEvaluator::github_action_example()
            .evaluate(&input)
            .map(|decision| {
                let decision_applied = apply_decision_to_event(normalized, &decision);
                let approval_request = approval_request_from_decision(&decision_applied, &decision);
                (decision_applied, decision, approval_request)
            })
    };
    let (
        _github_decision_applied_require_approval,
        github_policy_decision_require_approval,
        github_approval_request_require_approval,
    ) = match preview_github_policy(&github_normalized_require_approval) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("github_policy_require_approval_error={error}");
            std::process::exit(1);
        }
    };
    let github_approval_request_require_approval = match &github_approval_request_require_approval {
        Some(approval_request) => approval_request,
        None => {
            eprintln!("github_approval_request_require_approval_error=missing approval request");
            std::process::exit(1);
        }
    };
    let (github_enriched_require_approval, github_approval_request_require_approval) =
        match plan.github.record.reflect_hold(
            &github_normalized_require_approval,
            &github_policy_decision_require_approval,
            github_approval_request_require_approval,
        ) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("github_record_require_approval_error={error}");
                std::process::exit(1);
            }
        };
    println!(
        "github_policy_decision_require_approval={}",
        serde_json::to_string(&github_policy_decision_require_approval)
            .expect("github require approval policy decision should serialize")
    );
    println!(
        "github_enriched_require_approval={}",
        serde_json::to_string(&github_enriched_require_approval)
            .expect("github enriched require approval preview should serialize")
    );
    println!(
        "github_approval_request_require_approval={}",
        serde_json::to_string(&github_approval_request_require_approval)
            .expect("github require approval request should serialize")
    );

    let github_allow_classified = match plan.github.taxonomy.classify_signal(
        &agent_auditor_hostd::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_runs_rerun(),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("github_classify_allow_error=preview GitHub action did not classify");
            std::process::exit(1);
        }
    };
    let github_normalized_allow = plan
        .github
        .policy
        .normalize_classified_action(&github_allow_classified, &session);
    let (_, github_policy_decision_allow, _) = match preview_github_policy(&github_normalized_allow)
    {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("github_policy_allow_error={error}");
            std::process::exit(1);
        }
    };
    let github_enriched_allow = match plan
        .github
        .record
        .reflect_allow(&github_normalized_allow, &github_policy_decision_allow)
    {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("github_record_allow_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "github_normalized_allow={}",
        serde_json::to_string(&github_normalized_allow)
            .expect("github normalized allow preview should serialize")
    );
    println!(
        "github_policy_decision_allow={}",
        serde_json::to_string(&github_policy_decision_allow)
            .expect("github allow policy decision should serialize")
    );
    println!(
        "github_enriched_allow={}",
        serde_json::to_string(&github_enriched_allow)
            .expect("github enriched allow preview should serialize")
    );

    let github_deny_classified = match plan.github.taxonomy.classify_signal(
        &agent_auditor_hostd::poc::github::contract::GitHubGovernanceObservation::preview_api_actions_secrets_create_or_update(),
    ) {
        Some(classified) => classified,
        None => {
            eprintln!("github_classify_deny_error=preview GitHub action did not classify");
            std::process::exit(1);
        }
    };
    let github_normalized_deny = plan
        .github
        .policy
        .normalize_classified_action(&github_deny_classified, &session);
    let (_, github_policy_decision_deny, _) = match preview_github_policy(&github_normalized_deny) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("github_policy_deny_error={error}");
            std::process::exit(1);
        }
    };
    let github_enriched_deny = match plan
        .github
        .record
        .reflect_deny(&github_normalized_deny, &github_policy_decision_deny)
    {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("github_record_deny_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "github_normalized_deny={}",
        serde_json::to_string(&github_normalized_deny)
            .expect("github normalized deny preview should serialize")
    );
    println!(
        "github_policy_decision_deny={}",
        serde_json::to_string(&github_policy_decision_deny)
            .expect("github deny policy decision should serialize")
    );
    println!(
        "github_enriched_deny={}",
        serde_json::to_string(&github_enriched_deny)
            .expect("github enriched deny preview should serialize")
    );

    let github_store = match GitHubPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("github_store_error={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = github_store.append_audit_record(&github_enriched_require_approval) {
        eprintln!("persisted_github_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match github_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_github_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_github_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_github_audit_record_require_approval_error=missing persisted github audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_github_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) =
        github_store.append_approval_request(&github_approval_request_require_approval)
    {
        eprintln!("persisted_github_approval_request_error={error}");
        std::process::exit(1);
    }
    match github_store.latest_approval_request() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_github_approval_request={json}"),
            Err(error) => {
                eprintln!("persisted_github_approval_request_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_github_approval_request_error=missing persisted github approval request"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_github_approval_request_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = github_store.append_audit_record(&github_enriched_allow) {
        eprintln!("persisted_github_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match github_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_github_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_github_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_github_audit_record_allow_error=missing persisted github audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_github_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = github_store.append_audit_record(&github_enriched_deny) {
        eprintln!("persisted_github_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match github_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_github_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_github_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_github_audit_record_deny_error=missing persisted github audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_github_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }
    println!("github_record={}", plan.github.record.summary());

    let preview_generic_rest_policy = |normalized: &EventEnvelope| {
        let input = PolicyInput::from_event(normalized);
        RegoPolicyEvaluator::generic_rest_action_example()
            .evaluate(&input)
            .map(|decision| {
                let decision_applied = apply_decision_to_event(normalized, &decision);
                let approval_request = approval_request_from_decision(&decision_applied, &decision);
                (decision_applied, decision, approval_request)
            })
    };

    let generic_rest_normalized_require_approval = generic_rest_preview_event(
        "evt_rest_gmail_send_require_approval",
        "gws",
        "gmail.users.messages.send",
        "gmail.users/me",
        EventType::GwsAction,
        ActionClass::Gws,
        "gws.gmail",
        "POST",
        "gmail.googleapis.com",
        "/gmail/v1/users/{userId}/messages/send",
        "action_arguments",
        "https://www.googleapis.com/auth/gmail.send",
        &["https://www.googleapis.com/auth/gmail.send"],
        "sends a Gmail message to one or more recipients",
        "outbound_send",
    );
    println!(
        "generic_rest_normalized_require_approval={}",
        serde_json::to_string(&generic_rest_normalized_require_approval)
            .expect("generic REST require approval preview should serialize")
    );
    let (
        _generic_rest_decision_applied_require_approval,
        generic_rest_policy_decision_require_approval,
        generic_rest_approval_request_require_approval,
    ) = match preview_generic_rest_policy(&generic_rest_normalized_require_approval) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("generic_rest_policy_require_approval_error={error}");
            std::process::exit(1);
        }
    };
    let generic_rest_approval_request_require_approval =
        match &generic_rest_approval_request_require_approval {
            Some(approval_request) => approval_request,
            None => {
                eprintln!(
                    "generic_rest_approval_request_require_approval_error=missing approval request"
                );
                std::process::exit(1);
            }
        };
    let (generic_rest_enriched_require_approval, generic_rest_approval_request_require_approval) =
        match plan.generic_rest.record.reflect_hold(
            &generic_rest_normalized_require_approval,
            &generic_rest_policy_decision_require_approval,
            generic_rest_approval_request_require_approval,
        ) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("generic_rest_record_require_approval_error={error}");
                std::process::exit(1);
            }
        };
    println!(
        "generic_rest_policy_decision_require_approval={}",
        serde_json::to_string(&generic_rest_policy_decision_require_approval)
            .expect("generic REST require approval policy decision should serialize")
    );
    println!(
        "generic_rest_enriched_require_approval={}",
        serde_json::to_string(&generic_rest_enriched_require_approval)
            .expect("generic REST require approval enriched event should serialize")
    );
    println!(
        "generic_rest_approval_request_require_approval={}",
        serde_json::to_string(&generic_rest_approval_request_require_approval)
            .expect("generic REST require approval request should serialize")
    );

    let generic_rest_normalized_allow = generic_rest_preview_event(
        "evt_rest_admin_reports_allow",
        "gws",
        "admin.reports.activities.list",
        "admin.reports/users/all/applications/drive",
        EventType::GwsAction,
        ActionClass::Gws,
        "gws.admin",
        "GET",
        "admin.googleapis.com",
        "/admin/reports/v1/activity/users/all/applications/{applicationName}",
        "filter",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        &["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
        "lists admin activity reports without mutating tenant state",
        "admin_read",
    );
    println!(
        "generic_rest_normalized_allow={}",
        serde_json::to_string(&generic_rest_normalized_allow)
            .expect("generic REST allow preview should serialize")
    );
    let (_, generic_rest_policy_decision_allow, _) =
        match preview_generic_rest_policy(&generic_rest_normalized_allow) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("generic_rest_policy_allow_error={error}");
                std::process::exit(1);
            }
        };
    let generic_rest_enriched_allow = match plan.generic_rest.record.reflect_allow(
        &generic_rest_normalized_allow,
        &generic_rest_policy_decision_allow,
    ) {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("generic_rest_record_allow_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "generic_rest_policy_decision_allow={}",
        serde_json::to_string(&generic_rest_policy_decision_allow)
            .expect("generic REST allow policy decision should serialize")
    );
    println!(
        "generic_rest_enriched_allow={}",
        serde_json::to_string(&generic_rest_enriched_allow)
            .expect("generic REST allow enriched event should serialize")
    );

    let generic_rest_normalized_deny = generic_rest_preview_event(
        "evt_rest_github_secret_deny",
        "github",
        "actions.secrets.create_or_update",
        "repos/n01e0/agent-auditor/actions/secrets/DEPLOY_TOKEN",
        EventType::GithubAction,
        ActionClass::Github,
        "github.actions",
        "PUT",
        "api.github.com",
        "/repos/{owner}/{repo}/actions/secrets/{secret_name}",
        "none",
        "github.permission:secrets:write",
        &["github.permission:secrets:write", "github.oauth:repo"],
        "creates or updates an encrypted repository Actions secret",
        "admin_write",
    );
    println!(
        "generic_rest_normalized_deny={}",
        serde_json::to_string(&generic_rest_normalized_deny)
            .expect("generic REST deny preview should serialize")
    );
    let (_, generic_rest_policy_decision_deny, _) =
        match preview_generic_rest_policy(&generic_rest_normalized_deny) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("generic_rest_policy_deny_error={error}");
                std::process::exit(1);
            }
        };
    let generic_rest_enriched_deny = match plan.generic_rest.record.reflect_deny(
        &generic_rest_normalized_deny,
        &generic_rest_policy_decision_deny,
    ) {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("generic_rest_record_deny_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "generic_rest_policy_decision_deny={}",
        serde_json::to_string(&generic_rest_policy_decision_deny)
            .expect("generic REST deny policy decision should serialize")
    );
    println!(
        "generic_rest_enriched_deny={}",
        serde_json::to_string(&generic_rest_enriched_deny)
            .expect("generic REST deny enriched event should serialize")
    );

    let generic_rest_store = match GenericRestPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("generic_rest_store_error={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) =
        generic_rest_store.append_audit_record(&generic_rest_enriched_require_approval)
    {
        eprintln!("persisted_generic_rest_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match generic_rest_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_generic_rest_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_generic_rest_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_generic_rest_audit_record_require_approval_error=missing persisted generic REST audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_generic_rest_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) =
        generic_rest_store.append_approval_request(&generic_rest_approval_request_require_approval)
    {
        eprintln!("persisted_generic_rest_approval_request_error={error}");
        std::process::exit(1);
    }
    match generic_rest_store.latest_approval_request() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_generic_rest_approval_request={json}"),
            Err(error) => {
                eprintln!("persisted_generic_rest_approval_request_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_generic_rest_approval_request_error=missing persisted generic REST approval request"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_generic_rest_approval_request_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = generic_rest_store.append_audit_record(&generic_rest_enriched_allow) {
        eprintln!("persisted_generic_rest_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match generic_rest_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_generic_rest_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_generic_rest_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_generic_rest_audit_record_allow_error=missing persisted generic REST audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_generic_rest_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = generic_rest_store.append_audit_record(&generic_rest_enriched_deny) {
        eprintln!("persisted_generic_rest_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match generic_rest_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_generic_rest_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_generic_rest_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_generic_rest_audit_record_deny_error=missing persisted generic REST audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_generic_rest_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }

    run_forward_proxy_ingress_preview_or_exit();

    let preview_messaging_policy = |normalized: &EventEnvelope| {
        let input = PolicyInput::from_event(normalized);
        RegoPolicyEvaluator::messaging_action_example()
            .evaluate(&input)
            .map(|decision| {
                let decision_applied = apply_decision_to_event(normalized, &decision);
                let approval_request = approval_request_from_decision(&decision_applied, &decision);
                (decision_applied, decision, approval_request)
            })
    };

    let messaging_normalized_allow = messaging_preview_event(
        "evt_msg_slack_send_allow",
        "slack",
        "chat.post_message",
        "slack.channels/C12345678",
        "slack.chat",
        "POST",
        "slack.com",
        "/api/chat.postMessage",
        "action_arguments",
        "slack.scope:chat:write",
        &["slack.scope:chat:write"],
        "sends a message into a Slack conversation",
        "outbound_send",
        "message.send",
        Some("slack.channels/C12345678"),
        None,
        Some("public_channel"),
        None,
        None,
        None,
        None,
    );
    println!(
        "messaging_normalized_allow={}",
        serde_json::to_string(&messaging_normalized_allow)
            .expect("messaging allow preview should serialize")
    );
    let (_, messaging_policy_decision_allow, _) =
        match preview_messaging_policy(&messaging_normalized_allow) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("messaging_policy_allow_error={error}");
                std::process::exit(1);
            }
        };
    let messaging_enriched_allow = match plan.messaging.record.reflect_allow(
        &messaging_normalized_allow,
        &messaging_policy_decision_allow,
    ) {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("messaging_record_allow_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "messaging_policy_decision_allow={}",
        serde_json::to_string(&messaging_policy_decision_allow)
            .expect("messaging allow policy decision should serialize")
    );
    println!(
        "messaging_enriched_allow={}",
        serde_json::to_string(&messaging_enriched_allow)
            .expect("messaging allow enriched event should serialize")
    );

    let messaging_normalized_require_approval = messaging_preview_event(
        "evt_msg_discord_invite_require_approval",
        "discord",
        "channels.thread_members.put",
        "discord.threads/123456789012345678/members/234567890123456789",
        "discord.threads",
        "PUT",
        "discord.com",
        "/api/v10/channels/{thread_id}/thread-members/{user_id}",
        "none",
        "discord.permission:create_public_threads",
        &[
            "discord.permission:create_public_threads",
            "discord.permission:send_messages_in_threads",
        ],
        "adds a member into a Discord thread",
        "sharing_write",
        "channel.invite",
        None,
        Some("discord.threads/123456789012345678"),
        Some("thread"),
        Some("thread_member"),
        None,
        None,
        None,
    );
    println!(
        "messaging_normalized_require_approval={}",
        serde_json::to_string(&messaging_normalized_require_approval)
            .expect("messaging require approval preview should serialize")
    );
    let (
        _messaging_decision_applied_require_approval,
        messaging_policy_decision_require_approval,
        messaging_approval_request_require_approval,
    ) = match preview_messaging_policy(&messaging_normalized_require_approval) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("messaging_policy_require_approval_error={error}");
            std::process::exit(1);
        }
    };
    let messaging_approval_request_require_approval =
        match &messaging_approval_request_require_approval {
            Some(approval_request) => approval_request,
            None => {
                eprintln!(
                    "messaging_approval_request_require_approval_error=missing approval request"
                );
                std::process::exit(1);
            }
        };
    let (messaging_enriched_require_approval, messaging_approval_request_require_approval) =
        match plan.messaging.record.reflect_hold(
            &messaging_normalized_require_approval,
            &messaging_policy_decision_require_approval,
            messaging_approval_request_require_approval,
        ) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("messaging_record_require_approval_error={error}");
                std::process::exit(1);
            }
        };
    println!(
        "messaging_policy_decision_require_approval={}",
        serde_json::to_string(&messaging_policy_decision_require_approval)
            .expect("messaging require approval policy decision should serialize")
    );
    println!(
        "messaging_enriched_require_approval={}",
        serde_json::to_string(&messaging_enriched_require_approval)
            .expect("messaging require approval enriched event should serialize")
    );
    println!(
        "messaging_approval_request_require_approval={}",
        serde_json::to_string(&messaging_approval_request_require_approval)
            .expect("messaging require approval request should serialize")
    );

    let messaging_normalized_deny = messaging_preview_event(
        "evt_msg_discord_permission_deny",
        "discord",
        "channels.permissions.put",
        "discord.channels/123456789012345678/permissions/role:345678901234567890",
        "discord.permissions",
        "PUT",
        "discord.com",
        "/api/v10/channels/{channel_id}/permissions/{overwrite_id}",
        "none",
        "discord.permission:manage_roles",
        &["discord.permission:manage_channels"],
        "updates a Discord channel permission overwrite",
        "sharing_write",
        "permission.update",
        Some("discord.channels/123456789012345678"),
        None,
        None,
        None,
        Some("channel_permission_overwrite"),
        None,
        None,
    );
    println!(
        "messaging_normalized_deny={}",
        serde_json::to_string(&messaging_normalized_deny)
            .expect("messaging deny preview should serialize")
    );
    let (_, messaging_policy_decision_deny, _) =
        match preview_messaging_policy(&messaging_normalized_deny) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("messaging_policy_deny_error={error}");
                std::process::exit(1);
            }
        };
    let messaging_enriched_deny = match plan
        .messaging
        .record
        .reflect_deny(&messaging_normalized_deny, &messaging_policy_decision_deny)
    {
        Ok(enriched) => enriched,
        Err(error) => {
            eprintln!("messaging_record_deny_error={error}");
            std::process::exit(1);
        }
    };
    println!(
        "messaging_policy_decision_deny={}",
        serde_json::to_string(&messaging_policy_decision_deny)
            .expect("messaging deny policy decision should serialize")
    );
    println!(
        "messaging_enriched_deny={}",
        serde_json::to_string(&messaging_enriched_deny)
            .expect("messaging deny enriched event should serialize")
    );

    let messaging_normalized_file_upload = messaging_preview_event(
        "evt_msg_slack_file_upload_require_approval",
        "slack",
        "files.upload_v2",
        "slack.channels/C12345678/files/F12345678",
        "slack.files",
        "POST",
        "slack.com",
        "/api/files.uploadV2",
        "action_arguments",
        "slack.scope:files:write",
        &["slack.scope:files:write"],
        "uploads a file into a Slack conversation",
        "content_write",
        "file.upload",
        Some("slack.channels/C12345678"),
        None,
        Some("public_channel"),
        None,
        None,
        Some("channel_attachment"),
        Some(1),
    );
    println!(
        "messaging_normalized_file_upload={}",
        serde_json::to_string(&messaging_normalized_file_upload)
            .expect("messaging file upload preview should serialize")
    );
    let (
        _messaging_decision_applied_file_upload,
        messaging_policy_decision_file_upload,
        messaging_approval_request_file_upload,
    ) = match preview_messaging_policy(&messaging_normalized_file_upload) {
        Ok(parts) => parts,
        Err(error) => {
            eprintln!("messaging_policy_file_upload_error={error}");
            std::process::exit(1);
        }
    };
    let messaging_approval_request_file_upload = match &messaging_approval_request_file_upload {
        Some(approval_request) => approval_request,
        None => {
            eprintln!("messaging_approval_request_file_upload_error=missing approval request");
            std::process::exit(1);
        }
    };
    let (messaging_enriched_file_upload, messaging_approval_request_file_upload) =
        match plan.messaging.record.reflect_hold(
            &messaging_normalized_file_upload,
            &messaging_policy_decision_file_upload,
            messaging_approval_request_file_upload,
        ) {
            Ok(parts) => parts,
            Err(error) => {
                eprintln!("messaging_record_file_upload_error={error}");
                std::process::exit(1);
            }
        };
    println!(
        "messaging_policy_decision_file_upload={}",
        serde_json::to_string(&messaging_policy_decision_file_upload)
            .expect("messaging file upload policy decision should serialize")
    );
    println!(
        "messaging_enriched_file_upload={}",
        serde_json::to_string(&messaging_enriched_file_upload)
            .expect("messaging file upload enriched event should serialize")
    );
    println!(
        "messaging_approval_request_file_upload={}",
        serde_json::to_string(&messaging_approval_request_file_upload)
            .expect("messaging file upload approval request should serialize")
    );

    let messaging_store = match MessagingPocStore::bootstrap() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("messaging_store_error={error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = messaging_store.append_audit_record(&messaging_enriched_allow) {
        eprintln!("persisted_messaging_audit_record_allow_error={error}");
        std::process::exit(1);
    }
    match messaging_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_audit_record_allow={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_audit_record_allow_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_audit_record_allow_error=missing persisted messaging audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_audit_record_allow_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = messaging_store.append_audit_record(&messaging_enriched_require_approval) {
        eprintln!("persisted_messaging_audit_record_require_approval_error={error}");
        std::process::exit(1);
    }
    match messaging_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_audit_record_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_audit_record_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_audit_record_require_approval_error=missing persisted messaging audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_audit_record_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) =
        messaging_store.append_approval_request(&messaging_approval_request_require_approval)
    {
        eprintln!("persisted_messaging_approval_request_require_approval_error={error}");
        std::process::exit(1);
    }
    println!(
        "approval_local_jsonl_inspection_model=components=approval_local_jsonl_inspection_record linkage=approval_id,event_id,rule_id consistency=reviewer_summary,persisted_rationale,agent_reason,human_request,reviewer_hint explanation=redaction_safe_summary"
    );
    match messaging_store.latest_approval_request() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_approval_request_require_approval={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_approval_request_require_approval_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_approval_request_require_approval_error=missing persisted messaging approval request"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_approval_request_require_approval_error={error}");
            std::process::exit(1);
        }
    }
    print_local_jsonl_inspection_line(
        "persisted_messaging_local_jsonl_inspection_require_approval",
        &messaging_approval_request_require_approval,
    );
    if let Err(error) = messaging_store.append_audit_record(&messaging_enriched_deny) {
        eprintln!("persisted_messaging_audit_record_deny_error={error}");
        std::process::exit(1);
    }
    match messaging_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_audit_record_deny={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_audit_record_deny_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_audit_record_deny_error=missing persisted messaging audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_audit_record_deny_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) = messaging_store.append_audit_record(&messaging_enriched_file_upload) {
        eprintln!("persisted_messaging_audit_record_file_upload_error={error}");
        std::process::exit(1);
    }
    match messaging_store.latest_audit_record() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_audit_record_file_upload={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_audit_record_file_upload_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_audit_record_file_upload_error=missing persisted messaging audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_audit_record_file_upload_error={error}");
            std::process::exit(1);
        }
    }
    if let Err(error) =
        messaging_store.append_approval_request(&messaging_approval_request_file_upload)
    {
        eprintln!("persisted_messaging_approval_request_file_upload_error={error}");
        std::process::exit(1);
    }
    match messaging_store.latest_approval_request() {
        Ok(Some(record)) => match serde_json::to_string(&record) {
            Ok(json) => println!("persisted_messaging_approval_request_file_upload={json}"),
            Err(error) => {
                eprintln!("persisted_messaging_approval_request_file_upload_error={error}");
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "persisted_messaging_approval_request_file_upload_error=missing persisted messaging approval request"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_messaging_approval_request_file_upload_error={error}");
            std::process::exit(1);
        }
    }

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

    let process_preview = match preview_fixture_process_slice(&session) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("synthetic_process_preview_error={error}");
            std::process::exit(1);
        }
    };
    println!("event_log_exec={}", process_preview.exec_log_line);
    println!("event_log_exit={}", process_preview.exit_log_line);
    println!(
        "lifecycle_log={}",
        process_preview
            .lifecycle_record
            .summary_line(plan.event_path.transport)
    );

    match serde_json::to_string(&process_preview.normalized_exec) {
        Ok(json) => println!("normalized_exec={json}"),
        Err(error) => {
            eprintln!("normalized_exec_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_preview.normalized_exit) {
        Ok(json) => println!("normalized_exit={json}"),
        Err(error) => {
            eprintln!("normalized_exit_error={error}");
            std::process::exit(1);
        }
    }

    let preview_process_policy = |event: &ExecEvent| {
        let observed = plan.event_path.normalize_exec_event(event, &session);
        let input = PolicyInput::from_event(&observed);
        RegoPolicyEvaluator::process_exec_example()
            .evaluate(&input)
            .and_then(|decision| {
                let normalized = apply_decision_to_event(&observed, &decision);
                let approval_request = approval_request_from_decision(&normalized, &decision);
                plan.enforcement
                    .preview_process_outcome(&normalized, &decision, approval_request.as_ref())
                    .map(|enforcement| {
                        let record_enforcement = enforcement.record_projection();
                        let normalized =
                            apply_enforcement_to_event(&normalized, &record_enforcement);
                        let approval_request = approval_request.as_ref().map(|request| {
                            apply_enforcement_to_approval_request(request, &record_enforcement)
                        });
                        (normalized, decision, approval_request, enforcement)
                    })
                    .map_err(|error| {
                        agenta_policy::PolicyError::Evaluate(format!(
                            "process enforcement preview failed: {error}"
                        ))
                    })
            })
    };

    let (
        normalized_process_allow,
        process_policy_decision_allow,
        process_approval_request_allow,
        process_enforcement_allow,
    ) = match preview_process_policy(&process_preview.exec_event) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("process_policy_allow_error={error}");
            std::process::exit(1);
        }
    };

    match serde_json::to_string(&normalized_process_allow) {
        Ok(json) => println!("normalized_process_allow={json}"),
        Err(error) => {
            eprintln!("normalized_process_allow_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_policy_decision_allow) {
        Ok(json) => println!("process_policy_decision_allow={json}"),
        Err(error) => {
            eprintln!("process_policy_decision_allow_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_enforcement_allow) {
        Ok(json) => println!("process_enforcement_allow={json}"),
        Err(error) => {
            eprintln!("process_enforcement_allow_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_approval_request_allow) {
        Ok(json) => println!("process_approval_request_allow={json}"),
        Err(error) => {
            eprintln!("process_approval_request_allow_error={error}");
            std::process::exit(1);
        }
    }

    let process_exec_hold = ExecEvent {
        pid: 4545,
        ppid: process_preview.exec_event.ppid,
        uid: process_preview.exec_event.uid,
        gid: process_preview.exec_event.gid,
        command: "ssh".to_owned(),
        filename: "/usr/bin/ssh".to_owned(),
        exe: "/usr/bin/ssh".to_owned(),
        argv: vec!["/usr/bin/ssh".to_owned(), "user@example.com".to_owned()],
        cwd: "/workspace/fixture".to_owned(),
        container_id: "unknown".to_owned(),
        openclaw_lineage: None,
    };
    let (
        normalized_process_hold,
        process_policy_decision_hold,
        process_approval_request_hold,
        process_enforcement_hold,
    ) = match preview_process_policy(&process_exec_hold) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("process_policy_hold_error={error}");
            std::process::exit(1);
        }
    };

    match serde_json::to_string(&normalized_process_hold) {
        Ok(json) => println!("normalized_process_hold={json}"),
        Err(error) => {
            eprintln!("normalized_process_hold_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_policy_decision_hold) {
        Ok(json) => println!("process_policy_decision_hold={json}"),
        Err(error) => {
            eprintln!("process_policy_decision_hold_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_enforcement_hold) {
        Ok(json) => println!("process_enforcement_hold={json}"),
        Err(error) => {
            eprintln!("process_enforcement_hold_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_approval_request_hold) {
        Ok(json) => println!("process_approval_request_hold={json}"),
        Err(error) => {
            eprintln!("process_approval_request_hold_error={error}");
            std::process::exit(1);
        }
    }

    let process_exec_deny = ExecEvent {
        pid: 4646,
        ppid: process_preview.exec_event.ppid,
        uid: process_preview.exec_event.uid,
        gid: process_preview.exec_event.gid,
        command: "rm".to_owned(),
        filename: "/usr/bin/rm".to_owned(),
        exe: "/usr/bin/rm".to_owned(),
        argv: vec![
            "/usr/bin/rm".to_owned(),
            "-rf".to_owned(),
            "/tmp/demo".to_owned(),
        ],
        cwd: "/workspace/fixture".to_owned(),
        container_id: "unknown".to_owned(),
        openclaw_lineage: None,
    };
    let (
        normalized_process_deny,
        process_policy_decision_deny,
        process_approval_request_deny,
        process_enforcement_deny,
    ) = match preview_process_policy(&process_exec_deny) {
        Ok(preview) => preview,
        Err(error) => {
            eprintln!("process_policy_deny_error={error}");
            std::process::exit(1);
        }
    };

    match serde_json::to_string(&normalized_process_deny) {
        Ok(json) => println!("normalized_process_deny={json}"),
        Err(error) => {
            eprintln!("normalized_process_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_policy_decision_deny) {
        Ok(json) => println!("process_policy_decision_deny={json}"),
        Err(error) => {
            eprintln!("process_policy_decision_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_enforcement_deny) {
        Ok(json) => println!("process_enforcement_deny={json}"),
        Err(error) => {
            eprintln!("process_enforcement_deny_error={error}");
            std::process::exit(1);
        }
    }

    match serde_json::to_string(&process_approval_request_deny) {
        Ok(json) => println!("process_approval_request_deny={json}"),
        Err(error) => {
            eprintln!("process_approval_request_deny_error={error}");
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
                    .map(|enforcement| {
                        let record_enforcement = enforcement.record_projection();
                        let normalized =
                            apply_enforcement_to_event(&normalized, &record_enforcement);
                        let approval_request = approval_request.as_ref().map(|request| {
                            apply_enforcement_to_approval_request(request, &record_enforcement)
                        });
                        (normalized, decision, approval_request, enforcement)
                    })
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
    println!("filesystem_store_root={}", store.paths().root.display());
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

#[allow(clippy::too_many_arguments)]
fn generic_rest_preview_event(
    event_id: &str,
    provider_id: &str,
    action_key: &str,
    target: &str,
    event_type: EventType,
    action_class: ActionClass,
    semantic_surface: &str,
    method: &str,
    host: &str,
    path_template: &str,
    query_class: &str,
    primary_scope: &str,
    documented_scopes: &[&str],
    side_effect: &str,
    privilege_class: &str,
) -> EventEnvelope {
    let mut attributes = JsonMap::new();
    attributes.insert(
        "source_kind".to_owned(),
        serde_json::json!("api_observation"),
    );
    attributes.insert(
        "request_id".to_owned(),
        serde_json::json!(format!("req_{event_id}")),
    );
    attributes.insert("transport".to_owned(), serde_json::json!("https"));
    attributes.insert(
        "semantic_surface".to_owned(),
        serde_json::json!(semantic_surface),
    );
    attributes.insert("provider_id".to_owned(), serde_json::json!(provider_id));
    attributes.insert("action_key".to_owned(), serde_json::json!(action_key));
    attributes.insert(
        "provider_action_id".to_owned(),
        serde_json::json!(format!("{provider_id}:{action_key}")),
    );
    attributes.insert("target_hint".to_owned(), serde_json::json!(target));
    attributes.insert("method".to_owned(), serde_json::json!(method));
    attributes.insert("host".to_owned(), serde_json::json!(host));
    attributes.insert("path_template".to_owned(), serde_json::json!(path_template));
    attributes.insert("query_class".to_owned(), serde_json::json!(query_class));
    attributes.insert(
        "oauth_scope_labels".to_owned(),
        serde_json::json!({
            "primary": primary_scope,
            "documented": documented_scopes,
        }),
    );
    attributes.insert("side_effect".to_owned(), serde_json::json!(side_effect));
    attributes.insert(
        "privilege_class".to_owned(),
        serde_json::json!(privilege_class),
    );
    attributes.insert("content_retained".to_owned(), serde_json::json!(false));

    EventEnvelope::new(
        event_id,
        event_type,
        SessionRef {
            session_id: "sess_bootstrap_hostd".to_owned(),
            agent_id: Some("openclaw-main".to_owned()),
            initiator_id: None,
            workspace_id: None,
            policy_bundle_version: Some("bundle-bootstrap".to_owned()),
            environment: Some("dev".to_owned()),
        },
        Actor {
            kind: ActorKind::System,
            id: Some("agent-auditor-hostd".to_owned()),
            display_name: Some("agent-auditor-hostd PoC".to_owned()),
        },
        Action {
            class: action_class,
            verb: Some(action_key.to_owned()),
            target: Some(target.to_owned()),
            attributes,
        },
        ResultInfo {
            status: ResultStatus::Observed,
            reason: Some("observed by hostd generic REST smoke preview".to_owned()),
            exit_code: None,
            error: None,
        },
        SourceInfo {
            collector: CollectorKind::RuntimeHint,
            host_id: Some("hostd-poc".to_owned()),
            container_id: None,
            pod_uid: None,
            pid: None,
            ppid: None,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn messaging_preview_event(
    event_id: &str,
    provider_id: &str,
    action_key: &str,
    target: &str,
    semantic_surface: &str,
    method: &str,
    host: &str,
    path_template: &str,
    query_class: &str,
    primary_scope: &str,
    documented_scopes: &[&str],
    side_effect: &str,
    privilege_class: &str,
    action_family: &str,
    channel_hint: Option<&str>,
    conversation_hint: Option<&str>,
    delivery_scope: Option<&str>,
    membership_target_kind: Option<&str>,
    permission_target_kind: Option<&str>,
    file_target_kind: Option<&str>,
    attachment_count_hint: Option<u16>,
) -> EventEnvelope {
    let mut event = generic_rest_preview_event(
        event_id,
        provider_id,
        action_key,
        target,
        EventType::NetworkConnect,
        ActionClass::Browser,
        semantic_surface,
        method,
        host,
        path_template,
        query_class,
        primary_scope,
        documented_scopes,
        side_effect,
        privilege_class,
    );
    event
        .action
        .attributes
        .insert("action_family".to_owned(), serde_json::json!(action_family));
    if let Some(channel_hint) = channel_hint {
        event
            .action
            .attributes
            .insert("channel_hint".to_owned(), serde_json::json!(channel_hint));
    }
    if let Some(conversation_hint) = conversation_hint {
        event.action.attributes.insert(
            "conversation_hint".to_owned(),
            serde_json::json!(conversation_hint),
        );
    }
    if let Some(delivery_scope) = delivery_scope {
        event.action.attributes.insert(
            "delivery_scope".to_owned(),
            serde_json::json!(delivery_scope),
        );
    }
    if let Some(membership_target_kind) = membership_target_kind {
        event.action.attributes.insert(
            "membership_target_kind".to_owned(),
            serde_json::json!(membership_target_kind),
        );
    }
    if let Some(permission_target_kind) = permission_target_kind {
        event.action.attributes.insert(
            "permission_target_kind".to_owned(),
            serde_json::json!(permission_target_kind),
        );
    }
    if let Some(file_target_kind) = file_target_kind {
        event.action.attributes.insert(
            "file_target_kind".to_owned(),
            serde_json::json!(file_target_kind),
        );
    }
    if let Some(attachment_count_hint) = attachment_count_hint {
        event.action.attributes.insert(
            "attachment_count_hint".to_owned(),
            serde_json::json!(attachment_count_hint),
        );
    }
    event
}

fn run_forward_proxy_ingress_preview_or_exit() {
    let runtime = match ForwardProxyIngressRuntime::bootstrap() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("forward_proxy_ingress_bootstrap_error={error}");
            std::process::exit(1);
        }
    };
    let envelope =
        ForwardProxyIngressRuntime::preview_fixture("sess_live_proxy_forward_proxy_ingress");

    println!(
        "forward_proxy_ingress_source={}",
        ForwardProxyIngressInbox::SOURCE_LABEL
    );
    println!(
        "forward_proxy_ingress_root={}",
        runtime.inbox().paths().root.display()
    );
    println!(
        "forward_proxy_ingress_inbox={}",
        runtime.inbox().paths().inbox.display()
    );
    println!(
        "forward_proxy_ingress_cursor={}",
        runtime.inbox().paths().cursor.display()
    );
    println!(
        "forward_proxy_envelope={}",
        serde_json::to_string(&envelope).expect("forward proxy preview envelope should serialize")
    );

    if let Err(error) = runtime.inbox().append(&envelope) {
        eprintln!("forward_proxy_ingress_append_error={error}");
        std::process::exit(1);
    }

    let mut records = match runtime.drain_available() {
        Ok(records) => records,
        Err(error) => {
            eprintln!("forward_proxy_ingress_drain_error={error}");
            std::process::exit(1);
        }
    };
    let record = match records.pop() {
        Some(record) => record,
        None => {
            eprintln!("forward_proxy_ingress_drain_error=missing processed forward proxy record");
            std::process::exit(1);
        }
    };

    println!(
        "forward_proxy_request_summary={}",
        record.request.summary_line()
    );
    println!(
        "forward_proxy_normalized_event={}",
        serde_json::to_string(&record.normalized_event)
            .expect("forward proxy normalized event should serialize")
    );
    println!(
        "forward_proxy_policy_decision={}",
        serde_json::to_string(&record.policy_decision)
            .expect("forward proxy policy decision should serialize")
    );
    println!(
        "forward_proxy_approval_summary={}",
        record.approval.summary()
    );
    println!(
        "forward_proxy_reflection_summary={}",
        record.reflection.summary()
    );

    match record.approval.approval_request.as_ref() {
        Some(approval_request) => println!(
            "forward_proxy_approval_request={}",
            serde_json::to_string(approval_request)
                .expect("forward proxy approval request should serialize")
        ),
        None => {
            eprintln!("forward_proxy_approval_request_error=missing approval request");
            std::process::exit(1);
        }
    }

    match runtime.store().latest_audit_record() {
        Ok(Some(record)) => println!(
            "persisted_forward_proxy_audit_record={}",
            serde_json::to_string(&record)
                .expect("persisted forward proxy audit record should serialize")
        ),
        Ok(None) => {
            eprintln!(
                "persisted_forward_proxy_audit_record_error=missing persisted forward proxy audit record"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_forward_proxy_audit_record_error={error}");
            std::process::exit(1);
        }
    }
    match runtime.store().latest_approval_request() {
        Ok(Some(record)) => println!(
            "persisted_forward_proxy_approval_request={}",
            serde_json::to_string(&record)
                .expect("persisted forward proxy approval request should serialize")
        ),
        Ok(None) => {
            eprintln!(
                "persisted_forward_proxy_approval_request_error=missing persisted forward proxy approval request"
            );
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("persisted_forward_proxy_approval_request_error={error}");
            std::process::exit(1);
        }
    }
}

fn provider_abstraction_plan_summary(plan: &ProviderAbstractionPlan) -> String {
    format!(
        "providers={} taxonomy_output={} contract_fields={} metadata_fields={}",
        plan.taxonomy.providers.join(","),
        plan.taxonomy.output_fields.join(","),
        plan.contract.contract_fields.join(","),
        plan.metadata.metadata_fields.join(",")
    )
}

fn provider_metadata_catalog_summary(catalog: &ProviderMetadataCatalog) -> String {
    let actions = catalog
        .entries
        .iter()
        .map(|entry| entry.action.to_string())
        .collect::<Vec<_>>()
        .join(",");

    format!("entries={} actions={actions}", catalog.entries.len())
}
