use agent_auditor_hostd::poc::{
    HostdPocPlan,
    enforcement::contract::{EnforcementOutcome, EnforcementScope},
    event_path::ExecEvent,
    filesystem::persist::FilesystemPocStore,
    github::persist::GitHubPocStore,
    gws::{
        contract::ApiRequestObservation, persist::GwsPocStore, preview_provider_metadata_catalog,
    },
    network::{
        contract::{ClassifiedNetworkConnect, DestinationScope},
        persist::NetworkPocStore,
    },
    secret::{
        contract::{BrokeredSecretRequest, ClassifiedSecretAccess, SecretPathAccess},
        persist::SecretPocStore,
    },
};
use agenta_core::{
    PolicyDecision, PolicyDecisionKind, SessionRecord, Severity,
    provider::{ProviderAbstractionPlan, ProviderMetadataCatalog},
};
use agenta_policy::{
    PolicyEvaluator, PolicyInput, RegoPolicyEvaluator, apply_decision_to_event,
    apply_enforcement_to_approval_request, apply_enforcement_to_event,
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
    ) = match preview_process_policy(&exec_delivery.event) {
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
        ppid: exec_delivery.event.ppid,
        uid: exec_delivery.event.uid,
        gid: exec_delivery.event.gid,
        command: "ssh".to_owned(),
        filename: "/usr/bin/ssh".to_owned(),
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
        ppid: exec_delivery.event.ppid,
        uid: exec_delivery.event.uid,
        gid: exec_delivery.event.gid,
        command: "rm".to_owned(),
        filename: "/usr/bin/rm".to_owned(),
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
