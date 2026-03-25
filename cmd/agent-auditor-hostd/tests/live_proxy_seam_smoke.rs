use agent_auditor_hostd::poc::live_proxy::{
    LiveProxyInterceptionPlan, fixtures::seam_fixture_catalog, mode::LiveMode,
};

#[test]
fn smoke_test_runs_live_proxy_fixture_catalog_through_policy_approval_and_audit_reflection() {
    let live_proxy = LiveProxyInterceptionPlan::bootstrap();

    for fixture in seam_fixture_catalog() {
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(fixture.consumer, &fixture.event)
            .unwrap_or_else(|error| panic!("{} failed policy evaluation: {error}", fixture.name));

        assert_eq!(
            evaluation.policy_decision.decision,
            fixture.expected_decision
        );
        assert_eq!(
            evaluation.coverage_posture.label(),
            fixture.expected_coverage_posture
        );
        assert_eq!(
            evaluation.mode_behavior.label(),
            fixture.expected_mode_behavior
        );
        assert_eq!(evaluation.mode_status, fixture.expected_mode_status);
        assert_eq!(evaluation.record_status, fixture.expected_record_status);
        assert_eq!(
            evaluation.coverage_display_rule.label(),
            fixture.expected_coverage_display_rule
        );

        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .unwrap_or_else(|error| panic!("{} failed approval projection: {error}", fixture.name));

        assert_eq!(
            approval.approval_request.is_some(),
            fixture.expect_approval_request,
            "{} approval materialization mismatch",
            fixture.name
        );
        assert_eq!(approval.wait_state.as_deref(), fixture.expected_wait_state);

        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);

        assert_eq!(reflection.mode_behavior, fixture.expected_mode_behavior);
        assert_eq!(reflection.mode_status, fixture.expected_mode_status);
        assert_eq!(reflection.record_status, fixture.expected_record_status);
        assert_eq!(reflection.failure_posture, fixture.expected_failure_posture);
        assert_eq!(
            reflection.coverage_support,
            fixture.expected_coverage_support
        );
        assert_eq!(
            reflection.coverage_display_rule,
            fixture.expected_coverage_display_rule
        );
        assert_eq!(
            reflection.coverage_summary,
            fixture.expected_coverage_summary
        );
        assert_eq!(reflection.coverage_gap, fixture.expected_coverage_gap);
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("mode_status")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_mode_status)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("record_status")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_record_status)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("failure_posture")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_failure_posture)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("coverage_support")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_coverage_support)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("coverage_display_rule")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_coverage_display_rule)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("coverage_summary")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_coverage_summary)
        );
        assert_eq!(
            reflection
                .audit_record
                .action
                .attributes
                .get("coverage_gap")
                .and_then(|value| value.as_str()),
            Some(fixture.expected_coverage_gap)
        );
    }
}

#[test]
fn smoke_test_keeps_live_preview_hardening_posture_honest_across_fixture_catalog() {
    let live_proxy = LiveProxyInterceptionPlan::bootstrap();

    for fixture in seam_fixture_catalog() {
        let evaluation = live_proxy
            .policy
            .evaluate_preview_event(fixture.consumer, &fixture.event)
            .unwrap_or_else(|error| panic!("{} failed policy evaluation: {error}", fixture.name));
        let approval = live_proxy
            .approval
            .project_preview_approval(&evaluation)
            .unwrap_or_else(|error| panic!("{} failed approval projection: {error}", fixture.name));
        let reflection = live_proxy
            .audit
            .reflect_preview_records(&evaluation, &approval);
        let summary = reflection.summary();

        assert_eq!(
            reflection.failure_posture, "fail_open",
            "{} should stay fail-open until a validated inline path exists",
            fixture.name
        );
        assert!(
            !summary.contains("fail_closed"),
            "{} should not advertise fail-closed behavior in live preview summary",
            fixture.name
        );

        match fixture.mode {
            LiveMode::Unsupported => {
                assert_eq!(
                    reflection.coverage_support, "unsupported",
                    "{} should stay marked unsupported",
                    fixture.name
                );
                assert_eq!(
                    reflection.coverage_display_rule, "show_unsupported_and_fail_open",
                    "{} should advertise the unsupported+fail-open display rule",
                    fixture.name
                );
                assert!(
                    reflection
                        .coverage_summary
                        .contains("unsupported live preview path"),
                    "{} should explain that the path is unsupported",
                    fixture.name
                );
                assert!(
                    approval.approval_request.is_none(),
                    "{} should not materialize preview approval state in unsupported mode",
                    fixture.name
                );
            }
            LiveMode::Shadow | LiveMode::EnforcePreview => {
                assert_eq!(
                    reflection.coverage_support, "preview_supported",
                    "{} should remain within the supported preview contract",
                    fixture.name
                );
                assert_eq!(
                    reflection.coverage_display_rule, "show_preview_supported_and_fail_open",
                    "{} should advertise the supported-preview+fail-open display rule",
                    fixture.name
                );
                assert!(
                    reflection.coverage_summary.contains("fail-open"),
                    "{} should explain that supported preview still remains fail-open",
                    fixture.name
                );
            }
        }
    }
}
