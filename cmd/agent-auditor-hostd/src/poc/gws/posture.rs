use std::fmt;

use agenta_core::{EnforcementDirective, PolicyDecisionKind};

use super::contract::GwsActionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsRiskPriority {
    P0,
    P1,
    P2,
}

impl GwsRiskPriority {
    pub const fn label(self) -> &'static str {
        match self {
            Self::P0 => "p0",
            Self::P1 => "p1",
            Self::P2 => "p2",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
        }
    }
}

impl fmt::Display for GwsRiskPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsEnforcementPosture {
    ApprovalHoldPreview,
    ObserveOnlyAllowPreview,
}

impl GwsEnforcementPosture {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ApprovalHoldPreview => "approval_hold_preview",
            Self::ObserveOnlyAllowPreview => "observe_only_allow_preview",
        }
    }

    pub const fn expected_policy_decision(self) -> PolicyDecisionKind {
        match self {
            Self::ApprovalHoldPreview => PolicyDecisionKind::RequireApproval,
            Self::ObserveOnlyAllowPreview => PolicyDecisionKind::Allow,
        }
    }

    pub const fn intended_directive(self) -> EnforcementDirective {
        match self {
            Self::ApprovalHoldPreview => EnforcementDirective::Hold,
            Self::ObserveOnlyAllowPreview => EnforcementDirective::Allow,
        }
    }
}

impl fmt::Display for GwsEnforcementPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GwsActionPosture {
    pub action: GwsActionKind,
    pub priority: GwsRiskPriority,
    pub posture: GwsEnforcementPosture,
    pub primary_risk: &'static str,
    pub rationale: &'static str,
}

impl GwsActionPosture {
    pub fn action_label(self) -> &'static str {
        self.action.label()
    }

    pub const fn expected_policy_decision(self) -> PolicyDecisionKind {
        self.posture.expected_policy_decision()
    }

    pub const fn intended_directive(self) -> EnforcementDirective {
        self.posture.intended_directive()
    }
}

const GWS_ACTION_POSTURES: [GwsActionPosture; 4] = [
    GwsActionPosture {
        action: GwsActionKind::DrivePermissionsUpdate,
        priority: GwsRiskPriority::P0,
        posture: GwsEnforcementPosture::ApprovalHoldPreview,
        primary_risk: "sharing_mutation",
        rationale: "Drive sharing changes can broaden access or transfer ownership before the operator can review intent.",
    },
    GwsActionPosture {
        action: GwsActionKind::GmailUsersMessagesSend,
        priority: GwsRiskPriority::P0,
        posture: GwsEnforcementPosture::ApprovalHoldPreview,
        primary_risk: "outbound_delivery",
        rationale: "Outbound Gmail send can deliver sensitive content or impersonate the user to external recipients.",
    },
    GwsActionPosture {
        action: GwsActionKind::DriveFilesGetMedia,
        priority: GwsRiskPriority::P1,
        posture: GwsEnforcementPosture::ApprovalHoldPreview,
        primary_risk: "content_exfiltration",
        rationale: "Drive media download returns file bytes and is a direct content-exfiltration path even when the request is otherwise read-only.",
    },
    GwsActionPosture {
        action: GwsActionKind::AdminReportsActivitiesList,
        priority: GwsRiskPriority::P2,
        posture: GwsEnforcementPosture::ObserveOnlyAllowPreview,
        primary_risk: "audit_read",
        rationale: "Admin activity listing is read-only audit retrieval and should stay visible, but it is lower risk than sharing, send, or content-download actions.",
    },
];

pub fn catalog() -> &'static [GwsActionPosture] {
    &GWS_ACTION_POSTURES
}

pub fn posture_for_action(action: GwsActionKind) -> &'static GwsActionPosture {
    GWS_ACTION_POSTURES
        .iter()
        .find(|entry| entry.action == action)
        .expect("all supported GWS semantic actions must have an enforcement posture")
}

pub fn prioritized_actions() -> Vec<GwsActionKind> {
    GWS_ACTION_POSTURES
        .iter()
        .map(|entry| entry.action)
        .collect()
}

pub fn approval_hold_actions() -> Vec<GwsActionKind> {
    GWS_ACTION_POSTURES
        .iter()
        .filter(|entry| entry.posture == GwsEnforcementPosture::ApprovalHoldPreview)
        .map(|entry| entry.action)
        .collect()
}

#[cfg(test)]
mod tests {
    use agenta_core::{EnforcementDirective, PolicyDecisionKind, SessionRecord};
    use agenta_policy::{PolicyEvaluator, PolicyInput, RegoPolicyEvaluator};

    use super::{
        GwsEnforcementPosture, GwsRiskPriority, approval_hold_actions, catalog, posture_for_action,
        prioritized_actions,
    };
    use crate::poc::gws::{
        classify::ClassifyPlan,
        contract::{ApiRequestObservation, GwsActionKind, NetworkRequestObservation},
        evaluate::EvaluatePlan,
        session_linkage::SessionLinkagePlan,
    };

    #[test]
    fn posture_catalog_orders_supported_actions_by_priority() {
        assert_eq!(
            prioritized_actions(),
            vec![
                GwsActionKind::DrivePermissionsUpdate,
                GwsActionKind::GmailUsersMessagesSend,
                GwsActionKind::DriveFilesGetMedia,
                GwsActionKind::AdminReportsActivitiesList,
            ]
        );
        assert_eq!(catalog().len(), 4);
        assert!(
            catalog()
                .windows(2)
                .all(|pair| pair[0].priority.rank() <= pair[1].priority.rank())
        );
    }

    #[test]
    fn posture_catalog_marks_high_risk_actions_for_approval_hold_preview() {
        let drive_permissions_update = posture_for_action(GwsActionKind::DrivePermissionsUpdate);
        let gmail_users_messages_send = posture_for_action(GwsActionKind::GmailUsersMessagesSend);
        let drive_files_get_media = posture_for_action(GwsActionKind::DriveFilesGetMedia);
        let admin_reports_activities_list =
            posture_for_action(GwsActionKind::AdminReportsActivitiesList);

        assert_eq!(drive_permissions_update.priority, GwsRiskPriority::P0);
        assert_eq!(
            drive_permissions_update.posture,
            GwsEnforcementPosture::ApprovalHoldPreview
        );
        assert_eq!(
            drive_permissions_update.expected_policy_decision(),
            PolicyDecisionKind::RequireApproval
        );
        assert_eq!(
            drive_permissions_update.intended_directive(),
            EnforcementDirective::Hold
        );

        assert_eq!(gmail_users_messages_send.priority, GwsRiskPriority::P0);
        assert_eq!(
            gmail_users_messages_send.posture,
            GwsEnforcementPosture::ApprovalHoldPreview
        );
        assert_eq!(drive_files_get_media.priority, GwsRiskPriority::P1);
        assert_eq!(
            drive_files_get_media.posture,
            GwsEnforcementPosture::ApprovalHoldPreview
        );
        assert_eq!(admin_reports_activities_list.priority, GwsRiskPriority::P2);
        assert_eq!(
            admin_reports_activities_list.posture,
            GwsEnforcementPosture::ObserveOnlyAllowPreview
        );
        assert_eq!(
            admin_reports_activities_list.expected_policy_decision(),
            PolicyDecisionKind::Allow
        );
        assert_eq!(
            admin_reports_activities_list.intended_directive(),
            EnforcementDirective::Allow
        );
        assert_eq!(
            approval_hold_actions(),
            vec![
                GwsActionKind::DrivePermissionsUpdate,
                GwsActionKind::GmailUsersMessagesSend,
                GwsActionKind::DriveFilesGetMedia,
            ]
        );
    }

    #[test]
    fn posture_catalog_matches_checked_in_preview_policy() {
        assert_eq!(
            preview_policy_decision(GwsActionKind::DrivePermissionsUpdate),
            posture_for_action(GwsActionKind::DrivePermissionsUpdate).expected_policy_decision()
        );
        assert_eq!(
            preview_policy_decision(GwsActionKind::DriveFilesGetMedia),
            posture_for_action(GwsActionKind::DriveFilesGetMedia).expected_policy_decision()
        );
        assert_eq!(
            preview_policy_decision(GwsActionKind::GmailUsersMessagesSend),
            posture_for_action(GwsActionKind::GmailUsersMessagesSend).expected_policy_decision()
        );
        assert_eq!(
            preview_policy_decision(GwsActionKind::AdminReportsActivitiesList),
            posture_for_action(GwsActionKind::AdminReportsActivitiesList)
                .expected_policy_decision()
        );
    }

    fn preview_policy_decision(action: GwsActionKind) -> PolicyDecisionKind {
        let session = SessionRecord::placeholder("openclaw-main", "sess_gws_posture_policy");
        let linkage = SessionLinkagePlan::default();
        let classify = ClassifyPlan::from_session_linkage_boundary(linkage.handoff());
        let evaluate = EvaluatePlan::from_classification_boundary(classify.handoff());
        let classified = match action {
            GwsActionKind::DrivePermissionsUpdate => classify
                .classify_action(&linkage.link_api_observation(
                    &ApiRequestObservation::preview_drive_permissions_update(),
                    &session,
                ))
                .expect("drive permissions update should classify"),
            GwsActionKind::DriveFilesGetMedia => classify
                .classify_action(&linkage.link_network_observation(
                    &NetworkRequestObservation::preview_drive_files_get_media(),
                    &session,
                ))
                .expect("drive files get_media should classify"),
            GwsActionKind::GmailUsersMessagesSend => classify
                .classify_action(&linkage.link_api_observation(
                    &ApiRequestObservation::preview_gmail_users_messages_send(),
                    &session,
                ))
                .expect("gmail send should classify"),
            GwsActionKind::AdminReportsActivitiesList => classify
                .classify_action(&linkage.link_api_observation(
                    &ApiRequestObservation::preview_admin_reports_activities_list(),
                    &session,
                ))
                .expect("admin reports activities list should classify"),
        };
        let normalized = evaluate.normalize_classified_action(&classified, &session);

        RegoPolicyEvaluator::gws_action_example()
            .evaluate(&PolicyInput::from_event(&normalized))
            .expect("gws preview policy should evaluate")
            .decision
    }
}
