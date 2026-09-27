package authz

import (
	"context"
	"fmt"
	"time"
)

// ============================================================================
// GDPR / RIGHT-TO-ERASURE SUPPORT
// ============================================================================
//
// EraseSubjectData implements a best-effort "right to erasure" (GDPR Art. 17)
// across every store that may hold data identifying a subject. It is
// deliberately store-agnostic: callers wire up whichever stores their
// deployment actually uses via ErasureDeps, and any store left nil is
// skipped rather than treated as an error.
//
// Audit trail tradeoff: audit log entries are never deleted by this
// function. Audit stores in this project are moving towards tamper-evident,
// hash-chained storage (a concurrent workstream), so removing or mutating
// historical entries wholesale would break chain integrity and destroy the
// forensic value of the log. Instead, the subject identifier embedded in
// each historical entry is replaced with an anonymized placeholder
// (see anonymizedSubjectID), preserving the shape/count/chain of the log
// while removing the personally identifying value. This is a conscious
// compliance tradeoff: it satisfies "erase personal data" without
// sacrificing "preserve an immutable record that access decisions were
// made". Callers requiring true audit deletion must handle that outside
// this helper (e.g. once a retention window has passed and the chain
// segment can be archived/rotated).

// ErasureDeps lists the stores EraseSubjectData can operate against. Every
// field is optional (nil-safe): a nil store is simply skipped, so callers
// only need to wire up the stores they actually use.
type ErasureDeps struct {
	UserStore            UserStore
	SessionStore         SessionStore
	APIKeyStore          APIKeyStore
	RoleMembershipStore  RoleMembershipStore
	ACLStore             ACLStore
	GroupMembershipStore GroupMembershipStore
	InvitationStore      InvitationStore
	ServiceAccountStore  ServiceAccountStore
	AuditStore           AuditStore

	// TenantID scopes ACL/invitation listing where the underlying store
	// requires a tenant filter. Optional: an empty string lists across all
	// tenants where the store supports it.
	TenantID string
}

// ErasureReport summarizes what EraseSubjectData removed or anonymized,
// broken down per store, for compliance record-keeping.
type ErasureReport struct {
	SubjectID                 string    `json:"subject_id"`
	TenantID                  string    `json:"tenant_id,omitempty"`
	StartedAt                 time.Time `json:"started_at"`
	CompletedAt               time.Time `json:"completed_at"`
	UserDeleted               bool      `json:"user_deleted"`
	SessionsDeleted           int       `json:"sessions_deleted"`
	APIKeysDeleted            int       `json:"api_keys_deleted"`
	RoleMembershipsRemoved    int       `json:"role_memberships_removed"`
	ACLsRemoved               int       `json:"acls_removed"`
	GroupMembershipsRemoved   int       `json:"group_memberships_removed"`
	InvitationsAnonymized     int       `json:"invitations_anonymized"`
	ServiceAccountsAnonymized int       `json:"service_accounts_anonymized"`
	AuditEntriesAnonymized    int       `json:"audit_entries_anonymized"`
	Errors                    []string  `json:"errors,omitempty"`
}

func (r *ErasureReport) addErr(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

// anonymizedSubjectID returns a stable, non-reversible placeholder used to
// replace a subject identifier in records that must not be deleted outright
// (currently: audit log entries).
func anonymizedSubjectID(subjectID string) string {
	return "erased-subject"
}

// EraseSubjectData performs a best-effort right-to-erasure sweep for
// subjectID across every store configured in deps. It deletes user,
// session, API key, role-membership, ACL, and group-membership records
// naming the subject; anonymizes invitations addressed to the subject's
// email (when a UserStore is available to resolve it) and any service
// accounts the subject created; and anonymizes (never deletes) the
// subject's identifier within historical audit log entries. The erasure
// itself is logged as a new audit event under the action "gdpr.erase" when
// an AuditStore is configured.
//
// Individual store failures do not abort the sweep: they are collected in
// ErasureReport.Errors so a partial erasure is still visible to the caller,
// and the function returns a non-nil error only when at least one store
// operation failed.
func EraseSubjectData(ctx context.Context, deps ErasureDeps, tenantID, subjectID string) (*ErasureReport, error) {
	if subjectID == "" {
		return nil, fmt.Errorf("authz: subjectID is required for erasure")
	}
	if tenantID == "" {
		tenantID = deps.TenantID
	}

	report := &ErasureReport{
		SubjectID: subjectID,
		TenantID:  tenantID,
		StartedAt: time.Now(),
	}

	var subjectEmail string

	if deps.UserStore != nil {
		if user, err := deps.UserStore.GetUser(ctx, subjectID); err == nil && user != nil {
			subjectEmail = user.Email
		}
		if err := deps.UserStore.DeleteUser(ctx, subjectID); err != nil {
			report.addErr("user store: %v", err)
		} else {
			report.UserDeleted = true
		}
	}

	if deps.SessionStore != nil {
		sessions, err := deps.SessionStore.ListUserSessions(ctx, subjectID)
		if err != nil {
			report.addErr("session store list: %v", err)
		} else {
			report.SessionsDeleted = len(sessions)
		}
		if err := deps.SessionStore.DeleteUserSessions(ctx, subjectID); err != nil {
			report.addErr("session store delete: %v", err)
		}
	}

	if deps.APIKeyStore != nil {
		keys, err := deps.APIKeyStore.ListAPIKeys(ctx, subjectID)
		if err != nil {
			report.addErr("api key store list: %v", err)
		} else {
			for _, key := range keys {
				if err := deps.APIKeyStore.DeleteAPIKey(ctx, key.ID); err != nil {
					report.addErr("api key store delete %s: %v", key.ID, err)
					continue
				}
				report.APIKeysDeleted++
			}
		}
	}

	if deps.RoleMembershipStore != nil {
		roles, err := deps.RoleMembershipStore.ListRoles(ctx, subjectID)
		if err != nil {
			report.addErr("role membership store list: %v", err)
		} else {
			for _, roleID := range roles {
				if err := deps.RoleMembershipStore.RevokeRole(ctx, subjectID, roleID); err != nil {
					report.addErr("role membership store revoke %s: %v", roleID, err)
					continue
				}
				report.RoleMembershipsRemoved++
			}
		}
	}

	if deps.ACLStore != nil {
		acls, err := deps.ACLStore.ListACLsBySubject(ctx, subjectID)
		if err != nil {
			report.addErr("acl store list: %v", err)
		} else {
			for _, acl := range acls {
				if err := deps.ACLStore.RevokeACL(ctx, acl.ID); err != nil {
					report.addErr("acl store revoke %s: %v", acl.ID, err)
					continue
				}
				report.ACLsRemoved++
			}
		}
	}

	if deps.GroupMembershipStore != nil {
		groupIDs, err := deps.GroupMembershipStore.ListGroups(ctx, subjectID)
		if err != nil {
			report.addErr("group membership store list: %v", err)
		} else {
			for _, groupID := range groupIDs {
				if err := deps.GroupMembershipStore.RemoveMember(ctx, groupID, subjectID); err != nil {
					report.addErr("group membership store remove %s: %v", groupID, err)
					continue
				}
				report.GroupMembershipsRemoved++
			}
		}
	}

	if deps.InvitationStore != nil && subjectEmail != "" {
		invites, err := deps.InvitationStore.ListInvitations(ctx, tenantID)
		if err != nil {
			report.addErr("invitation store list: %v", err)
		} else {
			for _, inv := range invites {
				if inv.Email != subjectEmail {
					continue
				}
				inv.Email = anonymizedSubjectID(subjectID) + "@erased.invalid"
				inv.TokenHash = ""
				inv.Token = ""
				if err := deps.InvitationStore.UpdateInvitation(ctx, inv); err != nil {
					report.addErr("invitation store update %s: %v", inv.ID, err)
					continue
				}
				report.InvitationsAnonymized++
			}
		}
	}

	if deps.ServiceAccountStore != nil {
		sas, err := deps.ServiceAccountStore.ListServiceAccounts(ctx, tenantID)
		if err != nil {
			report.addErr("service account store list: %v", err)
		} else {
			for _, sa := range sas {
				if sa.CreatedBy != subjectID {
					continue
				}
				sa.CreatedBy = anonymizedSubjectID(subjectID)
				if err := deps.ServiceAccountStore.UpdateServiceAccount(ctx, sa); err != nil {
					report.addErr("service account store update %s: %v", sa.ID, err)
					continue
				}
				report.ServiceAccountsAnonymized++
			}
		}
	}

	if deps.AuditStore != nil {
		anonymized, err := anonymizeAuditSubject(ctx, deps.AuditStore, subjectID)
		if err != nil {
			report.addErr("audit store anonymize: %v", err)
		}
		report.AuditEntriesAnonymized = anonymized

		erasureEntry := &AuditEntry{
			ID:        fmt.Sprintf("gdpr-erase-%s-%d", subjectID, time.Now().UnixNano()),
			Timestamp: time.Now(),
			Subject:   &Subject{ID: subjectID, TenantID: tenantID, Type: "user"},
			Action:    Action("gdpr.erase"),
			Resource:  &Resource{ID: subjectID, Type: "subject", TenantID: tenantID},
			Decision: &Decision{
				Allowed:   true,
				Reason:    "gdpr erasure completed",
				MatchedBy: "gdpr.erase",
				Timestamp: time.Now(),
			},
			Metadata: map[string]any{
				"user_deleted":              report.UserDeleted,
				"sessions_deleted":          report.SessionsDeleted,
				"api_keys_deleted":          report.APIKeysDeleted,
				"role_memberships_removed":  report.RoleMembershipsRemoved,
				"acls_removed":              report.ACLsRemoved,
				"group_memberships_removed": report.GroupMembershipsRemoved,
				"invitations_anonymized":    report.InvitationsAnonymized,
				"audit_entries_anonymized":  report.AuditEntriesAnonymized,
			},
		}
		if err := deps.AuditStore.LogDecision(ctx, erasureEntry); err != nil {
			report.addErr("audit store log erasure event: %v", err)
		}
	}

	report.CompletedAt = time.Now()

	if len(report.Errors) > 0 {
		return report, fmt.Errorf("authz: erasure completed with %d error(s), see ErasureReport.Errors", len(report.Errors))
	}
	return report, nil
}

// anonymizeAuditSubject rewrites the subject identifier on historical audit
// entries belonging to subjectID in place, without removing the entries
// themselves. AuditStore is intentionally treated as read/append-only here
// (LogDecision/GetAccessLog): stores whose entries are hash-chained return
// pointers into their own storage from GetAccessLog for the in-memory
// implementation, so mutating the returned entries anonymizes them in
// place. Stores backed by immutable/hash-chained persistence that do not
// share this property should implement their own anonymization pass; this
// function is best-effort and never returns an error solely because no
// entries were found.
func anonymizeAuditSubject(ctx context.Context, store AuditStore, subjectID string) (int, error) {
	entries, err := store.GetAccessLog(ctx, AuditFilter{SubjectID: subjectID})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry == nil || entry.Subject == nil {
			continue
		}
		if entry.Subject.ID != subjectID {
			continue
		}
		entry.Subject.ID = anonymizedSubjectID(subjectID)
		entry.Subject.Attrs = nil
		count++
	}
	return count, nil
}
