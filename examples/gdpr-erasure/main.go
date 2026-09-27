// Command gdpr-erasure demonstrates the GDPR-style "right to erasure"
// (Art. 17) tooling provided by authz.EraseSubjectData.
//
// It wires up several in-memory stores from pkg/stores, seeds one record in
// each for a single subject, runs the erasure sweep, and then prints a
// before/after view of every store so the effect of the sweep is obvious:
// hard deletes for user/session/API-key/role-membership/ACL/group-membership
// records, anonymization (never deletion) for invitations, and anonymization
// in place of historical audit entries plus a new "gdpr.erase" audit record.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func main() {
	ctx := context.Background()

	const tenantID = "tenant-1"
	const subjectID = "user:carol"
	const subjectEmail = "carol@example.com"

	fmt.Println("=== GDPR Right-to-Erasure Example ===")
	fmt.Printf("Tenant:  %s\n", tenantID)
	fmt.Printf("Subject: %s (%s)\n\n", subjectID, subjectEmail)

	// ------------------------------------------------------------------
	// 1. Build in-memory stores and seed one record of each for the subject.
	// ------------------------------------------------------------------
	userStore := stores.NewMemoryUserStore()
	sessionStore := stores.NewMemorySessionStore()
	apiKeyStore := stores.NewMemoryAPIKeyStore()
	roleMembershipStore := stores.NewMemoryRoleMembershipStore()
	defer roleMembershipStore.Close()
	aclStore := stores.NewMemoryACLStore()
	defer aclStore.Close()
	groupMembershipStore := stores.NewMemoryGroupMembershipStore()
	invitationStore := stores.NewMemoryInvitationStore()
	auditStore := stores.NewMemoryAuditStore()

	if err := userStore.CreateUser(ctx, &authz.User{
		ID:       subjectID,
		TenantID: tenantID,
		Email:    subjectEmail,
		Name:     "Carol",
		Status:   authz.UserStatusActive,
	}); err != nil {
		panic(err)
	}

	if err := sessionStore.CreateSession(ctx, &authz.Session{
		ID:        "session-carol-1",
		UserID:    subjectID,
		TenantID:  tenantID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		panic(err)
	}

	if err := apiKeyStore.CreateAPIKey(ctx, &authz.APIKey{
		ID:       "key-carol-1",
		Name:     "carol's personal key",
		Prefix:   "sk_live_carol",
		KeyHash:  "hash-of-carols-key",
		UserID:   subjectID,
		TenantID: tenantID,
	}); err != nil {
		panic(err)
	}

	if err := roleMembershipStore.AssignRole(ctx, subjectID, "role-editor"); err != nil {
		panic(err)
	}

	if err := aclStore.GrantACL(ctx, &authz.ACL{
		ID:         "acl-carol-1",
		TenantID:   tenantID,
		SubjectID:  subjectID,
		ResourceID: "document:quarterly-report",
		Actions:    []authz.Action{"read", "write"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		panic(err)
	}

	if err := groupMembershipStore.AddMember(ctx, "group-finance", subjectID); err != nil {
		panic(err)
	}

	if err := invitationStore.CreateInvitation(ctx, &authz.Invitation{
		ID:        "invite-carol-1",
		TenantID:  tenantID,
		Email:     subjectEmail,
		Status:    authz.InviteStatusPending,
		InvitedBy: "admin-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		TokenHash: "some-invite-token-hash",
	}); err != nil {
		panic(err)
	}

	if err := auditStore.LogDecision(ctx, &authz.AuditEntry{
		ID:        "audit-carol-1",
		Timestamp: time.Now(),
		Subject:   &authz.Subject{ID: subjectID, TenantID: tenantID, Type: "user"},
		Action:    "document.read",
		Resource:  &authz.Resource{ID: "document:quarterly-report", TenantID: tenantID},
		Decision:  &authz.Decision{Allowed: true, Timestamp: time.Now()},
	}); err != nil {
		panic(err)
	}

	fmt.Println("Seeded records for the subject in: user, session, api key, role")
	fmt.Println("membership, acl, group membership, invitation, and audit stores.")

	// ------------------------------------------------------------------
	// 2. Show, before erasure, that the subject has data in each store.
	// ------------------------------------------------------------------
	fmt.Println("\n--- BEFORE erasure ---")

	if u, err := userStore.GetUser(ctx, subjectID); err == nil {
		fmt.Printf("user store:            user %q present (email=%s)\n", u.ID, u.Email)
	}

	sessionsBefore, _ := sessionStore.ListUserSessions(ctx, subjectID)
	fmt.Printf("session store:         %d session(s) present\n", len(sessionsBefore))

	keysBefore, _ := apiKeyStore.ListAPIKeys(ctx, subjectID)
	fmt.Printf("api key store:         %d api key(s) present\n", len(keysBefore))

	rolesBefore, _ := roleMembershipStore.ListRoles(ctx, subjectID)
	fmt.Printf("role membership store: %d role(s) present: %v\n", len(rolesBefore), rolesBefore)

	aclsBefore, _ := aclStore.ListACLsBySubject(ctx, subjectID)
	fmt.Printf("acl store:             %d acl(s) present\n", len(aclsBefore))

	groupsBefore, _ := groupMembershipStore.ListGroups(ctx, subjectID)
	fmt.Printf("group membership store: %d group(s) present: %v\n", len(groupsBefore), groupsBefore)

	inviteBefore, _ := invitationStore.GetInvitation(ctx, "invite-carol-1")
	fmt.Printf("invitation store:      invite %q addressed to %s\n", inviteBefore.ID, inviteBefore.Email)

	logsBefore, _ := auditStore.GetAccessLog(ctx, authz.AuditFilter{})
	fmt.Printf("audit store:           %d entry(ies), subject on audit-carol-1 = %s\n",
		len(logsBefore), findAuditSubject(logsBefore, "audit-carol-1"))

	// ------------------------------------------------------------------
	// 3. Call EraseSubjectData and print the returned report field by field.
	// ------------------------------------------------------------------
	deps := authz.ErasureDeps{
		UserStore:            userStore,
		SessionStore:         sessionStore,
		APIKeyStore:          apiKeyStore,
		RoleMembershipStore:  roleMembershipStore,
		ACLStore:             aclStore,
		GroupMembershipStore: groupMembershipStore,
		InvitationStore:      invitationStore,
		AuditStore:           auditStore,
		TenantID:             tenantID,
	}

	report, err := authz.EraseSubjectData(ctx, deps, tenantID, subjectID)
	if err != nil {
		// A non-nil error just means report.Errors is non-empty (partial
		// erasure); the report itself is still populated and useful.
		fmt.Printf("\nEraseSubjectData reported error(s): %v\n", err)
	}

	fmt.Println("\n--- ErasureReport ---")
	fmt.Printf("SubjectID:                 %s\n", report.SubjectID)
	fmt.Printf("TenantID:                  %s\n", report.TenantID)
	fmt.Printf("StartedAt:                 %s\n", report.StartedAt.Format(time.RFC3339Nano))
	fmt.Printf("CompletedAt:               %s\n", report.CompletedAt.Format(time.RFC3339Nano))
	fmt.Printf("UserDeleted:               %v\n", report.UserDeleted)
	fmt.Printf("SessionsDeleted:           %d\n", report.SessionsDeleted)
	fmt.Printf("APIKeysDeleted:            %d\n", report.APIKeysDeleted)
	fmt.Printf("RoleMembershipsRemoved:    %d\n", report.RoleMembershipsRemoved)
	fmt.Printf("ACLsRemoved:               %d\n", report.ACLsRemoved)
	fmt.Printf("GroupMembershipsRemoved:   %d\n", report.GroupMembershipsRemoved)
	fmt.Printf("InvitationsAnonymized:     %d\n", report.InvitationsAnonymized)
	fmt.Printf("ServiceAccountsAnonymized: %d\n", report.ServiceAccountsAnonymized)
	fmt.Printf("AuditEntriesAnonymized:    %d\n", report.AuditEntriesAnonymized)
	fmt.Printf("Errors:                    %v\n", report.Errors)

	// ------------------------------------------------------------------
	// 4. Show, after erasure, what happened in each store.
	// ------------------------------------------------------------------
	fmt.Println("\n--- AFTER erasure ---")

	if _, err := userStore.GetUser(ctx, subjectID); err != nil {
		fmt.Println("user store:            user gone (GetUser returned an error), as expected")
	} else {
		fmt.Println("user store:            UNEXPECTED - user still present")
	}

	sessionsAfter, _ := sessionStore.ListUserSessions(ctx, subjectID)
	fmt.Printf("session store:         %d session(s) remaining\n", len(sessionsAfter))

	keysAfter, _ := apiKeyStore.ListAPIKeys(ctx, subjectID)
	fmt.Printf("api key store:         %d api key(s) remaining\n", len(keysAfter))

	rolesAfter, _ := roleMembershipStore.ListRoles(ctx, subjectID)
	fmt.Printf("role membership store: %d role(s) remaining\n", len(rolesAfter))

	aclsAfter, _ := aclStore.ListACLsBySubject(ctx, subjectID)
	fmt.Printf("acl store:             %d acl(s) remaining\n", len(aclsAfter))

	groupsAfter, _ := groupMembershipStore.ListGroups(ctx, subjectID)
	fmt.Printf("group membership store: %d group(s) remaining\n", len(groupsAfter))

	inviteAfter, _ := invitationStore.GetInvitation(ctx, "invite-carol-1")
	fmt.Printf("invitation store:      invite %q NOT deleted; anonymized email=%q, token_hash=%q (was %q)\n",
		inviteAfter.ID, inviteAfter.Email, inviteAfter.TokenHash, inviteBefore.Email)

	logsAfter, _ := auditStore.GetAccessLog(ctx, authz.AuditFilter{})
	fmt.Printf("audit store:           %d entry(ies) total (was %d) - entries are never deleted\n",
		len(logsAfter), len(logsBefore))
	fmt.Printf("  original entry audit-carol-1 subject anonymized in place: %s\n",
		findAuditSubject(logsAfter, "audit-carol-1"))
	fmt.Println("  new entries recording the erasure itself:")
	for _, entry := range logsAfter {
		if entry.Action == "gdpr.erase" {
			fmt.Printf("    id=%s action=%s subject=%s allowed=%v\n",
				entry.ID, entry.Action, entry.Subject.ID, entry.Decision.Allowed)
		}
	}

	fmt.Println("\nDone.")
}

// findAuditSubject returns the anonymized-or-not subject ID recorded against
// the audit entry with the given ID, or "<not found>" if absent.
func findAuditSubject(entries []*authz.AuditEntry, id string) string {
	for _, e := range entries {
		if e.ID == id {
			if e.Subject == nil {
				return "<nil subject>"
			}
			return e.Subject.ID
		}
	}
	return "<not found>"
}
