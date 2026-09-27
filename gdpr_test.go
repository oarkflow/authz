package authz_test

import (
	"context"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func TestEraseSubjectData(t *testing.T) {
	ctx := context.Background()

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

	const tenantID = "tenant-1"
	const subjectID = "user-1"
	const subjectEmail = "erase-me@example.com"

	if err := userStore.CreateUser(ctx, &authz.User{
		ID:       subjectID,
		TenantID: tenantID,
		Email:    subjectEmail,
		Name:     "Erase Me",
		Status:   authz.UserStatusActive,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := sessionStore.CreateSession(ctx, &authz.Session{
		ID:        "session-1",
		UserID:    subjectID,
		TenantID:  tenantID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if err := apiKeyStore.CreateAPIKey(ctx, &authz.APIKey{
		ID:       "key-1",
		Name:     "test key",
		Prefix:   "sk_live_abc",
		KeyHash:  "hash",
		UserID:   subjectID,
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	if err := roleMembershipStore.AssignRole(ctx, subjectID, "role-admin"); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	if err := aclStore.GrantACL(ctx, &authz.ACL{
		ID:         "acl-1",
		TenantID:   tenantID,
		SubjectID:  subjectID,
		ResourceID: "resource-1",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		t.Fatalf("grant acl: %v", err)
	}

	if err := groupMembershipStore.AddMember(ctx, "group-1", subjectID); err != nil {
		t.Fatalf("add group member: %v", err)
	}

	if err := invitationStore.CreateInvitation(ctx, &authz.Invitation{
		ID:        "invite-1",
		TenantID:  tenantID,
		Email:     subjectEmail,
		Status:    authz.InviteStatusPending,
		InvitedBy: "admin-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		TokenHash: "some-hash",
	}); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	if err := auditStore.LogDecision(ctx, &authz.AuditEntry{
		ID:        "audit-1",
		Timestamp: time.Now(),
		Subject:   &authz.Subject{ID: subjectID, TenantID: tenantID, Type: "user"},
		Action:    "resource.read",
		Resource:  &authz.Resource{ID: "resource-1", TenantID: tenantID},
		Decision:  &authz.Decision{Allowed: true, Timestamp: time.Now()},
	}); err != nil {
		t.Fatalf("log decision: %v", err)
	}

	deps := authz.ErasureDeps{
		UserStore:            userStore,
		SessionStore:         sessionStore,
		APIKeyStore:          apiKeyStore,
		RoleMembershipStore:  roleMembershipStore,
		ACLStore:             aclStore,
		GroupMembershipStore: groupMembershipStore,
		InvitationStore:      invitationStore,
		AuditStore:           auditStore,
	}

	report, err := authz.EraseSubjectData(ctx, deps, tenantID, subjectID)
	if err != nil {
		t.Fatalf("EraseSubjectData returned error: %v (errors: %v)", err, report.Errors)
	}

	if !report.UserDeleted {
		t.Errorf("expected UserDeleted to be true")
	}
	if _, err := userStore.GetUser(ctx, subjectID); err == nil {
		t.Errorf("expected user to be gone after erasure")
	}

	if report.SessionsDeleted != 1 {
		t.Errorf("expected 1 session deleted, got %d", report.SessionsDeleted)
	}
	remainingSessions, err := sessionStore.ListUserSessions(ctx, subjectID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(remainingSessions) != 0 {
		t.Errorf("expected no sessions remaining, got %d", len(remainingSessions))
	}

	if report.APIKeysDeleted != 1 {
		t.Errorf("expected 1 api key deleted, got %d", report.APIKeysDeleted)
	}
	remainingKeys, err := apiKeyStore.ListAPIKeys(ctx, subjectID)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if len(remainingKeys) != 0 {
		t.Errorf("expected no api keys remaining, got %d", len(remainingKeys))
	}

	if report.RoleMembershipsRemoved != 1 {
		t.Errorf("expected 1 role membership removed, got %d", report.RoleMembershipsRemoved)
	}
	remainingRoles, err := roleMembershipStore.ListRoles(ctx, subjectID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(remainingRoles) != 0 {
		t.Errorf("expected no roles remaining, got %d", len(remainingRoles))
	}

	if report.ACLsRemoved != 1 {
		t.Errorf("expected 1 acl removed, got %d", report.ACLsRemoved)
	}
	remainingACLs, err := aclStore.ListACLsBySubject(ctx, subjectID)
	if err != nil {
		t.Fatalf("list acls: %v", err)
	}
	if len(remainingACLs) != 0 {
		t.Errorf("expected no acls remaining, got %d", len(remainingACLs))
	}

	if report.GroupMembershipsRemoved != 1 {
		t.Errorf("expected 1 group membership removed, got %d", report.GroupMembershipsRemoved)
	}
	isMember, err := groupMembershipStore.IsMember(ctx, "group-1", subjectID)
	if err != nil {
		t.Fatalf("is member: %v", err)
	}
	if isMember {
		t.Errorf("expected subject to no longer be a group member")
	}

	if report.InvitationsAnonymized != 1 {
		t.Errorf("expected 1 invitation anonymized, got %d", report.InvitationsAnonymized)
	}
	invite, err := invitationStore.GetInvitation(ctx, "invite-1")
	if err != nil {
		t.Fatalf("get invitation: %v", err)
	}
	if invite.Email == subjectEmail {
		t.Errorf("expected invitation email to be anonymized, still %q", invite.Email)
	}
	if invite.TokenHash != "" {
		t.Errorf("expected invitation token hash to be cleared")
	}

	if report.AuditEntriesAnonymized != 1 {
		t.Errorf("expected 1 audit entry anonymized, got %d", report.AuditEntriesAnonymized)
	}

	logs, err := auditStore.GetAccessLog(ctx, authz.AuditFilter{})
	if err != nil {
		t.Fatalf("get access log: %v", err)
	}
	foundOriginalAnonymized := false
	foundErasureRecord := false
	for _, entry := range logs {
		if entry.ID == "audit-1" {
			if entry.Subject == nil || entry.Subject.ID == subjectID {
				t.Errorf("expected original audit entry subject to be anonymized")
			} else {
				foundOriginalAnonymized = true
			}
		}
		if entry.Action == "gdpr.erase" {
			foundErasureRecord = true
		}
	}
	if !foundOriginalAnonymized {
		t.Errorf("expected to find the original audit entry with anonymized subject")
	}
	if !foundErasureRecord {
		t.Errorf("expected an audit log entry recording the gdpr.erase action")
	}
}

func TestEraseSubjectDataNilSafeDeps(t *testing.T) {
	ctx := context.Background()

	// Only wire up a user store; everything else should be skipped without error.
	userStore := stores.NewMemoryUserStore()
	if err := userStore.CreateUser(ctx, &authz.User{
		ID:       "user-solo",
		TenantID: "tenant-1",
		Email:    "solo@example.com",
		Name:     "Solo",
		Status:   authz.UserStatusActive,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	report, err := authz.EraseSubjectData(ctx, authz.ErasureDeps{UserStore: userStore}, "tenant-1", "user-solo")
	if err != nil {
		t.Fatalf("EraseSubjectData returned error: %v (errors: %v)", err, report.Errors)
	}
	if !report.UserDeleted {
		t.Errorf("expected user to be deleted")
	}
	if _, err := userStore.GetUser(ctx, "user-solo"); err == nil {
		t.Errorf("expected user to be gone")
	}
}

func TestEraseSubjectDataRequiresSubjectID(t *testing.T) {
	if _, err := authz.EraseSubjectData(context.Background(), authz.ErasureDeps{}, "tenant-1", ""); err == nil {
		t.Errorf("expected error for empty subjectID")
	}
}
