package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryInvitationStore implements in-memory invitation persistence
type MemoryInvitationStore struct {
	mu          sync.RWMutex
	invitations map[string]*authz.Invitation
}

func NewMemoryInvitationStore() *MemoryInvitationStore {
	return &MemoryInvitationStore{invitations: make(map[string]*authz.Invitation)}
}

func (s *MemoryInvitationStore) CreateInvitation(ctx context.Context, invite *authz.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.invitations[invite.ID]; exists {
		return fmt.Errorf("invitation already exists: %s", invite.ID)
	}
	invite.CreatedAt = time.Now()
	s.invitations[invite.ID] = invite
	return nil
}

func (s *MemoryInvitationStore) GetInvitation(ctx context.Context, id string) (*authz.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.invitations[id]
	if !ok {
		return nil, fmt.Errorf("invitation not found: %s", id)
	}
	cp := *inv
	return &cp, nil
}

func (s *MemoryInvitationStore) GetInvitationByToken(ctx context.Context, tokenHash string) (*authz.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.invitations {
		if inv.TokenHash == tokenHash {
			cp := *inv
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("invitation not found for token")
}

func (s *MemoryInvitationStore) UpdateInvitation(ctx context.Context, invite *authz.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.invitations[invite.ID]; !ok {
		return fmt.Errorf("invitation not found: %s", invite.ID)
	}
	s.invitations[invite.ID] = invite
	return nil
}

func (s *MemoryInvitationStore) DeleteInvitation(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.invitations, id)
	return nil
}

func (s *MemoryInvitationStore) ListInvitations(ctx context.Context, tenantID string) ([]*authz.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Invitation, 0)
	for _, inv := range s.invitations {
		if tenantID == "" || inv.TenantID == tenantID {
			cp := *inv
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (s *MemoryInvitationStore) ListPendingByEmail(ctx context.Context, email string) ([]*authz.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Invitation, 0)
	for _, inv := range s.invitations {
		if inv.Email == email && inv.Status == authz.InviteStatusPending {
			cp := *inv
			result = append(result, &cp)
		}
	}
	return result, nil
}
