package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryServiceAccountStore implements in-memory service account persistence
type MemoryServiceAccountStore struct {
	mu       sync.RWMutex
	accounts map[string]*authz.ServiceAccount
}

func NewMemoryServiceAccountStore() *MemoryServiceAccountStore {
	return &MemoryServiceAccountStore{accounts: make(map[string]*authz.ServiceAccount)}
}

func (s *MemoryServiceAccountStore) CreateServiceAccount(ctx context.Context, sa *authz.ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[sa.ID]; exists {
		return fmt.Errorf("service account already exists: %s", sa.ID)
	}
	sa.CreatedAt = time.Now()
	sa.UpdatedAt = sa.CreatedAt
	s.accounts[sa.ID] = sa
	return nil
}

func (s *MemoryServiceAccountStore) UpdateServiceAccount(ctx context.Context, sa *authz.ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[sa.ID]; !ok {
		return fmt.Errorf("service account not found: %s", sa.ID)
	}
	sa.UpdatedAt = time.Now()
	s.accounts[sa.ID] = sa
	return nil
}

func (s *MemoryServiceAccountStore) DeleteServiceAccount(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accounts, id)
	return nil
}

func (s *MemoryServiceAccountStore) GetServiceAccount(ctx context.Context, id string) (*authz.ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sa, ok := s.accounts[id]
	if !ok {
		return nil, fmt.Errorf("service account not found: %s", id)
	}
	cp := *sa
	return &cp, nil
}

func (s *MemoryServiceAccountStore) GetServiceAccountByClientID(ctx context.Context, clientID string) (*authz.ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sa := range s.accounts {
		if sa.ClientID == clientID {
			cp := *sa
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("service account not found for client_id: %s", clientID)
}

func (s *MemoryServiceAccountStore) ListServiceAccounts(ctx context.Context, tenantID string) ([]*authz.ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ServiceAccount, 0)
	for _, sa := range s.accounts {
		if tenantID == "" || sa.TenantID == tenantID {
			cp := *sa
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (s *MemoryServiceAccountStore) UpdateLastUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.accounts[id]
	if !ok {
		return fmt.Errorf("service account not found: %s", id)
	}
	sa.LastUsedAt = time.Now()
	return nil
}
