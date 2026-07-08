package stores

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryUserStore implements in-memory user persistence
type MemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*authz.User
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{users: make(map[string]*authz.User)}
}

func (s *MemoryUserStore) CreateUser(ctx context.Context, user *authz.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user already exists: %s", user.ID)
	}
	// Check unique email per tenant
	for _, u := range s.users {
		if u.TenantID == user.TenantID && u.Email == user.Email {
			return fmt.Errorf("user with email %s already exists in tenant %s", user.Email, user.TenantID)
		}
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = user.CreatedAt
	s.users[user.ID] = user
	return nil
}

func (s *MemoryUserStore) UpdateUser(ctx context.Context, user *authz.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.ID]; !ok {
		return fmt.Errorf("user not found: %s", user.ID)
	}
	// Check unique email per tenant (excluding self)
	for _, u := range s.users {
		if u.ID != user.ID && u.TenantID == user.TenantID && u.Email == user.Email {
			return fmt.Errorf("user with email %s already exists in tenant %s", user.Email, user.TenantID)
		}
	}
	user.UpdatedAt = time.Now()
	s.users[user.ID] = user
	return nil
}

func (s *MemoryUserStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

func (s *MemoryUserStore) GetUser(ctx context.Context, id string) (*authz.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", id)
	}
	copy := *user
	return &copy, nil
}

func (s *MemoryUserStore) GetUserByEmail(ctx context.Context, tenantID, email string) (*authz.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.TenantID == tenantID && u.Email == email {
			copy := *u
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("user not found with email %s in tenant %s", email, tenantID)
}

func (s *MemoryUserStore) ListUsers(ctx context.Context, filter authz.UserFilter) ([]*authz.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.User, 0)
	for _, u := range s.users {
		if !matchesUserFilter(u, filter) {
			continue
		}
		copy := *u
		result = append(result, &copy)
	}
	// Apply offset and limit
	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return []*authz.User{}, nil
		}
		result = result[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(result) {
		result = result[:filter.Limit]
	}
	return result, nil
}

func (s *MemoryUserStore) CountUsers(ctx context.Context, filter authz.UserFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count int64
	for _, u := range s.users {
		if matchesUserFilter(u, filter) {
			count++
		}
	}
	return count, nil
}

func matchesUserFilter(u *authz.User, filter authz.UserFilter) bool {
	if filter.TenantID != "" && u.TenantID != filter.TenantID {
		return false
	}
	if filter.Email != "" && u.Email != filter.Email {
		return false
	}
	if filter.Status != "" && u.Status != filter.Status {
		return false
	}
	if filter.Query != "" {
		q := strings.ToLower(filter.Query)
		if !strings.Contains(strings.ToLower(u.Name), q) && !strings.Contains(strings.ToLower(u.Email), q) {
			return false
		}
	}
	return true
}
