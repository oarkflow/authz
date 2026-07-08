package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryAPIKeyStore implements in-memory API key persistence.
type MemoryAPIKeyStore struct {
	mu     sync.RWMutex
	keys   map[string]*authz.APIKey // id -> key
	prefix map[string]*authz.APIKey // prefix -> key (for lookup)
}

func NewMemoryAPIKeyStore() *MemoryAPIKeyStore {
	return &MemoryAPIKeyStore{
		keys:   make(map[string]*authz.APIKey),
		prefix: make(map[string]*authz.APIKey),
	}
}

func (s *MemoryAPIKeyStore) CreateAPIKey(ctx context.Context, key *authz.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[key.ID]; exists {
		return fmt.Errorf("api key already exists: %s", key.ID)
	}
	key.CreatedAt = time.Now()
	s.keys[key.ID] = key
	s.prefix[key.Prefix] = key
	return nil
}

func (s *MemoryAPIKeyStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*authz.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.prefix[prefix]
	if !ok {
		return nil, fmt.Errorf("api key not found for prefix: %s", prefix)
	}
	copy := *key
	return &copy, nil
}

func (s *MemoryAPIKeyStore) ListAPIKeys(ctx context.Context, userID string) ([]*authz.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.APIKey, 0)
	for _, key := range s.keys {
		if key.UserID == userID {
			copy := *key
			result = append(result, &copy)
		}
	}
	return result, nil
}

func (s *MemoryAPIKeyStore) DeleteAPIKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[id]
	if !ok {
		return fmt.Errorf("api key not found: %s", id)
	}
	delete(s.prefix, key.Prefix)
	delete(s.keys, id)
	return nil
}

func (s *MemoryAPIKeyStore) UpdateLastUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[id]
	if !ok {
		return fmt.Errorf("api key not found: %s", id)
	}
	key.LastUsed = time.Now()
	return nil
}
