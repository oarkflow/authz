package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemorySessionStore implements in-memory session persistence.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*authz.Session // id -> session
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*authz.Session)}
}

func (s *MemorySessionStore) CreateSession(ctx context.Context, session *authz.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.ID]; exists {
		return fmt.Errorf("session already exists: %s", session.ID)
	}
	session.CreatedAt = time.Now()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemorySessionStore) GetSession(ctx context.Context, id string) (*authz.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}
	copy := *session
	return &copy, nil
}

func (s *MemorySessionStore) DeleteSession(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemorySessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *MemorySessionStore) ListUserSessions(ctx context.Context, userID string) ([]*authz.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Session, 0)
	for _, session := range s.sessions {
		if session.UserID == userID {
			copy := *session
			result = append(result, &copy)
		}
	}
	return result, nil
}
