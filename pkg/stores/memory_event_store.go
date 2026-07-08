package stores

import (
	"context"
	"fmt"
	"sync"

	"github.com/oarkflow/authz"
)

// MemoryEventStore implements in-memory event persistence
type MemoryEventStore struct {
	mu     sync.RWMutex
	events []*authz.Event
}

func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{events: make([]*authz.Event, 0)}
}

func (s *MemoryEventStore) LogEvent(ctx context.Context, event *authz.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *MemoryEventStore) ListEvents(ctx context.Context, filter authz.EventFilter) ([]*authz.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Event, 0)
	skipped := 0
	for _, event := range s.events {
		if filter.TenantID != "" && event.TenantID != filter.TenantID {
			continue
		}
		if filter.Type != "" && event.Type != filter.Type {
			continue
		}
		if filter.ActorID != "" && event.ActorID != filter.ActorID {
			continue
		}
		if filter.TargetID != "" && event.TargetID != filter.TargetID {
			continue
		}
		if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
			continue
		}
		if filter.Offset > 0 && skipped < filter.Offset {
			skipped++
			continue
		}
		result = append(result, event)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

// MemoryWebhookStore implements in-memory webhook persistence
type MemoryWebhookStore struct {
	mu       sync.RWMutex
	webhooks map[string]*authz.Webhook
}

func NewMemoryWebhookStore() *MemoryWebhookStore {
	return &MemoryWebhookStore{webhooks: make(map[string]*authz.Webhook)}
}

func (s *MemoryWebhookStore) CreateWebhook(ctx context.Context, wh *authz.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.webhooks[wh.ID]; exists {
		return fmt.Errorf("webhook already exists: %s", wh.ID)
	}
	s.webhooks[wh.ID] = wh
	return nil
}

func (s *MemoryWebhookStore) UpdateWebhook(ctx context.Context, wh *authz.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.webhooks[wh.ID]; !ok {
		return fmt.Errorf("webhook not found: %s", wh.ID)
	}
	s.webhooks[wh.ID] = wh
	return nil
}

func (s *MemoryWebhookStore) DeleteWebhook(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webhooks, id)
	return nil
}

func (s *MemoryWebhookStore) GetWebhook(ctx context.Context, id string) (*authz.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wh, ok := s.webhooks[id]
	if !ok {
		return nil, fmt.Errorf("webhook not found: %s", id)
	}
	copy := *wh
	return &copy, nil
}

func (s *MemoryWebhookStore) ListWebhooks(ctx context.Context, tenantID string) ([]*authz.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Webhook, 0)
	for _, wh := range s.webhooks {
		if tenantID == "" || wh.TenantID == tenantID {
			copy := *wh
			result = append(result, &copy)
		}
	}
	return result, nil
}

func (s *MemoryWebhookStore) ListWebhooksByEvent(ctx context.Context, tenantID string, eventType authz.EventType) ([]*authz.Webhook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Webhook, 0)
	for _, wh := range s.webhooks {
		if tenantID != "" && wh.TenantID != tenantID {
			continue
		}
		if !wh.Enabled {
			continue
		}
		for _, et := range wh.Events {
			if et == eventType {
				copy := *wh
				result = append(result, &copy)
				break
			}
		}
	}
	return result, nil
}
