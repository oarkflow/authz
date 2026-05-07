package authz

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// EventType represents the type of IAM event
type EventType string

const (
	EventUserCreated        EventType = "user.created"
	EventUserUpdated        EventType = "user.updated"
	EventUserDeleted        EventType = "user.deleted"
	EventUserSuspended      EventType = "user.suspended"
	EventUserLogin          EventType = "user.login"
	EventUserLoginFailed    EventType = "user.login_failed"
	EventRoleAssigned       EventType = "role.assigned"
	EventRoleRevoked        EventType = "role.revoked"
	EventPolicyCreated      EventType = "policy.created"
	EventPolicyUpdated      EventType = "policy.updated"
	EventPolicyDeleted      EventType = "policy.deleted"
	EventACLGranted         EventType = "acl.granted"
	EventACLRevoked         EventType = "acl.revoked"
	EventInviteSent         EventType = "invite.sent"
	EventInviteAccepted     EventType = "invite.accepted"
	EventGroupCreated       EventType = "group.created"
	EventGroupMemberAdded   EventType = "group.member_added"
	EventGroupMemberRemoved EventType = "group.member_removed"
	EventAPIKeyCreated      EventType = "apikey.created"
	EventAPIKeyRevoked      EventType = "apikey.revoked"
)

// Event represents an IAM event
type Event struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	Type      EventType      `json:"type"`
	ActorID   string         `json:"actor_id"`
	TargetID  string         `json:"target_id,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// EventStore persists events
type EventStore interface {
	LogEvent(ctx context.Context, event *Event) error
	ListEvents(ctx context.Context, filter EventFilter) ([]*Event, error)
}

// EventFilter defines criteria for querying events
type EventFilter struct {
	TenantID  string
	Type      EventType
	ActorID   string
	TargetID  string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
}

// Webhook represents a registered webhook endpoint
type Webhook struct {
	ID        string      `json:"id"`
	TenantID  string      `json:"tenant_id"`
	URL       string      `json:"url"`
	Secret    string      `json:"-"`
	Events    []EventType `json:"events"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// WebhookStore manages webhook registration
type WebhookStore interface {
	CreateWebhook(ctx context.Context, wh *Webhook) error
	UpdateWebhook(ctx context.Context, wh *Webhook) error
	DeleteWebhook(ctx context.Context, id string) error
	GetWebhook(ctx context.Context, id string) (*Webhook, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]*Webhook, error)
	ListWebhooksByEvent(ctx context.Context, tenantID string, eventType EventType) ([]*Webhook, error)
}

// WebhookDelivery tracks webhook delivery attempts
type WebhookDelivery struct {
	ID         string    `json:"id"`
	WebhookID  string    `json:"webhook_id"`
	EventID    string    `json:"event_id"`
	StatusCode int       `json:"status_code"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Attempts   int       `json:"attempts"`
	CreatedAt  time.Time `json:"created_at"`
}

// EventSubscriber is a function that handles events in-process
type EventSubscriber func(event *Event)

// EventDispatcher dispatches events to subscribers and webhooks
type EventDispatcher struct {
	eventStore   EventStore
	webhookStore WebhookStore
	subscribers  []EventSubscriber
	webhookCh    chan *Event
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	httpClient   *http.Client
}

// NewEventDispatcher creates a new EventDispatcher.
func NewEventDispatcher(es EventStore, ws WebhookStore) *EventDispatcher {
	return &EventDispatcher{
		eventStore:   es,
		webhookStore: ws,
		subscribers:  make([]EventSubscriber, 0),
		webhookCh:    make(chan *Event, 256),
		stopCh:       make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Subscribe registers an in-process event subscriber.
func (ed *EventDispatcher) Subscribe(fn EventSubscriber) {
	ed.mu.Lock()
	defer ed.mu.Unlock()
	ed.subscribers = append(ed.subscribers, fn)
}

// Dispatch sends an event to all subscribers and queues webhook deliveries.
func (ed *EventDispatcher) Dispatch(ctx context.Context, event *Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Persist the event
	if ed.eventStore != nil {
		if err := ed.eventStore.LogEvent(ctx, event); err != nil {
			return fmt.Errorf("failed to log event: %w", err)
		}
	}

	// Notify in-process subscribers
	ed.mu.RLock()
	subs := make([]EventSubscriber, len(ed.subscribers))
	copy(subs, ed.subscribers)
	ed.mu.RUnlock()

	for _, fn := range subs {
		fn(event)
	}

	// Queue for webhook delivery
	if ed.webhookStore != nil {
		select {
		case ed.webhookCh <- event:
		default:
			// Channel full; drop to avoid blocking
		}
	}

	return nil
}

// Start begins the webhook delivery worker.
func (ed *EventDispatcher) Start() {
	ed.wg.Add(1)
	go ed.webhookWorker()
}

// Stop gracefully shuts down the dispatcher.
func (ed *EventDispatcher) Stop() {
	close(ed.stopCh)
	ed.wg.Wait()
}

func (ed *EventDispatcher) webhookWorker() {
	defer ed.wg.Done()
	for {
		select {
		case event := <-ed.webhookCh:
			ed.processWebhookEvent(event)
		case <-ed.stopCh:
			// Drain remaining events
			for {
				select {
				case event := <-ed.webhookCh:
					ed.processWebhookEvent(event)
				default:
					return
				}
			}
		}
	}
}

func (ed *EventDispatcher) processWebhookEvent(event *Event) {
	if ed.webhookStore == nil {
		return
	}
	ctx := context.Background()
	webhooks, err := ed.webhookStore.ListWebhooksByEvent(ctx, event.TenantID, event.Type)
	if err != nil {
		return
	}
	for _, wh := range webhooks {
		if !wh.Enabled {
			continue
		}
		_ = ed.deliverWebhook(ctx, wh, event)
	}
}

// SignPayload signs an event payload with HMAC-SHA256.
func SignPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// deliverWebhook makes the HTTP POST to the webhook URL with signing.
func (ed *EventDispatcher) deliverWebhook(ctx context.Context, wh *Webhook, event *Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Type", string(event.Type))
	req.Header.Set("X-Event-ID", event.ID)

	if wh.Secret != "" {
		sig := SignPayload(wh.Secret, payload)
		req.Header.Set("X-Webhook-Signature", sig)
	}

	resp, err := ed.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook returned status %d", resp.StatusCode)
}
