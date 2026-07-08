package sqldriver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLEventStore persists events in SQL (squealx).
type SQLEventStore struct {
	db *squealx.DB
}

// NewSQLEventStore creates a new SQL-backed event store.
func NewSQLEventStore(db *squealx.DB) *SQLEventStore {
	return &SQLEventStore{db: db}
}

func (s *SQLEventStore) LogEvent(ctx context.Context, event *authz.Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	dataJSON := "{}"
	if event.Data != nil {
		b, err := json.Marshal(event.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal event data: %w", err)
		}
		dataJSON = string(b)
	}

	q := `INSERT INTO events (id, tenant_id, type, actor_id, target_id, data_json, timestamp)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, event.ID, event.TenantID, string(event.Type), event.ActorID, event.TargetID, dataJSON, event.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for event %s", event.ID)
	}
	return nil
}

func (s *SQLEventStore) ListEvents(ctx context.Context, filter authz.EventFilter) ([]*authz.Event, error) {
	q := `SELECT id, tenant_id, type, actor_id, target_id, data_json, timestamp FROM events WHERE 1=1`
	args := make([]any, 0)

	if filter.TenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, filter.TenantID)
	}
	if filter.Type != "" {
		q += ` AND type = ?`
		args = append(args, string(filter.Type))
	}
	if filter.ActorID != "" {
		q += ` AND actor_id = ?`
		args = append(args, filter.ActorID)
	}
	if filter.TargetID != "" {
		q += ` AND target_id = ?`
		args = append(args, filter.TargetID)
	}
	if !filter.StartTime.IsZero() {
		q += ` AND timestamp >= ?`
		args = append(args, filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		q += ` AND timestamp <= ?`
		args = append(args, filter.EndTime)
	}

	q += ` ORDER BY timestamp DESC`

	if filter.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		q += ` OFFSET ?`
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*authz.Event
	for rows.Next() {
		var event authz.Event
		var eventType string
		var actorID, targetID, dataJSON sql.NullString
		var timestamp sql.NullString

		err := rows.Scan(&event.ID, &event.TenantID, &eventType, &actorID, &targetID, &dataJSON, &timestamp)
		if err != nil {
			return nil, err
		}

		event.Type = authz.EventType(eventType)
		if actorID.Valid {
			event.ActorID = actorID.String
		}
		if targetID.Valid {
			event.TargetID = targetID.String
		}
		if dataJSON.Valid && dataJSON.String != "" {
			_ = json.Unmarshal([]byte(dataJSON.String), &event.Data)
		}
		if timestamp.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", timestamp.String); err == nil {
				event.Timestamp = t
			}
		}

		events = append(events, &event)
	}

	return events, nil
}

// SQLWebhookStore persists webhooks in SQL (squealx).
type SQLWebhookStore struct {
	db *squealx.DB
}

// NewSQLWebhookStore creates a new SQL-backed webhook store.
func NewSQLWebhookStore(db *squealx.DB) *SQLWebhookStore {
	return &SQLWebhookStore{db: db}
}

func (s *SQLWebhookStore) CreateWebhook(ctx context.Context, wh *authz.Webhook) error {
	if wh.CreatedAt.IsZero() {
		wh.CreatedAt = time.Now()
	}
	if wh.UpdatedAt.IsZero() {
		wh.UpdatedAt = wh.CreatedAt
	}

	eventsJSON := "[]"
	if wh.Events != nil {
		b, err := json.Marshal(wh.Events)
		if err != nil {
			return fmt.Errorf("failed to marshal events: %w", err)
		}
		eventsJSON = string(b)
	}

	enabled := 0
	if wh.Enabled {
		enabled = 1
	}

	q := `INSERT INTO webhooks (id, tenant_id, url, secret, events_json, enabled, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, wh.ID, wh.TenantID, wh.URL, wh.Secret, eventsJSON, enabled, wh.CreatedAt, wh.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert webhook: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for webhook %s", wh.ID)
	}
	return nil
}

func (s *SQLWebhookStore) UpdateWebhook(ctx context.Context, wh *authz.Webhook) error {
	wh.UpdatedAt = time.Now()

	eventsJSON := "[]"
	if wh.Events != nil {
		b, err := json.Marshal(wh.Events)
		if err != nil {
			return fmt.Errorf("failed to marshal events: %w", err)
		}
		eventsJSON = string(b)
	}

	enabled := 0
	if wh.Enabled {
		enabled = 1
	}

	q := `UPDATE webhooks SET tenant_id = :tenant_id, url = :url, secret = :secret, events_json = :events_json, enabled = :enabled, updated_at = :updated_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":          wh.ID,
		"tenant_id":   wh.TenantID,
		"url":         wh.URL,
		"secret":      wh.Secret,
		"events_json": eventsJSON,
		"enabled":     enabled,
		"updated_at":  wh.UpdatedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("webhook not found: %s", wh.ID)
	}
	return nil
}

func (s *SQLWebhookStore) DeleteWebhook(ctx context.Context, id string) error {
	q := `DELETE FROM webhooks WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("webhook not found: %s", id)
	}
	return nil
}

func (s *SQLWebhookStore) GetWebhook(ctx context.Context, id string) (*authz.Webhook, error) {
	q := `SELECT id, tenant_id, url, secret, events_json, enabled, created_at, updated_at FROM webhooks WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var wh authz.Webhook
	var secret, eventsJSON sql.NullString
	var enabled int
	var createdAt, updatedAt sql.NullString

	err := row.Scan(&wh.ID, &wh.TenantID, &wh.URL, &secret, &eventsJSON, &enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("webhook not found: %s", id)
	}

	if secret.Valid {
		wh.Secret = secret.String
	}
	if eventsJSON.Valid && eventsJSON.String != "" {
		_ = json.Unmarshal([]byte(eventsJSON.String), &wh.Events)
	}
	wh.Enabled = enabled == 1
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			wh.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedAt.String); err == nil {
			wh.UpdatedAt = t
		}
	}

	return &wh, nil
}

func (s *SQLWebhookStore) ListWebhooks(ctx context.Context, tenantID string) ([]*authz.Webhook, error) {
	q := `SELECT id, tenant_id, url, secret, events_json, enabled, created_at, updated_at FROM webhooks`
	args := make([]any, 0)

	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanWebhooks(rows)
}

func (s *SQLWebhookStore) ListWebhooksByEvent(ctx context.Context, tenantID string, eventType authz.EventType) ([]*authz.Webhook, error) {
	q := `SELECT id, tenant_id, url, secret, events_json, enabled, created_at, updated_at FROM webhooks WHERE enabled = 1`
	args := make([]any, 0)

	if tenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	all, err := s.scanWebhooks(rows)
	if err != nil {
		return nil, err
	}

	// Filter by event type in application layer since events_json is a JSON array
	result := make([]*authz.Webhook, 0)
	for _, wh := range all {
		for _, et := range wh.Events {
			if et == eventType {
				result = append(result, wh)
				break
			}
		}
	}
	return result, nil
}

func (s *SQLWebhookStore) scanWebhooks(rows *squealx.Rows) ([]*authz.Webhook, error) {
	var webhooks []*authz.Webhook
	for rows.Next() {
		var wh authz.Webhook
		var secret, eventsJSON sql.NullString
		var enabled int
		var createdAt, updatedAt sql.NullString

		err := rows.Scan(&wh.ID, &wh.TenantID, &wh.URL, &secret, &eventsJSON, &enabled, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		if secret.Valid {
			wh.Secret = secret.String
		}
		if eventsJSON.Valid && eventsJSON.String != "" {
			_ = json.Unmarshal([]byte(eventsJSON.String), &wh.Events)
		}
		wh.Enabled = enabled == 1
		if createdAt.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
				wh.CreatedAt = t
			}
		}
		if updatedAt.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", updatedAt.String); err == nil {
				wh.UpdatedAt = t
			}
		}

		webhooks = append(webhooks, &wh)
	}
	return webhooks, nil
}
