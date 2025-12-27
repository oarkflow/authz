package stores

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLAuditStore persists audit entries in SQL
type SQLAuditStore struct {
	db *squealx.DB
}

func NewSQLAuditStore(db *squealx.DB) (*SQLAuditStore, error) {
	return &SQLAuditStore{db: db}, nil
}

func (s *SQLAuditStore) LogDecision(ctx context.Context, entry *authz.AuditEntry) error {
	traceB, _ := json.Marshal(entry.Decision.Trace)
	metaB, _ := json.Marshal(entry.Metadata)
	q := `INSERT INTO audit_log(id, timestamp, tenant_id, subject_id, action, resource, allowed, matched_by, reason, trace_json, metadata_json) VALUES(:id, :timestamp, :tenant_id, :subject_id, :action, :resource, :allowed, :matched_by, :reason, :trace_json, :metadata_json)`
	tenant := ""
	if entry != nil && entry.Resource != nil {
		tenant = entry.Resource.TenantID
	}
	subject := ""
	if entry != nil && entry.Subject != nil {
		subject = entry.Subject.ID
	}
	resource := ""
	if entry != nil && entry.Resource != nil {
		resource = entry.Resource.ID
	}
	action := ""
	if entry != nil {
		action = string(entry.Action)
	}
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":            entry.ID,
		"timestamp":     entry.Timestamp,
		"tenant_id":     tenant,
		"subject_id":    subject,
		"action":        action,
		"resource":      resource,
		"allowed":       boolToInt(entry.Decision.Allowed),
		"matched_by":    entry.Decision.MatchedBy,
		"reason":        entry.Decision.Reason,
		"trace_json":    string(traceB),
		"metadata_json": string(metaB),
	})
	return err
}

func (s *SQLAuditStore) GetAccessLog(ctx context.Context, filter authz.AuditFilter) ([]*authz.AuditEntry, error) {
	q := `SELECT id, timestamp, tenant_id, subject_id, action, resource, allowed, matched_by, reason, trace_json, metadata_json FROM audit_log WHERE 1=1`
	params := map[string]any{}
	if filter.SubjectID != "" {
		q += " AND subject_id = :subject_id"
		params["subject_id"] = filter.SubjectID
	}
	if filter.ResourceID != "" {
		q += " AND resource = :resource"
		params["resource"] = filter.ResourceID
	}
	if filter.Action != "" {
		q += " AND action = :action"
		params["action"] = filter.Action
	}
	if !filter.StartTime.IsZero() {
		q += " AND timestamp >= :start"
		params["start"] = filter.StartTime
	}
	if !filter.EndTime.IsZero() {
		q += " AND timestamp <= :end"
		params["end"] = filter.EndTime
	}
	if filter.Limit > 0 {
		q += " LIMIT :limit"
		params["limit"] = filter.Limit
	} else {
		q += " LIMIT 100"
	}
	r, err := s.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.AuditEntry, 0)
	for r.Next() {
		var id, tenant, subject, action, resource, matchedBy, reason, traceJSON, metaJSON string
		var timestampRaw interface{}
		var allowedInt int
		if err := r.Scan(&id, &timestampRaw, &tenant, &subject, &action, &resource, &allowedInt, &matchedBy, &reason, &traceJSON, &metaJSON); err != nil {
			return nil, err
		}
		entry := &authz.AuditEntry{ID: id}
		switch v := timestampRaw.(type) {
		case time.Time:
			entry.Timestamp = v
		case string:
			if t, err := parseFlexibleTime(v); err == nil {
				entry.Timestamp = t
			}
		case []byte:
			if t, err := parseFlexibleTime(string(v)); err == nil {
				entry.Timestamp = t
			}
		}
		entry.Subject = &authz.Subject{ID: subject}
		entry.Action = authz.Action(action)
		entry.Resource = &authz.Resource{ID: resource}
		if tenant != "" {
			entry.Resource.TenantID = tenant
		}
		entry.Decision = &authz.Decision{Allowed: allowedInt != 0, MatchedBy: matchedBy, Reason: reason}
		_ = json.Unmarshal([]byte(traceJSON), &entry.Decision.Trace)
		_ = json.Unmarshal([]byte(metaJSON), &entry.Metadata)
		out = append(out, entry)
	}
	return out, nil
}
