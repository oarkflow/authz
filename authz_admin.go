package authz

import (
	"context"
	"strings"
	"time"
)

// ExplainRequest is a minimal request for Explain API used by admin server
type ExplainRequest struct {
	Tenant    string   `json:"tenant"`
	SubjectID string   `json:"subject_id"`
	Roles     []string `json:"roles,omitempty"`
	Action    string   `json:"action"`
	Resource  string   `json:"resource"` // format: type:id or route:GET:/users/1
	OwnerID   string   `json:"owner_id,omitempty"`
}

func (e *Engine) ExplainRequest(ctx context.Context, req *ExplainRequest) (*Decision, error) {
	sub := &Subject{ID: req.SubjectID, TenantID: req.Tenant}
	if len(req.Roles) > 0 {
		sub.Roles = append(sub.Roles, req.Roles...)
	}
	// parse resource
	rType := ""
	rID := req.Resource
	if idx := strings.Index(req.Resource, ":"); idx != -1 {
		rType = req.Resource[:idx]
		rID = req.Resource[idx+1:]
	}
	res := &Resource{Type: rType, ID: rID, TenantID: req.Tenant}
	if req.OwnerID != "" {
		res.OwnerID = req.OwnerID
	}
	env := &Environment{Time: time.Now(), TenantID: req.Tenant}
	return e.Explain(ctx, sub, Action(req.Action), res, env)
}
