package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/middleware"
	"github.com/oarkflow/authz/stores"
)

func TestConfigAuthzHTTPRouteServer(t *testing.T) {
	data, err := os.ReadFile("examples/config.authz")
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := authz.NewDSLParser().Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	roleMembers := stores.NewMemoryRoleMembershipStore()
	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(roleMembers),
	)

	if err := engine.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin dashboard"))
	})
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("user profile"))
	})
	mux.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("public info"))
	})

	authMiddleware := middleware.NewHTTP(&middleware.Config{
		Engine: engine,
		Subject: func(r *http.Request) *authz.Subject {
			return &authz.Subject{
				ID:       r.Header.Get("X-Subject-ID"),
				TenantID: r.Header.Get("X-Tenant-ID"),
			}
		},
		Resource: func(r *http.Request) *authz.Resource {
			res := &authz.Resource{
				ID:       r.Method + ":" + r.URL.Path,
				Type:     "route",
				TenantID: r.Header.Get("X-Tenant-ID"),
			}
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) >= 2 && parts[0] == "users" {
				res.OwnerID = parts[len(parts)-1]
			}
			return res
		},
		Environment: func(r *http.Request) *authz.Environment {
			return &authz.Environment{Time: time.Now(), TenantID: r.Header.Get("X-Tenant-ID")}
		},
	})

	handler := authMiddleware(mux)

	tests := []struct {
		name      string
		subjectID string
		method    string
		path      string
		want      int
	}{
		{
			name:      "route role member can access admin route",
			subjectID: "user:erin",
			method:    http.MethodGet,
			path:      "/admin/dashboard",
			want:      http.StatusOK,
		},
		{
			name:      "owner policy allows owner profile route",
			subjectID: "alice",
			method:    http.MethodGet,
			path:      "/users/alice",
			want:      http.StatusOK,
		},
		{
			name:      "owner policy denies non-owner profile route",
			subjectID: "bob",
			method:    http.MethodGet,
			path:      "/users/alice",
			want:      http.StatusForbidden,
		},
		{
			name:      "route ACL allows guest public info",
			subjectID: "guest",
			method:    http.MethodGet,
			path:      "/public/info",
			want:      http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Subject-ID", tt.subjectID)
			req.Header.Set("X-Tenant-ID", "org1")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("%s %s as %s: got status %d, want %d", tt.method, tt.path, tt.subjectID, rec.Code, tt.want)
			}
		})
	}
}
