package authz_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func TestPolicyBundleDistributorPublishesBundles(t *testing.T) {
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore)
	policy := &authz.Policy{
		ID:        "bundle-policy",
		TenantID:  "tenant-dist",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
	}
	if err := engine.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	dist, err := authz.NewPolicyBundleDistributor(policyStore)
	if err != nil {
		t.Fatalf("new distributor: %v", err)
	}
	received := make(chan *authz.SignedPolicyBundle, 1)
	dist.RegisterSubscriber("tenant-dist", authz.BundleSubscriberFunc(func(ctx context.Context, tenantID string, _ ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
		if tenantID != "tenant-dist" {
			t.Fatalf("unexpected tenant: %s", tenantID)
		}
		received <- bundle
		return nil
	}))
	dist.Start(context.Background())
	engine.SetBundleDistributor(dist)

	dist.NotifyPolicyChange("tenant-dist")

	select {
	case bundle := <-received:
		if len(bundle.Policies) == 0 {
			t.Fatalf("expected bundle policies")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for bundle")
	}

	if err := dist.Stop(context.Background()); err != nil {
		t.Fatalf("stop distributor: %v", err)
	}
}
