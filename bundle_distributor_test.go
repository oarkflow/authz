package authz_test

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
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

// fakeTransport is an in-process stand-in for a network BundleTransport
// (e.g. Redis Pub/Sub), used to exercise PolicyBundleDistributor's transport
// wiring without a real broker. It fans published bundles out to every
// Subscribe-registered handler except the one belonging to the publishing
// Transport instance, mirroring the "never echo my own publications"
// contract every BundleTransport implementation must uphold.
type fakeTransport struct {
	mu      sync.Mutex
	handler authz.BundleSubscriber
	peers   *[]*fakeTransport
}

func newFakeTransportHub() func() *fakeTransport {
	peers := make([]*fakeTransport, 0)
	return func() *fakeTransport {
		t := &fakeTransport{peers: &peers}
		peers = append(peers, t)
		return t
	}
}

func (t *fakeTransport) Publish(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
	for _, peer := range *t.peers {
		if peer == t {
			continue
		}
		peer.mu.Lock()
		h := peer.handler
		peer.mu.Unlock()
		if h != nil {
			_ = h.OnBundle(ctx, tenantID, pub, bundle)
		}
	}
	return nil
}

func (t *fakeTransport) Subscribe(ctx context.Context, handler authz.BundleSubscriber) (func() error, error) {
	t.mu.Lock()
	t.handler = handler
	t.mu.Unlock()
	return func() error {
		t.mu.Lock()
		t.handler = nil
		t.mu.Unlock()
		return nil
	}, nil
}

func TestPolicyBundleDistributorTransportPropagatesAcrossInstances(t *testing.T) {
	newTransport := newFakeTransportHub()

	policyStoreA := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	engineA := authz.NewEngine(policyStoreA, roleStore, aclStore, auditStore)
	policy := &authz.Policy{
		ID:        "bundle-policy",
		TenantID:  "tenant-dist",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
	}
	if err := engineA.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	distA, err := authz.NewPolicyBundleDistributor(policyStoreA, authz.WithBundleTransport(newTransport()))
	if err != nil {
		t.Fatalf("new distributor A: %v", err)
	}
	engineA.SetBundleDistributor(distA)

	policyStoreB := stores.NewMemoryPolicyStore()
	distB, err := authz.NewPolicyBundleDistributor(policyStoreB, authz.WithBundleTransport(newTransport()))
	if err != nil {
		t.Fatalf("new distributor B: %v", err)
	}

	received := make(chan *authz.SignedPolicyBundle, 1)
	distB.RegisterSubscriber("tenant-dist", authz.BundleSubscriberFunc(func(ctx context.Context, tenantID string, _ ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
		received <- bundle
		return nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	distA.Start(ctx)
	defer distA.Stop(context.Background())
	distB.Start(ctx)
	defer distB.Stop(context.Background())

	distA.NotifyPolicyChange("tenant-dist")

	select {
	case bundle := <-received:
		if len(bundle.Policies) != 1 || bundle.Policies[0].ID != "bundle-policy" {
			t.Fatalf("unexpected bundle contents: %+v", bundle)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bundle to propagate over fake transport")
	}
}
