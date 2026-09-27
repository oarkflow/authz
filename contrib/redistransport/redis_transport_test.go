package redistransport_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/contrib/redistransport"
	"github.com/oarkflow/authz/pkg/stores"
)

// redisAddr returns the address configured via AUTHZ_TEST_REDIS_ADDR, or
// skips the test when it is unset. There is no in-repo fake Redis, so these
// tests are gated behind a real Redis instance rather than run against a
// bespoke double.
func redisAddr(t *testing.T) string {
	addr := os.Getenv("AUTHZ_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("AUTHZ_TEST_REDIS_ADDR not set; skipping Redis-backed transport test")
	}
	return addr
}

func newClient(t *testing.T, addr string) *redis.Client {
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("could not reach redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedisTransportPropagatesBetweenDistributors(t *testing.T) {
	addr := redisAddr(t)
	channel := "authz:policy-bundles:test"

	clientA := newClient(t, addr)
	clientB := newClient(t, addr)

	transportA := redistransport.New(clientA, redistransport.WithChannel(channel))
	transportB := redistransport.New(clientB, redistransport.WithChannel(channel))

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

	distA, err := authz.NewPolicyBundleDistributor(policyStoreA, authz.WithBundleTransport(transportA))
	if err != nil {
		t.Fatalf("new distributor A: %v", err)
	}
	engineA.SetBundleDistributor(distA)

	// distB represents a second engine replica: it never sees policyStoreA
	// directly, only bundles that arrive over the transport.
	policyStoreB := stores.NewMemoryPolicyStore()
	distB, err := authz.NewPolicyBundleDistributor(policyStoreB, authz.WithBundleTransport(transportB))
	if err != nil {
		t.Fatalf("new distributor B: %v", err)
	}

	received := make(chan *authz.SignedPolicyBundle, 1)
	distB.RegisterSubscriber("tenant-dist", authz.BundleSubscriberFunc(func(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
		received <- bundle
		return nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	distA.Start(ctx)
	defer distA.Stop(context.Background())
	distB.Start(ctx)
	defer distB.Stop(context.Background())

	// Give the Redis subscription time to actually register before publishing.
	time.Sleep(200 * time.Millisecond)

	distA.NotifyPolicyChange("tenant-dist")

	select {
	case bundle := <-received:
		if len(bundle.Policies) != 1 || bundle.Policies[0].ID != "bundle-policy" {
			t.Fatalf("unexpected bundle contents: %+v", bundle)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for bundle to propagate over redis transport")
	}
}

func TestRedisTransportDoesNotEchoOwnPublications(t *testing.T) {
	addr := redisAddr(t)
	channel := "authz:policy-bundles:echo-test"
	client := newClient(t, addr)
	transport := redistransport.New(client, redistransport.WithChannel(channel))

	received := make(chan struct{}, 1)
	stop, err := transport.Subscribe(context.Background(), authz.BundleSubscriberFunc(func(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
		received <- struct{}{}
		return nil
	}))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer stop()

	time.Sleep(200 * time.Millisecond)

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	bundle := &authz.SignedPolicyBundle{Policies: nil, Signatures: map[string]string{}}
	if err := transport.Publish(context.Background(), "tenant-x", pub, bundle); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case <-received:
		t.Fatal("transport delivered its own publication back to its handler")
	case <-time.After(500 * time.Millisecond):
	}
}
