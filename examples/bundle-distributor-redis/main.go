// Command bundle-distributor-redis demonstrates cross-replica policy
// propagation: two engine replicas, each with its own PolicyBundleDistributor
// and its own PolicyStore, kept in sync over Redis Pub/Sub instead of relying
// solely on each replica's own scheduled reload from a shared store.
//
// See the "Staleness in multi-instance deployments" section of the repo
// README and the package doc comment on bundle_distributor.go for the full
// explanation of why this matters: without a BundleTransport, a policy
// change made against one replica's PolicyBundleDistributor is invisible to
// other replicas until they happen to reload on their own schedule.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/contrib/redistransport"
	"github.com/oarkflow/authz/pkg/stores"
)

func main() {
	fmt.Println("=== Cross-replica policy propagation via Redis pub/sub ===")
	fmt.Println()
	fmt.Println("This example simulates two replicas of the same service, each running")
	fmt.Println("its own Engine and its own PolicyBundleDistributor over its own")
	fmt.Println("PolicyStore. Replica A creates a policy and notifies its distributor.")
	fmt.Println("Without a shared BundleTransport, replica B would never see that")
	fmt.Println("change until it independently reloaded from a shared store. Here we")
	fmt.Println("wire both distributors to a Redis Pub/Sub BundleTransport")
	fmt.Println("(contrib/redistransport) so replica B receives and applies the signed")
	fmt.Println("bundle within one round-trip of it being published.")
	fmt.Println()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}

	fmt.Printf("Connecting to Redis at %s ...\n", addr)
	pingCtx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	client := redis.NewClient(&redis.Options{Addr: addr})
	err := client.Ping(pingCtx).Err()
	cancel()
	if err != nil {
		_ = client.Close()
		fmt.Printf("Could not reach Redis at %s: %v\n", addr, err)
		fmt.Println()
		fmt.Println("This example needs a local Redis instance to actually demonstrate")
		fmt.Println("pub/sub propagation. Start one with:")
		fmt.Println()
		fmt.Println("    docker run -p 6379:6379 redis")
		fmt.Println()
		fmt.Println("or set REDIS_ADDR to point at an existing instance.")
		fmt.Println()
		fmt.Println("What this example WOULD do with Redis available:")
		fmt.Println("  1. Start two PolicyBundleDistributor instances (\"replica A\" and")
		fmt.Println("     \"replica B\"), each with its own in-memory PolicyStore, both")
		fmt.Println("     wired to a redistransport.Transport pointed at the same Redis")
		fmt.Println("     Pub/Sub channel.")
		fmt.Println("  2. Create a policy directly against replica A's engine, which")
		fmt.Println("     automatically notifies its distributor; the distributor signs a")
		fmt.Println("     policy bundle and publishes it both to A's local subscribers and")
		fmt.Println("     to the Redis channel.")
		fmt.Println("  3. Show replica B - which never touched replica A's PolicyStore -")
		fmt.Println("     receiving that bundle over Redis and applying it via")
		fmt.Println("     Engine.ApplySignedBundle, so B's engine can now authorize against")
		fmt.Println("     the policy A created, with no shared database polling involved.")
		fmt.Println()
		fmt.Println("Exiting cleanly since this is a documentation example, not a test.")
		return
	}
	fmt.Println("Connected.")
	defer client.Close()

	// A second client for replica B: in a real deployment each replica has
	// its own Redis client, even though they may point at the same server.
	clientB := redis.NewClient(&redis.Options{Addr: addr})
	defer clientB.Close()

	const channel = "authz:policy-bundles:example"
	const tenantID = "tenant-acme"

	fmt.Println()
	fmt.Println("--- Setting up replica A ---")
	policyStoreA := stores.NewMemoryPolicyStore()
	roleStoreA := stores.NewMemoryRoleStore()
	aclStoreA := stores.NewMemoryACLStore()
	auditStoreA := stores.NewMemoryAuditStore()
	engineA := authz.NewEngine(policyStoreA, roleStoreA, aclStoreA, auditStoreA)

	transportA := redistransport.New(client, redistransport.WithChannel(channel))
	distA, err := authz.NewPolicyBundleDistributor(policyStoreA, authz.WithBundleTransport(transportA))
	if err != nil {
		fmt.Printf("failed to create distributor A: %v\n", err)
		os.Exit(1)
	}
	engineA.SetBundleDistributor(distA)
	fmt.Println("Replica A: engine + PolicyBundleDistributor + Redis transport ready.")

	fmt.Println()
	fmt.Println("--- Setting up replica B ---")
	policyStoreB := stores.NewMemoryPolicyStore()
	roleStoreB := stores.NewMemoryRoleStore()
	aclStoreB := stores.NewMemoryACLStore()
	auditStoreB := stores.NewMemoryAuditStore()
	engineB := authz.NewEngine(policyStoreB, roleStoreB, aclStoreB, auditStoreB)

	transportB := redistransport.New(clientB, redistransport.WithChannel(channel))
	distB, err := authz.NewPolicyBundleDistributor(policyStoreB, authz.WithBundleTransport(transportB))
	if err != nil {
		fmt.Printf("failed to create distributor B: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Replica B: separate engine, separate PolicyStore, separate Redis transport.")
	fmt.Println("Replica B has NOT seen any of replica A's policies yet.")

	// Replica B applies any bundle it receives over the transport to its own
	// engine, exactly like a real replica reacting to a remote policy change.
	received := make(chan *authz.SignedPolicyBundle, 1)
	distB.RegisterSubscriber(tenantID, authz.BundleSubscriberFunc(func(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
		fmt.Printf("Replica B: received bundle over Redis for tenant %q with %d polic(y/ies)\n", tenantID, len(bundle.Policies))
		if err := engineB.ApplySignedBundle(ctx, pub, bundle); err != nil {
			fmt.Printf("Replica B: failed to apply bundle: %v\n", err)
			return err
		}
		fmt.Println("Replica B: applied bundle to its own engine via ApplySignedBundle.")
		received <- bundle
		return nil
	}))

	ctx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	distA.Start(ctx)
	defer distA.Stop(context.Background())
	distB.Start(ctx)
	defer distB.Stop(context.Background())

	// Give the Redis subscriptions a moment to actually register before
	// publishing, mirroring the pattern used in redis_transport_test.go.
	time.Sleep(200 * time.Millisecond)

	fmt.Println()
	fmt.Println("--- Creating a policy on replica A ---")
	policy := &authz.Policy{
		ID:        "policy-read-docs",
		TenantID:  tenantID,
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
		Enabled:   true,
	}
	// engineA.SetBundleDistributor(distA) above means CreatePolicy already
	// calls distA.NotifyPolicyChange internally, so there is no separate
	// "notify" step to trigger by hand: creating the policy is enough to
	// sign a bundle and publish it over the Redis transport.
	if err := engineA.CreatePolicy(ctx, policy); err != nil {
		fmt.Printf("failed to create policy on replica A: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Replica A: created policy %q (allow read on document:*).\n", policy.ID)
	fmt.Println("Replica A: Engine.CreatePolicy automatically notified the distributor,")
	fmt.Println("which signs a bundle and publishes it over the Redis transport.")

	// Before propagation, replica B's engine has no such policy.
	subject := &authz.Subject{ID: "user-1", TenantID: tenantID}
	resource := &authz.Resource{ID: "doc-1", Type: "document", TenantID: tenantID}
	env := &authz.Environment{Time: time.Now(), TenantID: tenantID}

	if err := engineB.ReloadPolicies(ctx, tenantID); err != nil {
		fmt.Printf("replica B initial reload failed: %v\n", err)
	}
	before, _ := engineB.Authorize(ctx, subject, "read", resource, env)
	fmt.Printf("Replica B, before propagation: authorize read -> allowed=%v\n", before.Allowed)

	fmt.Println()
	fmt.Println("--- Waiting for the bundle to propagate to replica B over Redis ---")

	select {
	case <-received:
		fmt.Println()
		fmt.Println("--- Verifying replica B now has the policy, with no direct access")
		fmt.Println("    to replica A's PolicyStore ---")
		if err := engineB.ReloadPolicies(ctx, tenantID); err != nil {
			fmt.Printf("replica B reload after bundle failed: %v\n", err)
		}
		after, _ := engineB.Authorize(ctx, subject, "read", resource, env)
		fmt.Printf("Replica B, after propagation: authorize read -> allowed=%v\n", after.Allowed)
	case <-time.After(5 * time.Second):
		fmt.Println("Timed out waiting for the bundle to propagate over the Redis transport.")
	}

	fmt.Println()
	fmt.Println("--- Cleaning up ---")
	fmt.Println("Stopping distributors and closing Redis clients (deferred).")
	fmt.Println("Done.")
}
