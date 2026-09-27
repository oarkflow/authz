// Package-level doc for PolicyBundleDistributor's cross-instance behavior.
//
// # Staleness window
//
// By default PolicyBundleDistributor only fans bundles out to in-process
// BundleSubscriber values registered via RegisterSubscriber. That is enough
// for a single engine instance, but in a horizontally-scaled deployment
// (multiple replicas of the process, each with its own Engine and its own
// decision/role/compiled-condition caches) a policy change made against one
// replica's PolicyBundleDistributor is never observed by the others: they
// keep serving decisions from their local caches until something external
// (a restart, a scheduled ReloadPolicies, or the rotationInterval ticker)
// causes them to reload from the shared PolicyStore. In practice this means
// the staleness window for other replicas is unbounded unless the caller
// wires up its own out-of-band reload/invalidation trigger.
//
// To bound that window, configure a BundleTransport with
// WithBundleTransport. When a transport is set, every bundle produced by
// distributeTenant (in response to NotifyPolicyChange) is, in addition to
// being handed to local subscribers, published on the transport. Every
// PolicyBundleDistributor instance that has called Start with that same
// transport subscribed will receive the bundle and redispatch it to its own
// local subscribers (the same BundleSubscriber values registered via
// RegisterSubscriber), which typically call Engine.ApplySignedBundle. That
// method reloads the policy store and calls Engine.InvalidateDecisionCache,
// so a remote replica picks up the change within one transport round-trip
// (sub-second for Redis Pub/Sub under normal conditions) instead of waiting
// for its next scheduled reload. This is still at-most-once, best-effort
// delivery (Redis Pub/Sub does not persist messages for offline
// subscribers), so a replica that is down when a bundle is published will
// remain stale until it reconnects and either receives a later bundle or
// reloads through some other path.
package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"sync"
	"time"
)

type BundleSubscriber interface {
	OnBundle(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error
}

type BundleSubscriberFunc func(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error

func (f BundleSubscriberFunc) OnBundle(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error {
	return f(ctx, tenantID, pub, bundle)
}

// BundleTransport lets a PolicyBundleDistributor broadcast signed bundles
// across process boundaries (e.g. to other replicas of the same service),
// in addition to its default in-process subscriber fan-out. Implementations
// are expected to be at-most-once and best-effort: a subscriber that is not
// currently connected may miss a published bundle.
type BundleTransport interface {
	// Publish broadcasts a signed bundle for tenantID to all remote
	// subscribers of this transport.
	Publish(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error
	// Subscribe starts delivering bundles received from other publishers on
	// this transport to handler, until ctx is done or the returned stop
	// function is called. Implementations must not invoke handler for
	// bundles published by this same process/origin.
	Subscribe(ctx context.Context, handler BundleSubscriber) (stop func() error, err error)
}

type PolicyBundleDistributor struct {
	policyStore      PolicyStore
	pub              ed25519.PublicKey
	priv             ed25519.PrivateKey
	rotationInterval time.Duration
	notifyCh         chan string
	stopCh           chan struct{}
	subscribers      map[string][]BundleSubscriber
	transport        BundleTransport
	transportStop    func() error
	mu               sync.RWMutex
	started          bool
	wg               sync.WaitGroup
}

type PolicyBundleDistributorOption func(*PolicyBundleDistributor)

// WithBundleTransport configures a BundleTransport used, in addition to the
// existing in-process subscriber mechanism, to broadcast signed bundles to
// other PolicyBundleDistributor instances (e.g. other replicas). See the
// package doc comment above for the resulting staleness/propagation
// characteristics. Passing nil is a no-op, so this option keeps the
// default in-process-only behavior unless a real transport is supplied.
func WithBundleTransport(t BundleTransport) PolicyBundleDistributorOption {
	return func(d *PolicyBundleDistributor) {
		if t != nil {
			d.transport = t
		}
	}
}

func WithBundleSigningKey(priv ed25519.PrivateKey) PolicyBundleDistributorOption {
	return func(d *PolicyBundleDistributor) {
		if priv != nil && len(priv) == ed25519.PrivateKeySize {
			d.priv = append(ed25519.PrivateKey{}, priv...)
			d.pub = priv.Public().(ed25519.PublicKey)
		}
	}
}

func WithBundleRotationInterval(interval time.Duration) PolicyBundleDistributorOption {
	return func(d *PolicyBundleDistributor) {
		if interval > 0 {
			d.rotationInterval = interval
		}
	}
}

func NewPolicyBundleDistributor(store PolicyStore, opts ...PolicyBundleDistributorOption) (*PolicyBundleDistributor, error) {
	if store == nil {
		return nil, fmt.Errorf("policy store is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	dist := &PolicyBundleDistributor{
		policyStore:      store,
		priv:             priv,
		pub:              pub,
		rotationInterval: 24 * time.Hour,
		notifyCh:         make(chan string, 1024),
		stopCh:           make(chan struct{}),
		subscribers:      make(map[string][]BundleSubscriber),
	}
	for _, opt := range opts {
		opt(dist)
	}
	return dist, nil
}

func (d *PolicyBundleDistributor) Start(ctx context.Context) {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return
	}
	d.started = true
	transport := d.transport
	d.mu.Unlock()

	if transport != nil {
		stop, err := transport.Subscribe(ctx, BundleSubscriberFunc(func(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error {
			for _, sub := range d.collectSubscribers(tenantID) {
				if err := sub.OnBundle(ctx, tenantID, pub, bundle); err != nil {
					log.Printf("bundle subscriber error for tenant %s (via transport): %v", tenantID, err)
				}
			}
			return nil
		}))
		if err != nil {
			log.Printf("bundle transport subscribe failed: %v", err)
		} else {
			d.mu.Lock()
			d.transportStop = stop
			d.mu.Unlock()
		}
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		ticker := time.NewTicker(d.rotationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCh:
				return
			case tenantID := <-d.notifyCh:
				if tenantID == "" {
					continue
				}
				if err := d.distributeTenant(ctx, tenantID); err != nil {
					log.Printf("bundle distribution failed for %s: %v", tenantID, err)
				}
			case <-ticker.C:
				if err := d.RotateSigningKey(); err != nil {
					log.Printf("bundle key rotation failed: %v", err)
				}
			}
		}
	}()
}

func (d *PolicyBundleDistributor) Stop(ctx context.Context) error {
	d.mu.Lock()
	if !d.started {
		d.mu.Unlock()
		return nil
	}
	d.started = false
	transportStop := d.transportStop
	d.transportStop = nil
	d.mu.Unlock()

	if transportStop != nil {
		if err := transportStop(); err != nil {
			log.Printf("bundle transport stop failed: %v", err)
		}
	}

	close(d.stopCh)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (d *PolicyBundleDistributor) NotifyPolicyChange(tenantID string) {
	if tenantID == "" {
		return
	}
	select {
	case d.notifyCh <- tenantID:
	default:
	}
}

func (d *PolicyBundleDistributor) RegisterSubscriber(tenantID string, sub BundleSubscriber) {
	if sub == nil {
		return
	}
	if tenantID == "" {
		tenantID = "*"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscribers[tenantID] = append(d.subscribers[tenantID], sub)
}

func (d *PolicyBundleDistributor) RotateSigningKey() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.priv = priv
	d.pub = pub
	d.mu.Unlock()
	return nil
}

func (d *PolicyBundleDistributor) CurrentPublicKey() ed25519.PublicKey {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append(ed25519.PublicKey(nil), d.pub...)
}

func (d *PolicyBundleDistributor) distributeTenant(ctx context.Context, tenantID string) error {
	policies, err := d.policyStore.ListPolicies(ctx, tenantID)
	if err != nil {
		return err
	}
	bundle, err := SignBundle(d.priv, policies)
	if err != nil {
		return err
	}
	if bundle.Meta == nil {
		bundle.Meta = map[string]any{}
	}
	bundle.Meta["tenant_id"] = tenantID
	bundle.Meta["generated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	bundle.Meta["signing_key"] = base64.StdEncoding.EncodeToString(d.pub)

	subs := d.collectSubscribers(tenantID)
	for _, sub := range subs {
		if err := sub.OnBundle(ctx, tenantID, d.CurrentPublicKey(), bundle); err != nil {
			log.Printf("bundle subscriber error for tenant %s: %v", tenantID, err)
		}
	}

	d.mu.RLock()
	transport := d.transport
	d.mu.RUnlock()
	if transport != nil {
		if err := transport.Publish(ctx, tenantID, d.CurrentPublicKey(), bundle); err != nil {
			log.Printf("bundle transport publish failed for tenant %s: %v", tenantID, err)
		}
	}
	return nil
}

func (d *PolicyBundleDistributor) collectSubscribers(tenantID string) []BundleSubscriber {
	d.mu.RLock()
	defer d.mu.RUnlock()
	subs := make([]BundleSubscriber, 0, len(d.subscribers[tenantID])+len(d.subscribers["*"]))
	subs = append(subs, d.subscribers[tenantID]...)
	subs = append(subs, d.subscribers["*"]...)
	return subs
}
