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

type PolicyBundleDistributor struct {
	policyStore      PolicyStore
	pub              ed25519.PublicKey
	priv             ed25519.PrivateKey
	rotationInterval time.Duration
	notifyCh         chan string
	stopCh           chan struct{}
	subscribers      map[string][]BundleSubscriber
	mu               sync.RWMutex
	started          bool
	wg               sync.WaitGroup
}

type PolicyBundleDistributorOption func(*PolicyBundleDistributor)

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
	d.mu.Unlock()

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
	d.mu.Unlock()

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
