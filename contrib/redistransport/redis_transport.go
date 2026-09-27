// Package redistransport implements authz.BundleTransport on top of Redis
// Pub/Sub, so that a PolicyBundleDistributor can broadcast signed policy
// bundles to other replicas of the same service in near-real-time instead
// of relying solely on each replica's own scheduled reloads.
//
// It reuses github.com/redis/go-redis/v9, the same Redis client already
// used by contrib/stores.RedisRoleMembershipStore, so a deployment that
// already depends on go-redis for role membership does not pick up a
// second client implementation.
package redistransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/oarkflow/authz"
)

// DefaultChannel is the Redis Pub/Sub channel used when no channel is
// supplied to New.
const DefaultChannel = "authz:policy-bundles"

// envelope is the wire format published on the Redis channel. It carries
// enough information to reconstruct the OnBundle call on the receiving
// side, plus an originID so a Transport never re-delivers its own
// publications back to its local subscribers.
//
// authz.Policy.Condition is the Expr interface, which does not round-trip
// through encoding/json on its own (json.Unmarshal has no way to know which
// concrete Expr type to allocate). Rather than duplicating authz's
// expression AST here, wirePolicy stores the condition using
// authz.FormatCondition/authz.ParseCondition, the same DSL text form authz
// already uses to serialize conditions (see dsl.go), which is already
// exported and covers every Expr variant the engine supports.
type envelope struct {
	OriginID   string            `json:"origin_id"`
	TenantID   string            `json:"tenant_id"`
	PublicKey  string            `json:"public_key"`
	Signatures map[string]string `json:"signatures"`
	Meta       map[string]any    `json:"meta,omitempty"`
	Policies   []wirePolicy      `json:"policies"`
}

type wirePolicy struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Effect    string    `json:"effect"`
	Actions   []string  `json:"actions"`
	Resources []string  `json:"resources"`
	Condition string    `json:"condition"`
	Priority  int       `json:"priority"`
	Version   int       `json:"version"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toWirePolicy(p *authz.Policy) wirePolicy {
	actions := make([]string, len(p.Actions))
	for i, a := range p.Actions {
		actions[i] = string(a)
	}
	return wirePolicy{
		ID:        p.ID,
		TenantID:  p.TenantID,
		Effect:    string(p.Effect),
		Actions:   actions,
		Resources: append([]string(nil), p.Resources...),
		Condition: authz.FormatCondition(p.Condition),
		Priority:  p.Priority,
		Version:   p.Version,
		Enabled:   p.Enabled,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func (w wirePolicy) toPolicy() (*authz.Policy, error) {
	cond, err := authz.ParseCondition(w.Condition)
	if err != nil {
		return nil, fmt.Errorf("parse condition for policy %s: %w", w.ID, err)
	}
	actions := make([]authz.Action, len(w.Actions))
	for i, a := range w.Actions {
		actions[i] = authz.Action(a)
	}
	return &authz.Policy{
		ID:        w.ID,
		TenantID:  w.TenantID,
		Effect:    authz.Effect(w.Effect),
		Actions:   actions,
		Resources: w.Resources,
		Condition: cond,
		Priority:  w.Priority,
		Version:   w.Version,
		Enabled:   w.Enabled,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}, nil
}

func toEnvelope(originID, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) envelope {
	policies := make([]wirePolicy, len(bundle.Policies))
	for i, p := range bundle.Policies {
		policies[i] = toWirePolicy(p)
	}
	return envelope{
		OriginID:   originID,
		TenantID:   tenantID,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		Signatures: bundle.Signatures,
		Meta:       bundle.Meta,
		Policies:   policies,
	}
}

func (env envelope) toBundle() (*authz.SignedPolicyBundle, error) {
	policies := make([]*authz.Policy, len(env.Policies))
	for i, wp := range env.Policies {
		p, err := wp.toPolicy()
		if err != nil {
			return nil, err
		}
		policies[i] = p
	}
	return &authz.SignedPolicyBundle{
		Policies:   policies,
		Signatures: env.Signatures,
		Meta:       env.Meta,
	}, nil
}

// Transport is a Redis Pub/Sub backed authz.BundleTransport.
type Transport struct {
	client   *redis.Client
	channel  string
	originID string
}

// Option configures a Transport.
type Option func(*Transport)

// WithChannel overrides the Redis Pub/Sub channel used for bundle
// propagation. Useful when multiple unrelated services share a Redis
// instance and need distinct channels.
func WithChannel(channel string) Option {
	return func(t *Transport) {
		if channel != "" {
			t.channel = channel
		}
	}
}

// New creates a Redis Pub/Sub BundleTransport using client. The caller owns
// the *redis.Client's lifecycle (creation and Close).
func New(client *redis.Client, opts ...Option) *Transport {
	t := &Transport{
		client:   client,
		channel:  DefaultChannel,
		originID: newOriginID(),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func newOriginID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to a fixed value rather than
		// panicking. Worst case a single instance may filter out its own
		// messages incorrectly, which only affects a redundant local
		// re-delivery, not correctness of remote propagation.
		return "redistransport-fallback"
	}
	return hex.EncodeToString(b)
}

// Publish implements authz.BundleTransport.
func (t *Transport) Publish(ctx context.Context, tenantID string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
	env := toEnvelope(t.originID, tenantID, pub, bundle)
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("redistransport: marshal envelope: %w", err)
	}
	return t.client.Publish(ctx, t.channel, data).Err()
}

// Subscribe implements authz.BundleTransport. It starts a goroutine reading
// from the Redis Pub/Sub channel until ctx is done or the returned stop
// function is called; either path closes the underlying redis.PubSub.
func (t *Transport) Subscribe(ctx context.Context, handler authz.BundleSubscriber) (func() error, error) {
	pubsub := t.client.Subscribe(ctx, t.channel)
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		return nil, fmt.Errorf("redistransport: subscribe: %w", err)
	}

	ch := pubsub.Channel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				t.handleMessage(ctx, msg, handler)
			}
		}
	}()

	stop := func() error {
		err := pubsub.Close()
		<-done
		return err
	}
	return stop, nil
}

func (t *Transport) handleMessage(ctx context.Context, msg *redis.Message, handler authz.BundleSubscriber) {
	var env envelope
	if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
		return
	}
	if env.OriginID == t.originID {
		// Skip our own publications: the local PolicyBundleDistributor
		// already delivered this bundle to its in-process subscribers
		// before publishing to the transport.
		return
	}
	pub, err := base64.StdEncoding.DecodeString(env.PublicKey)
	if err != nil {
		return
	}
	bundle, err := env.toBundle()
	if err != nil {
		return
	}
	_ = handler.OnBundle(ctx, env.TenantID, ed25519.PublicKey(pub), bundle)
}
