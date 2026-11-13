package authz_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

// slowAudit is an audit store whose writes take time, so a test can tell whether
// Close really waits for them.
type slowAudit struct {
	delay   time.Duration
	written atomic.Int64
	closed  atomic.Bool // set by the test once it has "closed the database"
	late    atomic.Int64
}

func (s *slowAudit) LogDecision(_ context.Context, _ *authz.AuditEntry) error {
	time.Sleep(s.delay)
	if s.closed.Load() {
		s.late.Add(1) // written after the owner closed the store
	}
	s.written.Add(1)
	return nil
}

func (s *slowAudit) GetAccessLog(context.Context, authz.AuditFilter) ([]*authz.AuditEntry, error) {
	return nil, nil
}

func engineWith(t *testing.T, audit authz.AuditStore) *authz.Engine {
	t.Helper()
	e := authz.NewEngine(stores.NewMemoryPolicyStore(), stores.NewMemoryRoleStore(), stores.NewMemoryACLStore(), audit)
	p := &authz.Policy{ID: "allow-read", TenantID: "tenant-1", Effect: authz.EffectAllow, Actions: []authz.Action{"document.read"},
		Resources: []string{"document:*"}, Condition: &authz.TrueExpr{}, Priority: 1}
	if err := e.CreatePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadPolicies(context.Background(), "tenant-1"); err != nil {
		t.Fatal(err)
	}
	return e
}

func decide(e *authz.Engine, id string) (bool, error) {
	d, err := e.Authorize(context.Background(),
		&authz.Subject{ID: "u-" + id, TenantID: "tenant-1"}, "document.read",
		&authz.Resource{ID: id, Type: "document", TenantID: "tenant-1"},
		&authz.Environment{Time: time.Now(), TenantID: "tenant-1"})
	if err != nil {
		return false, err
	}
	return d.Allowed, nil
}

// Everything queued before Close is in the store when Close returns, with no
// need to wait: a caller can close its database right after.
func TestCloseFlushesQueuedAuditEntries(t *testing.T) {
	store := stores.NewMemoryAuditStore()
	e := engineWith(t, store)
	const n = 300
	for i := 0; i < n; i++ {
		if _, err := decide(e, string(rune('a'+i%26))+time.Duration(i).String()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAccessLog(context.Background(), authz.AuditFilter{TenantID: "tenant-1", Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("audit entries after Close = %d, want %d", len(got), n)
	}
}

// Close waits for the worker: nothing is written to the store after it returns.
func TestCloseWaitsForSlowStoreAndNothingIsWrittenAfter(t *testing.T) {
	store := &slowAudit{delay: 5 * time.Millisecond}
	e := engineWith(t, store)
	for i := 0; i < 20; i++ {
		if _, err := decide(e, time.Duration(i).String()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	store.closed.Store(true) // the caller now closes its database
	wrote := store.written.Load()
	if wrote != 20 {
		t.Fatalf("Close returned with %d of 20 entries written", wrote)
	}
	time.Sleep(100 * time.Millisecond)
	if store.late.Load() != 0 || store.written.Load() != wrote {
		t.Fatalf("the audit worker wrote %d entries after Close returned", store.late.Load())
	}
}

func TestCloseIsIdempotentAndConcurrencySafe(t *testing.T) {
	e := engineWith(t, stores.NewMemoryAuditStore())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// A closed engine still answers; it just stops logging (and must not panic).
func TestDecisionsAfterCloseAreAnsweredButNotLogged(t *testing.T) {
	store := stores.NewMemoryAuditStore()
	e := engineWith(t, store)
	if ok, err := decide(e, "before"); err != nil || !ok {
		t.Fatalf("before close: %v %v", ok, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		ok, err := decide(e, "after"+time.Duration(i).String())
		if err != nil || !ok {
			t.Fatalf("decision after Close: %v %v", ok, err)
		}
	}
	got, _ := store.GetAccessLog(context.Background(), authz.AuditFilter{TenantID: "tenant-1", Limit: 1000})
	if len(got) != 1 {
		t.Fatalf("entries = %d, want only the one made before Close", len(got))
	}
}

// Deciding while another goroutine closes the engine must never panic
// (a send on a closed channel would). Run with -race.
func TestCloseWhileDecidingDoesNotPanic(t *testing.T) {
	for round := 0; round < 20; round++ {
		e := engineWith(t, stores.NewMemoryAuditStore())
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
						_, _ = decide(e, time.Duration(g*100000+i).String())
					}
				}
			}(g)
		}
		time.Sleep(2 * time.Millisecond)
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		close(stop)
		wg.Wait()
	}
}
