// Command admin-api-hardening demonstrates the security hardening built into
// authz's admin HTTP API:
//
//  1. Fail-closed authentication: NewAdminHTTPServer refuses to start unless
//     you either configure an auth function (WithAdminAuth) or explicitly
//     acknowledge that you want no authentication (WithAdminAuthDisabled).
//  2. A conservative default rate limiter that is applied automatically even
//     when the caller never touches WithAdminRateLimiter, so the control
//     plane always has baseline DoS protection.
//
// See the "Admin HTTP API" section of the repository README for background.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func newEngine() *authz.Engine {
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	return authz.NewEngine(policyStore, roleStore, aclStore, auditStore)
}

func main() {
	fmt.Println("=== 1. Fail-closed authentication: no options at all ===")
	fmt.Println("Calling authz.NewAdminHTTPServer(engine) with zero options...")

	engine := newEngine()
	server, err := authz.NewAdminHTTPServer(engine)
	if server != nil {
		panic("expected a nil server when no auth is configured")
	}
	if err == nil {
		panic("expected NewAdminHTTPServer to fail when no auth is configured")
	}
	fmt.Printf("Got expected error: %v\n", err)
	fmt.Printf("errors.Is(err, authz.ErrAdminAuthNotConfigured) => %v\n", err == authz.ErrAdminAuthNotConfigured)
	fmt.Println("The admin control plane refuses to start unauthenticated by default.")
	fmt.Println()

	fmt.Println("=== 2. Opting in with WithAdminAuth ===")
	const sharedSecret = "supersecret"
	authFn := func(r *http.Request) error {
		if r.Header.Get("Authorization") != "Bearer "+sharedSecret {
			return fmt.Errorf("missing or invalid Authorization header")
		}
		return nil
	}
	authedEngine := newEngine()
	authedServer, err := authz.NewAdminHTTPServer(authedEngine, authz.WithAdminAuth(authFn))
	if err != nil {
		panic(fmt.Sprintf("expected authenticated server to construct successfully, got: %v", err))
	}
	fmt.Println("Server constructed successfully with WithAdminAuth(...).")
	fmt.Println("Every admin request now needs 'Authorization: Bearer supersecret'.")
	_ = authedServer
	fmt.Println()

	fmt.Println("=== 3. Explicit opt-out with WithAdminAuthDisabled ===")
	devEngine := newEngine()
	devServer, err := authz.NewAdminHTTPServer(devEngine, authz.WithAdminAuthDisabled())
	if err != nil {
		panic(fmt.Sprintf("expected dev server to construct successfully, got: %v", err))
	}
	fmt.Println("Server constructed successfully with WithAdminAuthDisabled().")
	fmt.Println("This is the explicit \"I know what I'm doing\" escape hatch for local dev,")
	fmt.Println("tests, or setups where auth is enforced upstream (e.g. a reverse proxy).")
	fmt.Println("It is never the default - NewAdminHTTPServer only skips auth when you ask it to,")
	fmt.Println("and it logs a [WARN] on every startup as a standing reminder.")
	_ = devServer
	fmt.Println()

	fmt.Println("=== 4. Automatic default rate limiter (no WithAdminRateLimiter used) ===")
	demoEngine := newEngine()
	// Deliberately do NOT call WithAdminRateLimiter - the server should still
	// apply DefaultRateLimiterConfig() (10 req/s, burst 20 per client) on its own.
	unlimitedOptsServer, err := authz.NewAdminHTTPServer(demoEngine, authz.WithAdminAuthDisabled())
	if err != nil {
		panic(fmt.Sprintf("failed to construct demo server: %v", err))
	}

	ts := httptest.NewServer(unlimitedOptsServer)
	defer ts.Close()

	fmt.Printf("Started test server at %s (admin server built WITHOUT WithAdminRateLimiter).\n", ts.URL)
	fmt.Println("Firing 30 rapid GET /healthz requests from a single client...")

	total := 30
	ok200, blocked429, other := 0, 0, 0
	client := ts.Client()
	for i := 0; i < total; i++ {
		resp, err := client.Get(ts.URL + "/healthz")
		if err != nil {
			other++
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			ok200++
		case http.StatusTooManyRequests:
			blocked429++
		default:
			other++
		}
		resp.Body.Close()
	}
	fmt.Printf("Results: %d requests -> %d OK, %d rate-limited (429), %d other\n", total, ok200, blocked429, other)
	if blocked429 > 0 {
		fmt.Println("A rate limiter kicked in even though none was explicitly configured -")
		fmt.Println("this is authz.DefaultRateLimiterConfig() being applied automatically.")
	} else {
		fmt.Println("No 429s observed in this run (burst allowance absorbed all requests);")
		fmt.Println("a default limiter is still installed and will trip under sustained load.")
	}
	fmt.Println()

	fmt.Println("=== 5. Overriding the default with a custom, tighter rate limit ===")
	tightEngine := newEngine()
	tightServer, err := authz.NewAdminHTTPServer(tightEngine,
		authz.WithAdminAuthDisabled(),
		authz.WithAdminRateLimiter(&authz.RateLimiterConfig{
			RequestsPerSecond: 1,
			Burst:             2,
			KeyFunc: func(r *http.Request) string {
				return "fixed-key" // treat every caller as the same client for this demo
			},
			OnLimit: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"custom tight rate limit exceeded"}`))
			},
		}),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to construct tight-rate-limit server: %v", err))
	}

	tightTS := httptest.NewServer(tightServer)
	defer tightTS.Close()

	fmt.Printf("Started a second test server at %s with WithAdminRateLimiter(1 req/s, burst 2).\n", tightTS.URL)
	fmt.Println("Firing 5 rapid GET /healthz requests...")

	tightOK, tightBlocked := 0, 0
	tightClient := tightTS.Client()
	for i := 0; i < 5; i++ {
		resp, err := tightClient.Get(tightTS.URL + "/healthz")
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			tightOK++
		} else if resp.StatusCode == http.StatusTooManyRequests {
			tightBlocked++
		}
		resp.Body.Close()
	}
	fmt.Printf("With the tighter custom limit: %d OK, %d rate-limited (429)\n", tightOK, tightBlocked)
	fmt.Println("WithAdminRateLimiter fully overrides the automatic default when you supply one.")
	fmt.Println()

	// Clean shutdown of the servers we constructed but did not wrap in httptest
	// (httptest.Server.Close already shuts down the two we used above).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = authedServer.Shutdown(shutdownCtx)
	_ = devServer.Shutdown(shutdownCtx)

	fmt.Println("Done. All servers shut down cleanly.")
}
