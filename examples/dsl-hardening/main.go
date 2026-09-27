package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func main() {
	fmt.Println("=== AuthZ DSL Hardening Demo ===")

	strictComparisonExample()
	rejectAbsoluteIncludeExample()
	includeRootJailExample()
}

// strictComparisonExample shows the `>` / `<` comparison operators being parsed into
// GtExpr / LtExpr and evaluated for both a passing and a failing subject.
func strictComparisonExample() {
	fmt.Println("\n1. Strict '>' / '<' comparison operators")
	fmt.Println("-----------------------------------------")

	dsl := `
tenant acme "Acme Corp"

policy senior-only acme allow read document:* subject.attrs.level>3.0 priority:10
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Parsed policy condition: %q\n", "subject.attrs.level>3.0")
	fmt.Println("  (note: the comparison literal must match the attribute's numeric type --")
	fmt.Println("   e.g. use 3.0, not 3, when comparing against a float64 attribute value)")

	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(stores.NewMemoryRoleMembershipStore()),
	)

	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		log.Fatal(err)
	}

	senior := &authz.Subject{
		ID:       "user:alice",
		Type:     "user",
		TenantID: "acme",
		Attrs:    map[string]any{"level": 5.0},
	}
	junior := &authz.Subject{
		ID:       "user:bob",
		Type:     "user",
		TenantID: "acme",
		Attrs:    map[string]any{"level": 2.0},
	}
	doc := &authz.Resource{ID: "doc-1", Type: "document", TenantID: "acme"}
	env := &authz.Environment{TenantID: "acme"}

	decision, _ := engine.Authorize(ctx, senior, "read", doc, env)
	fmt.Printf("  Alice (level=5.0, level>3.0 passes): allowed=%v reason=%s\n", decision.Allowed, decision.Reason)

	decision, _ = engine.Authorize(ctx, junior, "read", doc, env)
	fmt.Printf("  Bob   (level=2.0, level>3.0 fails):  allowed=%v reason=%s\n", decision.Allowed, decision.Reason)

	// Direct condition evaluation, showing the parsed expression types.
	gtExpr, err := authz.ParseCondition("subject.attrs.level>3.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Parsed expression type: %T\n", gtExpr)

	ltExpr, err := authz.ParseCondition("subject.attrs.level<3.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Parsed expression type: %T\n", ltExpr)
}

// rejectAbsoluteIncludeExample shows that NewDSLParser() (strict mode) rejects an
// `include` directive pointing at an absolute path by default.
func rejectAbsoluteIncludeExample() {
	fmt.Println("\n2. Strict parser rejects absolute include paths")
	fmt.Println("-------------------------------------------------")

	dsl := `include "/etc/passwd"`

	_, err := authz.NewDSLParser().Parse([]byte(dsl))
	if err == nil {
		log.Fatal("expected strict parser to reject an absolute include path, but it did not")
	}
	fmt.Printf("  include \"/etc/passwd\" rejected as expected: %v\n", err)

	// AllowAbsoluteIncludes(true) opts back in, mirroring NewPermissiveDSLParser().
	permissive := authz.NewDSLParser().AllowAbsoluteIncludes(true)
	fmt.Printf("  NewPermissiveDSLParser() and AllowAbsoluteIncludes(true) both restore the\n")
	fmt.Printf("  old behavior -- but that only affects the absolute-path check, not SetIncludeRoot.\n")
	_ = permissive
}

// includeRootJailExample demonstrates SetIncludeRoot: an include that resolves inside
// the configured root succeeds, while one that escapes it (via "../" traversal) is
// rejected, matching TestIncludeRootRestrictsTraversal / TestIncludeRootAllowsWithinRoot.
func includeRootJailExample() {
	fmt.Println("\n3. SetIncludeRoot jails includes to a directory")
	fmt.Println("--------------------------------------------------")

	dir, err := os.MkdirTemp("", "authz-dsl-hardening-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	sandbox := filepath.Join(dir, "sandbox")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		log.Fatal(err)
	}

	// A file outside the sandbox root -- must not be reachable via include.
	outside := filepath.Join(dir, "outside.authz")
	if err := os.WriteFile(outside, []byte(`tenant leaked "Leaked"`), 0o644); err != nil {
		log.Fatal(err)
	}

	// A file inside the sandbox root -- must be reachable via include.
	inner := filepath.Join(sandbox, "inner.authz")
	if err := os.WriteFile(inner, []byte(`tenant inner "Inner"`), 0o644); err != nil {
		log.Fatal(err)
	}

	// Entry point that tries to escape the sandbox via "../".
	escaping := filepath.Join(sandbox, "escaping.authz")
	if err := os.WriteFile(escaping, []byte(`include "../outside.authz"`), 0o644); err != nil {
		log.Fatal(err)
	}

	// Entry point that stays inside the sandbox.
	safe := filepath.Join(sandbox, "safe.authz")
	if err := os.WriteFile(safe, []byte(`include "inner.authz"`), 0o644); err != nil {
		log.Fatal(err)
	}

	rootedParser := authz.NewPermissiveDSLParser().SetIncludeRoot(sandbox)
	if _, err := rootedParser.ParseFile(escaping); err == nil {
		log.Fatal("expected include escaping the configured root to be rejected, but it succeeded")
	} else {
		fmt.Printf("  include \"../outside.authz\" escaping root rejected as expected: %v\n", err)
	}

	rootedParser2 := authz.NewPermissiveDSLParser().SetIncludeRoot(sandbox)
	cfg, err := rootedParser2.ParseFile(safe)
	if err != nil {
		log.Fatalf("expected include within root to succeed, got error: %v", err)
	}
	fmt.Printf("  include \"inner.authz\" within root succeeded: %d tenant(s) merged (%s)\n",
		len(cfg.Tenants), cfg.Tenants[0].ID)

	// Absolute includes are still rejected even by the permissive parser once a root
	// is configured, since SetIncludeRoot applies independently of AllowAbsoluteIncludes.
	rootedParser3 := authz.NewPermissiveDSLParser().SetIncludeRoot(sandbox)
	if _, err := rootedParser3.Parse([]byte(`include "/etc/passwd"`)); err == nil {
		log.Fatal("expected /etc/passwd include outside the root to be rejected, but it succeeded")
	} else {
		fmt.Printf("  include \"/etc/passwd\" outside root rejected as expected: %v\n", err)
	}

	fmt.Println("\nTemporary files cleaned up.")
}
