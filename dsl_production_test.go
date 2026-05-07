package authz_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/authz"
)

func TestDSLRichConditionGrammar(t *testing.T) {
	dsl := `tenant org "Org"
policy p org allow read document:* "(subject.roles@admin,ops || resource.owner_id=subject.id) && subject.attrs.level>=3 && regex(subject.id,^user:) && time_between(09:00,18:00) && cidr(10.0.0.0/8) && range(subject.attrs.score,1,10)"`
	cfg, err := authz.NewDSLParser().Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Policies[0].Condition.(*authz.AndExpr); !ok {
		t.Fatalf("expected top-level AND expression, got %T", cfg.Policies[0].Condition)
	}
}

func TestDSLIncludesAndCycleDetection(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "roles.authz"), []byte(`role admin org Admin *:*`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.authz"), []byte(`tenant org "Org"
include "roles.authz"`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := authz.NewDSLParser().ParseFile(filepath.Join(dir, "main.authz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Roles) != 1 {
		t.Fatalf("expected included role, got %d", len(cfg.Roles))
	}

	if err := os.WriteFile(filepath.Join(dir, "a.authz"), []byte(`include "b.authz"`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.authz"), []byte(`include "a.authz"`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := authz.NewDSLParser().ParseFile(filepath.Join(dir, "a.authz")); err == nil {
		t.Fatal("expected include cycle error")
	}
}

func TestDSLFirstClassIAMDirectives(t *testing.T) {
	dsl := `tenant org "Org"
user user:alice org alice@example.com "Alice" status:active
group eng org Engineering
scope docs.read org read:documents
service_account svc:bot org Bot client:bot-client roles:admin scopes:docs.read
invitation inv1 org bob@example.com admin groups:eng invited_by:user:alice expires:2030-01-01T00:00:00Z
api_key key1 org user:alice sk_test_ "Alice Key" scopes:docs.read expires:2030-01-01T00:00:00Z
boundary b1 org ReadOnly read document:*`
	cfg, err := authz.NewDSLParser().Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 1 || len(cfg.Groups) != 1 || len(cfg.Scopes) != 1 || len(cfg.ServiceAccounts) != 1 || len(cfg.Invitations) != 1 || len(cfg.APIKeys) != 1 || len(cfg.PermissionBoundaries) != 1 {
		t.Fatalf("IAM directives did not parse into config: %#v", cfg)
	}
	if cfg.Invitations[0].ExpiresAt.Before(time.Now()) {
		t.Fatal("invitation expiration was not parsed")
	}
	if err := authz.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSigning(t *testing.T) {
	pub, priv, err := authz.GenerateConfigSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("tenant org \"Org\"\n")
	sig, err := authz.SignConfig(data, priv)
	if err != nil {
		t.Fatal(err)
	}
	signed := authz.AppendConfigSignature(data, sig)
	if err := authz.VerifyConfigSignature(signed, pub); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte("tenant other \"Other\"\n"), signed[len(data):]...)
	if err := authz.VerifyConfigSignature(tampered, pub); err == nil {
		t.Fatal("expected tampered config verification failure")
	}
}
