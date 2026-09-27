package authz_test

import (
	"os"
	"testing"

	"github.com/oarkflow/authz"
)

// FuzzParse feeds arbitrary bytes into the DSL parser, exercising both the zero-copy
// and copying tokenization paths. dsl.go leans on unsafe for zero-copy string views over
// the input buffer, so a malformed or adversarial document could in principle read out of
// bounds or panic; a parse error is an acceptable outcome, a panic is not.
func FuzzParse(f *testing.F) {
	seeds := []string{
		`tenant org1 "Organization 1"`,
		`
tenant org1 "Organization 1"
tenant team1 "Team 1" parent:"org1:dept1"

policy p1 org1 allow read document:* subject.type=user priority:10
policy p2 org1 deny delete document:* subject.roles@guest priority:20

role admin org1 Admin *:*
role viewer org1 Viewer read:*

acl acl1 document:123 user:alice read,write allow

member user:alice admin
member user:bob viewer

engine cache_ttl=5000 batch_size=100
`,
		`policy p1 org1 allow read document:* subject.attrs.age>18.0`,
		`policy p1 org1 allow read document:* subject.attrs.age<18.0`,
		`policy p1 org1 allow read document:* subject.attrs.age>=18`,
		`policy p1 org1 allow read document:* (subject.type==user && subject.attrs.age>18) || subject.roles@admin`,
		`policy p1 org1 allow read document:* regex(subject.id,^user:.*$)`,
		`policy p1 org1 allow read document:* cidr(10.0.0.0/8)`,
		`policy p1 org1 allow read document:* time_between(09:00,17:00)`,
		`policy p1 org1 allow read document:* range(subject.attrs.score,0,100)`,
		`include "nested.authz"`,
		`include "/etc/passwd"`,
		`include "../../outside.authz"`,
		"tenant org1 {\n  name \"Engineering Org\"\n  parent root\n}",
	}
	if data, err := os.ReadFile("examples/config.authz"); err == nil {
		seeds = append(seeds, string(data))
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("zero-copy parse panicked on %q: %v", data, r)
			}
		}()
		_, _ = authz.NewDSLParser().Parse(data)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("non-zero-copy parse panicked on %q: %v", data, r)
				}
			}()
			_, _ = authz.NewDSLParser().SetZeroCopy(false).Parse(data)
		}()
	})
}
