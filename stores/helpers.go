package stores

import (
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/date"
)

func parseFlexibleTime(s string) (time.Time, error) {
	return date.Parse(s)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sqlNullTimeOrNil(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func cloneACL(a *authz.ACL) *authz.ACL {
	if a == nil {
		return nil
	}
	dup := *a
	return &dup
}

func aclMatchesResource(pattern, resourceID string) bool {
	if pattern == resourceID || pattern == "*" {
		return true
	}
	for i, ch := range pattern {
		if ch == '*' {
			prefix := pattern[:i]
			return len(resourceID) >= len(prefix) && resourceID[:len(prefix)] == prefix
		}
	}
	return false
}

func filterACLsSnapshot(acls []*authz.ACL, resourceID string) []*authz.ACL {
	result := make([]*authz.ACL, 0)
	for _, acl := range acls {
		if acl == nil || acl.IsExpired() {
			continue
		}
		if aclMatchesResource(acl.ResourceID, resourceID) {
			result = append(result, cloneACL(acl))
		}
	}
	return result
}

func filterACLsBySubject(acls []*authz.ACL, subjectID string) []*authz.ACL {
	result := make([]*authz.ACL, 0)
	for _, acl := range acls {
		if acl == nil || acl.IsExpired() {
			continue
		}
		if acl.SubjectID == subjectID {
			result = append(result, cloneACL(acl))
		}
	}
	return result
}
