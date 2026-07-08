package stores

import (
	"github.com/oarkflow/authz"
)

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
