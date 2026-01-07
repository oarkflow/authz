package authz

import (
	"fmt"
	"regexp"
	"strings"
)

// ParseCondition attempts to parse a limited subset of expressive condition strings
// into the native Expr AST used by the engine. This intentionally supports the
// commonly used patterns (owner equality, role membership, time between, basic
// comparisons and "in" membership) while keeping parsing simple and deterministic.
func ParseCondition(s string) (Expr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &TrueExpr{}, nil
	}

	// owner equality: resource.owner_id == subject.id
	ownerRe := regexp.MustCompile(`resource\.owner_id\s*==\s*subject\.id`)
	if ownerRe.MatchString(s) {
		return &EqExpr{Field: "resource.owner_id", Value: "subject.id"}, nil
	}

	// subject role membership e.g., subject.roles in ["admin","ops"]
	inRe := regexp.MustCompile(`subject\.roles?\s+in\s*\[([^\]]+)\]`)
	if m := inRe.FindStringSubmatch(s); len(m) == 2 {
		inner := m[1]
		parts := splitCSV(inner)
		vals := make([]any, 0, len(parts))
		for _, p := range parts {
			vals = append(vals, p)
		}
		return &InExpr{Field: "subject.roles", Values: vals}, nil
	}

	// time between e.g., env.time between 09:00-18:00 or env.time between "09:00" and "18:00"
	timeRe := regexp.MustCompile(`env\.time\s+between\s+\"?(\d{1,2}:\d{2})\"?\s*(?:-|–|and)\s*\"?(\d{1,2}:\d{2})\"?`)
	if m := timeRe.FindStringSubmatch(s); len(m) == 3 {
		return &TimeBetweenExpr{Start: m[1], End: m[2]}, nil
	}

	// >= comparisons (supports literal RHS or field ref)
	gteRe := regexp.MustCompile(`(?P<left>[a-zA-Z0-9_\.]+)\s*>=\s*(?P<right>[a-zA-Z0-9_\.\"']+)`)
	if gteRe.MatchString(s) {
		m := gteRe.FindStringSubmatch(s)
		if len(m) >= 3 {
			left := m[1]
			right := m[2]
			// strip quotes if present
			right = strings.Trim(right, "\"'")
			return &GteExpr{Field: left, Value: right}, nil
		}
	}

	// equality e.g., subject.id == "alice" or resource.owner_id == subject.id
	eqRe := regexp.MustCompile(`(?P<left>[a-zA-Z0-9_\.]+)\s*==\s*(?P<right>\"[^\"]+\"|[^\s]+)`)
	if eqRe.MatchString(s) {
		m := eqRe.FindStringSubmatch(s)
		if len(m) >= 3 {
			left := m[1]
			right := strings.Trim(m[2], "\"")
			// preserve field refs like subject.id
			if strings.Contains(right, "subject.") || strings.Contains(right, "resource.") || strings.Contains(right, "env.") {
				return &EqExpr{Field: left, Value: right}, nil
			}
			return &EqExpr{Field: left, Value: right}, nil
		}
	}

	// inequality e.g., subject.id != "alice"
	neRe := regexp.MustCompile(`(?P<left>[a-zA-Z0-9_\.]+)\s*!=\s*(?P<right>\"[^\"]+\"|[^\s]+)`)
	if neRe.MatchString(s) {
		m := neRe.FindStringSubmatch(s)
		if len(m) >= 3 {
			left := m[1]
			right := strings.Trim(m[2], "\"")
			return &NeExpr{Field: left, Value: right}, nil
		}
	}

	return nil, fmt.Errorf("unsupported condition syntax: %s", s)
}

// splitCSV splits items like "\"a\",\"b\"" or "a, b" into []string (trimmed, unquoted)
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"'")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
