package utils

import "strings"

// MatchResource checks if the given value ("METHOD URI" or just a resource/action string)
// matches the provided pattern. Patterns may include:
//   - Wildcard '*' which matches any sequence of characters (including none).
//   - Parameter prefix ':' (e.g., ':id') matching any segment until '/'.
//
// If the value contains an HTTP method (space as separator), both method and URI are matched.
func MatchResource(value, pattern string) bool {
	// Split out HTTP method if present
	valParts := strings.SplitN(value, " ", 2)
	patParts := strings.SplitN(pattern, " ", 2)

	// If pattern includes a method, require it
	if len(patParts) == 2 {
		if len(valParts) != 2 {
			return false
		}
		// Special case for wildcard
		if patParts[0] == "*" && patParts[1] == "*" {
			return true
		}
		if patParts[0] != "*" && valParts[0] != patParts[0] {
			return false
		}
		// Match URI part
		return matchPattern(valParts[1], patParts[1])
	}
	return matchPattern(value, pattern)
}

// matchPattern matches a plain value against a pattern containing
// '*' wildcards and ':' parameters. Parameters match until the next '/'.
// Enhanced to support hierarchical resources.
func matchPattern(value, pattern string) bool {
	vIndex, pIndex := 0, 0
	vLen, pLen := len(value), len(pattern)

	for pIndex < pLen {
		switch pattern[pIndex] {
		case '*':
			// '*' matches any sequence; if it's last, accept
			if pIndex == pLen-1 {
				return true
			}
			// Match until next '/' or end of value
			for vIndex < vLen && value[vIndex] != '/' {
				vIndex++
			}
			pIndex++
		case ':':
			// Skip pattern until end of param name
			pIndex++
			for pIndex < pLen && pattern[pIndex] != '/' {
				pIndex++
			}
			// Skip value until next '/'
			for vIndex < vLen && value[vIndex] != '/' {
				vIndex++
			}
		default:
			// Match literal char
			if vIndex < vLen && pattern[pIndex] == value[vIndex] {
				vIndex++
				pIndex++
			} else {
				return false
			}
		}
	}

	// Both fully consumed?
	// Add support for hierarchical wildcards
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "/*"))
	}
	return vIndex == vLen && pIndex == pLen
}
