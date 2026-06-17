package granttype

import "strings"

// parseScopes splits comma/space-separated scopes (same rules as oauth2.ParseScopes) | 解析 scope
func parseScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	sep := func(r rune) bool { return r == ',' || r == ' ' }
	parts := strings.FieldsFunc(raw, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
