package oauth2

import (
	"net/url"
	"slices"
	"strings"
)

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func matchAllowURL(allowList []string, target string) bool {
	for _, p := range allowList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if before, ok := strings.CutSuffix(p, "*"); ok {
			prefix := before
			if strings.HasPrefix(target, prefix) {
				return true
			}
			continue
		}
		if p == target {
			return true
		}
	}
	return false
}

func containsStr(list []string, v string) bool {
	return slices.Contains(list, v)
}

func intersectStr(a, b []string) bool {
	for _, x := range a {
		if containsStr(b, x) {
			return true
		}
	}
	return false
}

func subtractStr(a, remove []string) []string {
	out := make([]string, 0, len(a))
rm:
	for _, x := range a {
		for _, r := range remove {
			if x == r {
				continue rm
			}
		}
		out = append(out, x)
	}
	return out
}
