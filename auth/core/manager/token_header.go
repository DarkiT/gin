package manager

import "strings"

// GetTokenName returns configured token header/cookie name | 返回配置的 Token 名称
func (m *Manager) GetTokenName() string {
	if m.config != nil && m.config.TokenName != "" {
		return m.config.TokenName
	}
	return "satoken"
}

// CutTokenPrefix strips configured prefix (e.g. "Bearer ") | 去掉 Token 前缀
func (m *Manager) CutTokenPrefix(raw string) string {
	if m.config == nil || m.config.TokenPrefix == "" {
		return raw
	}
	if strings.HasPrefix(raw, m.config.TokenPrefix) {
		return strings.TrimSpace(raw[len(m.config.TokenPrefix):])
	}
	return raw
}
