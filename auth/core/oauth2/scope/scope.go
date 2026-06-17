package scope

// Handler optional scope processing hook | scope 处理钩子
type Handler interface {
	Name() string
	// AfterIssue runs after access_token is issued | 颁发 access_token 后回调
	AfterIssue(loginID, clientID string, scopes []string) error
}

// NoopHandler default no-op implementation | 默认空实现
type NoopHandler struct {
	N string
}

// Name returns handler name | 名称
func (h NoopHandler) Name() string { return h.N }

// AfterIssue no-op | 空实现
func (h NoopHandler) AfterIssue(loginID, clientID string, scopes []string) error {
	_ = loginID
	_ = clientID
	_ = scopes
	return nil
}
