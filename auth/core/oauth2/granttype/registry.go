package granttype

import "sync"

// Registry thread-safe grant_type handler map | grant_type 注册表
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry creates an empty registry | 创建注册表
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Register registers a handler | 注册处理器
func (r *Registry) Register(h Handler) {
	if h == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[h.Type()] = h
}

// Get returns handler or nil | 查询处理器
func (r *Registry) Get(grantType string) Handler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.handlers[grantType]
}
