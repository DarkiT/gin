package middleware

import (
	"sort"
	"sync"
	"time"

	"github.com/darkit/gin"
)

// Middleware 描述可注册的中间件元信息。
type Middleware struct {
	Name        string
	Description string
	Factory     func() gin.HandlerFunc
	Order       int
	Enabled     bool
}

// Registry 管理中间件注册与启用状态。
type Registry struct {
	mu          sync.RWMutex
	middlewares map[string]*Middleware
}

// NewRegistry 创建并初始化中间件注册表。
func NewRegistry() *Registry {
	r := &Registry{
		middlewares: make(map[string]*Middleware),
	}
	r.registerBuiltin()
	return r
}

// Register 注册中间件定义到注册表。
func (r *Registry) Register(m *Middleware) {
	if m == nil || m.Name == "" {
		return
	}
	clone := *m
	r.mu.Lock()
	r.middlewares[m.Name] = &clone
	r.mu.Unlock()
}

// Get 获取启用的中间件处理器。
func (r *Registry) Get(name string) (gin.HandlerFunc, bool) {
	r.mu.RLock()
	m, ok := r.middlewares[name]
	if !ok || !m.Enabled {
		r.mu.RUnlock()
		return nil, false
	}
	factory := m.Factory
	r.mu.RUnlock()
	if factory == nil {
		return nil, false
	}
	return factory(), true
}

// Enable 启用指定名称的中间件。
func (r *Registry) Enable(names ...string) {
	r.mu.Lock()
	for _, name := range names {
		if m, ok := r.middlewares[name]; ok {
			m.Enabled = true
		}
	}
	r.mu.Unlock()
}

// Disable 禁用指定名称的中间件。
func (r *Registry) Disable(names ...string) {
	r.mu.Lock()
	for _, name := range names {
		if m, ok := r.middlewares[name]; ok {
			m.Enabled = false
		}
	}
	r.mu.Unlock()
}

// GetChain 按顺序返回所有已启用的中间件处理器。
func (r *Registry) GetChain() []gin.HandlerFunc {
	r.mu.RLock()
	enabled := make([]*Middleware, 0, len(r.middlewares))
	for _, m := range r.middlewares {
		if m.Enabled {
			clone := *m
			enabled = append(enabled, &clone)
		}
	}
	r.mu.RUnlock()

	sort.Slice(enabled, func(i, j int) bool {
		return enabled[i].Order < enabled[j].Order
	})

	chain := make([]gin.HandlerFunc, 0, len(enabled))
	for _, m := range enabled {
		if m.Factory == nil {
			continue
		}
		chain = append(chain, m.Factory())
	}
	return chain
}

func (r *Registry) registerBuiltin() {
	r.Register(&Middleware{Name: "recovery", Factory: Recovery, Order: 0, Enabled: true})
	r.Register(&Middleware{Name: "request_id", Factory: RequestID, Order: 10, Enabled: true})
	r.Register(&Middleware{Name: "logger", Factory: Logger, Order: 20, Enabled: true})
	r.Register(&Middleware{Name: "cors", Factory: func() gin.HandlerFunc { return CORS() }, Order: 30, Enabled: false})
	r.Register(&Middleware{Name: "ratelimit", Factory: func() gin.HandlerFunc { return RateLimit() }, Order: 40, Enabled: false})
	r.Register(&Middleware{Name: "timeout", Factory: func() gin.HandlerFunc { return Timeout(30 * time.Second) }, Order: 50, Enabled: false})
	r.Register(&Middleware{Name: "secure", Factory: Secure, Order: 60, Enabled: false})
	r.Register(&Middleware{Name: "circuit_breaker", Factory: func() gin.HandlerFunc { return CircuitBreaker() }, Order: 70, Enabled: false})
}
