package gin

import (
	"sync"
)

// Handler 接口定义了处理程序的基本方法
type Handler interface {
	// GetHandler 根据动作获取处理函数
	GetHandler(action string) (HandlerFunc, bool)

	// SetHandler 设置处理函数
	SetHandler(action string, handlerFunc HandlerFunc)

	// Clone 克隆当前处理器实例
	Clone() Handler

	// Handlers 获取所有处理函数映射
	Handlers() map[string]HandlerFunc
}

// BasicHandler 结构体用于存储处理函数
type BasicHandler struct {
	mutex    sync.RWMutex
	handlers map[string]HandlerFunc
}

// SetHandler 方法用于设置处理函数
func (b *BasicHandler) SetHandler(action string, handlerFunc HandlerFunc) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.handlers == nil {
		b.handlers = make(map[string]HandlerFunc)
	}
	b.handlers[action] = handlerFunc
}

// GetHandler 方法根据动作获取处理函数
// 返回处理函数和是否找到的布尔值
func (b *BasicHandler) GetHandler(action string) (HandlerFunc, bool) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	handler, ok := b.handlers[action]
	return handler, ok
}

// Clone 克隆当前处理器实例
func (b *BasicHandler) Clone() Handler {
	if b == nil {
		return NewBasicHandler()
	}
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	clone := &BasicHandler{
		handlers: make(map[string]HandlerFunc, len(b.handlers)),
	}

	for action, handler := range b.handlers {
		clone.handlers[action] = handler
	}

	return clone
}

// Handlers 获取所有处理函数映射
func (b *BasicHandler) Handlers() map[string]HandlerFunc {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	result := make(map[string]HandlerFunc, len(b.handlers))
	for k, v := range b.handlers {
		result[k] = v
	}
	return result
}

// NewBasicHandler 创建一个新的基本处理器
func NewBasicHandler() *BasicHandler {
	return &BasicHandler{
		handlers: make(map[string]HandlerFunc),
	}
}

// RouteHandler 基于路由的处理器
type RouteHandler struct {
	BasicHandler
	prefix string // 路由前缀
}

// NewRouteHandler 创建新的路由处理器
func NewRouteHandler(prefix string) *RouteHandler {
	return &RouteHandler{
		BasicHandler: BasicHandler{
			handlers: make(map[string]HandlerFunc),
		},
		prefix: prefix,
	}
}

// GetRouteHandler 获取路由处理函数
func (r *RouteHandler) GetRouteHandler(method, path string) (HandlerFunc, bool) {
	return r.GetHandler(method + ":" + path)
}

// SetRouteHandler 设置路由处理函数
func (r *RouteHandler) SetRouteHandler(method, path string, handlerFunc HandlerFunc) {
	r.SetHandler(method+":"+path, handlerFunc)
}

// Route 创建路由处理映射
func Route(method, path string, handler HandlerFunc) (string, HandlerFunc) {
	return method + ":" + path, handler
}
