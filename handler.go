package gin

// Handler 接口定义了处理程序的基本方法
type Handler interface {
	GetHandler(action string) (HandlerFunc, bool)
	SetHandler(action string, handlerFunc HandlerFunc)
	Clone() Handler
}

// BasicHandler 结构体用于存储处理函数
type BasicHandler struct {
	Handlers map[string]HandlerFunc
}

// SetHandler 方法用于设置处理函数
func (b *BasicHandler) SetHandler(action string, handlerFunc HandlerFunc) {
	if b.Handlers == nil {
		b.Handlers = make(map[string]HandlerFunc)
	}
	b.Handlers[action] = handlerFunc
}

// GetHandler 方法根据动作获取处理函数
// 返回处理函数和是否找到的布尔值
func (b *BasicHandler) GetHandler(action string) (HandlerFunc, bool) {
	handler, ok := b.Handlers[action]
	return handler, ok
}

// Clone 克隆当前处理器实例
func (b *BasicHandler) Clone() Handler {
	if b == nil {
		return NewBasicHandler()
	}

	clone := &BasicHandler{
		Handlers: make(map[string]HandlerFunc, len(b.Handlers)),
	}

	for action, handler := range b.Handlers {
		clone.Handlers[action] = handler
	}

	return clone
}

// NewBasicHandler 创建一个新的基本处理器
func NewBasicHandler() *BasicHandler {
	return &BasicHandler{
		Handlers: make(map[string]HandlerFunc),
	}
}

// HandlerWrapper 封装了 Handler 便于添加中间件
type HandlerWrapper struct {
	Handler     Handler                // 原始处理器
	Middlewares []HandlerFunc          // 中间件列表
	Cache       map[string]HandlerFunc // 中间件缓存
}

// NewHandlerWrapper 创建新的处理器包装器
func NewHandlerWrapper(handler Handler) *HandlerWrapper {
	return &HandlerWrapper{
		Handler:     handler,
		Middlewares: make([]HandlerFunc, 0),
		Cache:       make(map[string]HandlerFunc),
	}
}

// UseMiddleware 添加中间件
func (hw *HandlerWrapper) UseMiddleware(middlewares ...HandlerFunc) {
	hw.Middlewares = append(hw.Middlewares, middlewares...)
	// 清除缓存，因为中间件已更改
	hw.Cache = make(map[string]HandlerFunc)
}

// GetHandler 获取添加了中间件的处理函数
func (hw *HandlerWrapper) GetHandler(action string) (HandlerFunc, bool) {
	// 检查缓存
	if handler, ok := hw.Cache[action]; ok {
		return handler, true
	}

	// 从原始处理器获取处理函数
	handler, ok := hw.Handler.GetHandler(action)
	if !ok {
		return nil, false
	}

	// 如果没有中间件，直接返回原始处理函数
	if len(hw.Middlewares) == 0 {
		return handler, true
	}

	// 创建包含中间件的新处理函数
	wrappedHandler := func(c *Context) {
		// 创建中间件链
		next := handler

		// 从后向前包装，这样执行时会从前向后执行
		for i := len(hw.Middlewares) - 1; i >= 0; i-- {
			currentMiddleware := hw.Middlewares[i]
			nextHandler := next

			next = func(ctx *Context) {
				if !ctx.IsAborted() {
					currentMiddleware(ctx)
				}
				if !ctx.IsAborted() {
					nextHandler(ctx)
				}
			}
		}

		// 执行整个链条
		next(c)
	}

	// 缓存包装后的处理函数
	hw.Cache[action] = wrappedHandler
	return wrappedHandler, true
}

// SetHandler 设置处理函数
func (hw *HandlerWrapper) SetHandler(action string, handlerFunc HandlerFunc) {
	hw.Handler.SetHandler(action, handlerFunc)
	// 清除缓存
	delete(hw.Cache, action)
}

// Clone 克隆处理器包装器
func (hw *HandlerWrapper) Clone() Handler {
	clone := &HandlerWrapper{
		Handler:     hw.Handler.Clone(),
		Middlewares: make([]HandlerFunc, len(hw.Middlewares)),
		Cache:       make(map[string]HandlerFunc),
	}

	copy(clone.Middlewares, hw.Middlewares)
	return clone
}
