package gin

// Handler 接口定义了处理程序的基本方法
type Handler interface {
	GetHandler(action string) HandlerFunc
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
func (b *BasicHandler) GetHandler(action string) HandlerFunc {
	return b.Handlers[action]
}
