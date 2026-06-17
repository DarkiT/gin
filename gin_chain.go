package gin

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/gin-gonic/gin"
)

var (
	// 偏移在初始化时连同字段类型一并校验：gin 升级若改动 gin.Context 的字段类型，
	// 启动即 panic 暴露问题，避免 unsafe 写入按错误类型静默破坏内存。
	ginContextHandlersOffset = mustGinContextFieldOffset("handlers", reflect.TypeFor[gin.HandlersChain]())
	ginContextIndexOffset    = mustGinContextFieldOffset("index", reflect.TypeFor[int8]())
	ginContextFullPathOffset = mustGinContextFieldOffset("fullPath", reflect.TypeFor[string]())
)

// mustGinContextFieldOffset 返回 gin.Context 指定字段的偏移，并断言其类型与 want 一致。
// 字段不存在或类型不符时 panic（fail-fast），用于保护后续 unsafe 指针写入的内存安全。
func mustGinContextFieldOffset(name string, want reflect.Type) uintptr {
	field, ok := reflect.TypeFor[gin.Context]().FieldByName(name)
	if !ok {
		panic(fmt.Sprintf("gin: unable to locate gin.Context.%s", name))
	}
	if field.Type != want {
		panic(fmt.Sprintf("gin: gin.Context.%s type mismatch: got %s, want %s (gin upstream layout changed)",
			name, field.Type, want))
	}
	return field.Offset
}

func wrapHandlersChain(handlers []HandlerFunc, engine *Engine) gin.HandlersChain {
	chain := make(gin.HandlersChain, 0, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		chain = append(chain, wrapHandler(handler, engine))
	}
	return chain
}

func cloneGinHandlers(handlers []gin.HandlerFunc) gin.HandlersChain {
	if len(handlers) == 0 {
		return nil
	}
	chain := make(gin.HandlersChain, len(handlers))
	copy(chain, handlers)
	return chain
}

func executeGinHandlerChain(c *gin.Context, handlers gin.HandlersChain, fullPath string) {
	if c == nil || len(handlers) == 0 {
		return
	}

	setGinContextHandlers(c, handlers)
	setGinContextIndex(c, -1)
	if fullPath != "" {
		setGinContextFullPath(c, fullPath)
	}
	c.Next()
}

func setGinContextHandlers(c *gin.Context, handlers gin.HandlersChain) {
	*(*gin.HandlersChain)(unsafe.Add(unsafe.Pointer(c), ginContextHandlersOffset)) = handlers
}

func setGinContextIndex(c *gin.Context, index int8) {
	*(*int8)(unsafe.Add(unsafe.Pointer(c), ginContextIndexOffset)) = index
}

func setGinContextFullPath(c *gin.Context, fullPath string) {
	*(*string)(unsafe.Add(unsafe.Pointer(c), ginContextFullPathOffset)) = fullPath
}
