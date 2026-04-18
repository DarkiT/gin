package gin

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/gin-gonic/gin"
)

var (
	ginContextHandlersOffset = mustGinContextFieldOffset("handlers")
	ginContextIndexOffset    = mustGinContextFieldOffset("index")
	ginContextFullPathOffset = mustGinContextFieldOffset("fullPath")
)

func mustGinContextFieldOffset(name string) uintptr {
	field, ok := reflect.TypeOf(gin.Context{}).FieldByName(name)
	if !ok {
		panic(fmt.Sprintf("gin: unable to locate gin.Context.%s", name))
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
