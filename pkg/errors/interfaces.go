package errors

import "github.com/darkit/gin/types"

// ErrorHandler 错误处理器接口
type ErrorHandler interface {
	HandleError(ctx types.RequestContext, err error)
}
