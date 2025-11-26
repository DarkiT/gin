package errors

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 为 gin.Context 提供的错误处理函数
func HandleGinError(c *gin.Context, err error) {
	var response ErrorResponse
	var status int

	// 检查是否是我们的错误类型
	if appErr, ok := err.(*Error); ok {
		response = ErrorResponse{
			Code:    appErr.Code,
			Message: appErr.Message,
			Data:    appErr.Data,
		}
		status = appErr.GetStatus()
	} else {
		// 未知错误类型，使用默认值
		response = ErrorResponse{
			Code:    ErrCodeUnknown,
			Message: err.Error(),
		}
		status = http.StatusInternalServerError
	}

	c.JSON(status, response)
	c.Abort()
}

// GinErrorMiddleware 创建一个 gin 错误处理中间件
func GinErrorMiddleware(filters ...ErrorFilter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 处理 panic
		defer func() {
			if r := recover(); r != nil {
				var err error
				switch t := r.(type) {
				case error:
					err = t
				default:
					err = New(ErrCodeInternal).WithMessage("服务器内部错误")
				}

				// 将错误转换为我们的错误类型
				if appErr, ok := err.(*Error); ok {
					// 应用过滤器
					for _, filter := range filters {
						appErr = filter(appErr)
					}
					err = appErr
				} else {
					err = Wrap(err, ErrCodeInternal)
				}

				// 处理错误
				HandleGinError(c, err)
			}
		}()

		// 执行请求处理
		c.Next()

		// 如果有错误，处理它
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err

			// 将错误转换为我们的错误类型
			if appErr, ok := err.(*Error); ok {
				// 应用过滤器
				for _, filter := range filters {
					appErr = filter(appErr)
				}
				err = appErr
			} else {
				err = Wrap(err, ErrCodeUnknown)
			}

			// 处理错误
			HandleGinError(c, err)
		}
	}
}

// GinDefaultErrorMiddleware 创建一个默认的 gin 错误处理中间件
func GinDefaultErrorMiddleware() gin.HandlerFunc {
	return GinErrorMiddleware(SensitiveDataFilter)
}

// Gin 错误处理助手函数

// GinError 在 gin 上下文中返回一个错误
func GinError(c *gin.Context, err *Error) {
	_ = c.Error(err)
	c.Abort()
}

// GinInvalidParam 在 gin 上下文中返回一个无效参数错误
func GinInvalidParam(c *gin.Context, paramName string) {
	err := InvalidParam(paramName)
	GinError(c, err)
}

// GinMissingParam 在 gin 上下文中返回一个缺少参数错误
func GinMissingParam(c *gin.Context, paramName string) {
	err := MissingParam(paramName)
	GinError(c, err)
}

// GinUnauthorized 在 gin 上下文中返回一个未授权错误
func GinUnauthorized(c *gin.Context, reason string) {
	err := Unauthorized(reason)
	GinError(c, err)
}

// GinForbidden 在 gin 上下文中返回一个禁止访问错误
func GinForbidden(c *gin.Context, reason string) {
	err := Forbidden(reason)
	GinError(c, err)
}

// GinNotFound 在 gin 上下文中返回一个资源不存在错误
func GinNotFound(c *gin.Context, resource string) {
	err := NotFound(resource)
	GinError(c, err)
}

// GinInternal 在 gin 上下文中返回一个内部错误
func GinInternal(c *gin.Context, err error) {
	appErr := Internal(err)
	GinError(c, appErr)
}

// GinCustomError 在 gin 上下文中返回一个自定义错误
func GinCustomError(c *gin.Context, code int, message string) {
	err := New(code).WithMessage(message)
	GinError(c, err)
}
