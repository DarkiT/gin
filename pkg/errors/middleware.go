package errors

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
)

// ResponseWriter 接口定义了一个可以写入 HTTP 响应的对象
type ResponseWriter interface {
	http.ResponseWriter
	JSON(code int, obj interface{})
}

// ErrorResponse 表示一个错误响应
type ErrorResponse struct {
	Code    int         `json:"code"`    // 错误码
	Message string      `json:"message"` // 错误消息
	Data    interface{} `json:"data,omitempty"`
}

// ErrorHandlerFunc 表示一个错误处理函数
type ErrorHandlerFunc func(w ResponseWriter, err error)

// DefaultErrorHandler 是默认的错误处理函数
func DefaultErrorHandler(w ResponseWriter, err error) {
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

	w.JSON(status, response)
}

// ErrorFilter 是一个错误过滤器，用于隐藏或修改特定错误信息
type ErrorFilter func(err *Error) *Error

// SensitiveDataFilter 隐藏敏感错误信息
func SensitiveDataFilter(err *Error) *Error {
	// 检查错误消息中是否包含敏感信息
	sensitivePatterns := []string{
		"password", "密码", "token", "令牌", "secret", "秘钥",
		"private", "api_key", "auth", "credential", "key",
	}

	message := err.Message
	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(message), strings.ToLower(pattern)) {
			// 如果包含敏感信息，替换为通用消息
			err.Message = "系统错误，请联系管理员"
			break
		}
	}

	// 数据库错误也应该隐藏详情
	if err.Code >= ErrCodeDBBase && err.Code < ErrCodeDBBase+1000 {
		if err.Cause != nil {
			// 保留错误但隐藏具体细节
			err.Data = map[string]string{
				"error_type": "database_error",
			}
		}
	}

	return err
}

// RecoveryMiddleware 处理 panic 并将其转换为错误响应
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				// 打印调用栈以便调试
				log.Printf("Handler panic: %v\n%s", r, debug.Stack())

				// 创建 500 错误响应
				errorResponse := ErrorResponse{
					Code:    ErrCodeInternal,
					Message: "服务器内部错误",
				}

				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
					log.Printf("failed to encode error response: %v", err)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

/*
// ErrorHandlerMiddleware 创建一个错误处理中间件
func ErrorHandlerMiddleware(handler ErrorHandlerFunc, filters ...ErrorFilter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 这里需要具体实现，具体取决于你的 Web 框架
			// 这只是一个示例骨架

			// 你需要包装 ResponseWriter 以捕获错误
			// 并使用提供的 handler 函数处理错误
			// 下面是伪代码：
			wrappedWriter := WrapResponseWriter(w)

			// 调用下一个处理器
			next.ServeHTTP(wrappedWriter, r)

			// 检查是否有错误
			if err := wrappedWriter.GetError(); err != nil {
				// 应用过滤器
				if appErr, ok := err.(*Error); ok {
					for _, filter := range filters {
						appErr = filter(appErr)
					}
					err = appErr
				}

				// 处理错误
				handler(wrappedWriter, err)
			}

		})
	}
}

// 以下是一个使用示例（在实际项目中需要根据具体框架调整）：
func ExampleUsage() {
	// 创建一个带有错误处理的 mux
	mux := http.NewServeMux()

	// 添加路由
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		// 业务逻辑
		if err := someFunction(); err != nil {
			// 将错误转换为我们的错误类型
			appErr := errors.Wrap(err, errors.ErrCodeDBQuery)

			// 设置自定义消息和数据
			appErr.WithMessage("获取用户数据失败").
				  WithData(map[string]interface{}{
					  "request_id": getRequestID(r),
				  })

			// 将错误传递给错误处理器
			DefaultErrorHandler(w.(ResponseWriter), appErr)
			return
		}

		// 成功响应
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	// 应用中间件
	handler := RecoveryMiddleware(mux)

	// 启动服务器
	http.ListenAndServe(":8080", handler)
}
*/
