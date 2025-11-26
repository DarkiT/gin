// Package errors 提供统一的错误处理机制
package errors

import (
	stdErrors "errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

// 预定义错误码
const (
	// 通用错误码范围 1-999
	ErrCodeUnknown        = 1   // 未知错误
	ErrCodeInternal       = 2   // 内部错误
	ErrCodeInvalidParam   = 100 // 无效参数
	ErrCodeUnauthorized   = 401 // 未授权
	ErrCodeForbidden      = 403 // 禁止访问
	ErrCodeNotFound       = 404 // 资源不存在
	ErrCodeTimeout        = 408 // 超时
	ErrCodeTooManyRequest = 429 // 请求过多

	// 业务错误码范围 1000-1999
	ErrCodeBusinessBase = 1000
	ErrCodeInvalidToken = 1001 // 无效令牌
	ErrCodeTokenExpired = 1002 // 令牌过期

	// 数据库错误码范围 2000-2999
	ErrCodeDBBase       = 2000
	ErrCodeDBConnection = 2001 // 数据库连接失败
	ErrCodeDBQuery      = 2002 // 数据库查询失败
	ErrCodeDBInsert     = 2003 // 数据库插入失败
	ErrCodeDBUpdate     = 2004 // 数据库更新失败
	ErrCodeDBDelete     = 2005 // 数据库删除失败

	// 外部服务错误码范围 3000-3999
	ErrCodeServiceBase    = 3000
	ErrCodeServiceTimeout = 3001 // 服务调用超时
	ErrCodeServiceDown    = 3002 // 服务不可用
)

// 错误码对应的默认HTTP状态码
var defaultHttpStatus = map[int]int{
	ErrCodeUnknown:        http.StatusInternalServerError,
	ErrCodeInternal:       http.StatusInternalServerError,
	ErrCodeInvalidParam:   http.StatusBadRequest,
	ErrCodeUnauthorized:   http.StatusUnauthorized,
	ErrCodeForbidden:      http.StatusForbidden,
	ErrCodeNotFound:       http.StatusNotFound,
	ErrCodeTimeout:        http.StatusRequestTimeout,
	ErrCodeTooManyRequest: http.StatusTooManyRequests,

	ErrCodeInvalidToken: http.StatusUnauthorized,
	ErrCodeTokenExpired: http.StatusUnauthorized,

	ErrCodeDBConnection: http.StatusInternalServerError,
	ErrCodeDBQuery:      http.StatusInternalServerError,
	ErrCodeDBInsert:     http.StatusInternalServerError,
	ErrCodeDBUpdate:     http.StatusInternalServerError,
	ErrCodeDBDelete:     http.StatusInternalServerError,

	ErrCodeServiceTimeout: http.StatusInternalServerError,
	ErrCodeServiceDown:    http.StatusInternalServerError,
}

// 错误码对应的默认错误信息
var defaultErrorMessages = map[int]string{
	ErrCodeUnknown:        "未知错误",
	ErrCodeInternal:       "内部错误",
	ErrCodeInvalidParam:   "无效参数",
	ErrCodeUnauthorized:   "未授权",
	ErrCodeForbidden:      "禁止访问",
	ErrCodeNotFound:       "资源不存在",
	ErrCodeTimeout:        "请求超时",
	ErrCodeTooManyRequest: "请求过多，请稍后再试",

	ErrCodeInvalidToken: "无效令牌",
	ErrCodeTokenExpired: "令牌已过期",

	ErrCodeDBConnection: "数据库连接失败",
	ErrCodeDBQuery:      "数据库查询失败",
	ErrCodeDBInsert:     "数据库插入失败",
	ErrCodeDBUpdate:     "数据库更新失败",
	ErrCodeDBDelete:     "数据库删除失败",

	ErrCodeServiceTimeout: "服务调用超时",
	ErrCodeServiceDown:    "服务不可用",
}

// Error 表示一个应用错误
type Error struct {
	// Code 错误码
	Code int `json:"code"`

	// Message 错误信息
	Message string `json:"message"`

	// Data 附加信息
	Data interface{} `json:"data,omitempty"`

	// Status HTTP状态码
	Status int `json:"-"`

	// Cause 原始错误
	Cause error `json:"-"`

	// File 发生错误的文件
	File string `json:"-"`

	// Line 发生错误的行号
	Line int `json:"-"`

	// Stack 调用栈
	Stack string `json:"-"`
}

// Error 实现error接口
func (e *Error) Error() string {
	parts := []string{fmt.Sprintf("错误码: %d", e.Code)}

	if e.Message != "" {
		parts = append(parts, fmt.Sprintf("信息: %s", e.Message))
	}

	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("原因: %s", e.Cause.Error()))
	}

	if e.File != "" {
		parts = append(parts, fmt.Sprintf("位置: %s:%d", e.File, e.Line))
	}

	return strings.Join(parts, ", ")
}

// Unwrap 获取底层错误
func (e *Error) Unwrap() error {
	return e.Cause
}

// WithStatus 设置HTTP状态码
func (e *Error) WithStatus(status int) *Error {
	e.Status = status
	return e
}

// WithMessage 设置错误信息
func (e *Error) WithMessage(message string) *Error {
	e.Message = message
	return e
}

// WithData 设置附加数据
func (e *Error) WithData(data interface{}) *Error {
	e.Data = data
	return e
}

// WithCause 设置原始错误
func (e *Error) WithCause(cause error) *Error {
	if cause != nil {
		e.Cause = cause
	}
	return e
}

// GetStatus 获取HTTP状态码
func (e *Error) GetStatus() int {
	if e.Status != 0 {
		return e.Status
	}

	if status, exists := defaultHttpStatus[e.Code]; exists {
		return status
	}

	return http.StatusInternalServerError
}

// GetDefaultMessage 获取错误码对应的默认错误信息
func GetDefaultMessage(code int) string {
	if msg, exists := defaultErrorMessages[code]; exists {
		return msg
	}
	return defaultErrorMessages[ErrCodeUnknown]
}

// GetDefaultStatus 获取错误码对应的默认HTTP状态码
func GetDefaultStatus(code int) int {
	if status, exists := defaultHttpStatus[code]; exists {
		return status
	}
	return http.StatusInternalServerError
}

// New 创建一个新的错误
func New(code int) *Error {
	message := GetDefaultMessage(code)
	status := GetDefaultStatus(code)

	// 获取调用堆栈
	_, file, line, _ := runtime.Caller(1)

	return &Error{
		Code:    code,
		Message: message,
		Status:  status,
		File:    file,
		Line:    line,
		Stack:   getCallStack(2), // 跳过当前函数和调用者
	}
}

// Wrap 包装一个已有的错误
func Wrap(err error, code int) *Error {
	if err == nil {
		return nil
	}

	// 如果已经是我们的错误类型，则更新错误码
	if appErr, ok := err.(*Error); ok {
		if code != 0 {
			appErr.Code = code
			appErr.Message = GetDefaultMessage(code)
			appErr.Status = GetDefaultStatus(code)
		}
		return appErr
	}

	// 获取调用堆栈
	_, file, line, _ := runtime.Caller(1)

	return &Error{
		Code:    code,
		Message: GetDefaultMessage(code),
		Status:  GetDefaultStatus(code),
		Cause:   err,
		File:    file,
		Line:    line,
		Stack:   getCallStack(2), // 跳过当前函数和调用者
	}
}

// WrapWithMessage 包装错误并设置自定义消息
func WrapWithMessage(err error, code int, message string) *Error {
	appErr := Wrap(err, code)
	if appErr != nil {
		appErr.Message = message
	}
	return appErr
}

// Is 检查错误码是否匹配
func Is(err error, code int) bool {
	if err == nil {
		return false
	}

	var appErr *Error
	if ok := As(err, &appErr); ok {
		return appErr.Code == code
	}

	return false
}

// As 将错误转换为指定类型
func As(err error, target interface{}) bool {
	return stdErrors.As(err, target)
}

// getCallStack 获取调用栈信息
func getCallStack(skip int) string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(skip, pcs[:])

	frames := runtime.CallersFrames(pcs[:n])
	var stackBuilder strings.Builder

	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		// 忽略运行时内部函数
		if strings.Contains(frame.File, "runtime/") {
			continue
		}

		fmt.Fprintf(&stackBuilder, "%s:%d %s\n", frame.File, frame.Line, frame.Function)

		// 最多显示8层调用栈
		if stackBuilder.Len() > 8 {
			break
		}
	}

	return stackBuilder.String()
}

// InvalidParam 创建无效参数错误
func InvalidParam(paramName string) *Error {
	msg := fmt.Sprintf("无效参数: %s", paramName)
	return New(ErrCodeInvalidParam).WithMessage(msg)
}

// MissingParam 创建缺少参数错误
func MissingParam(paramName string) *Error {
	msg := fmt.Sprintf("缺少参数: %s", paramName)
	return New(ErrCodeInvalidParam).WithMessage(msg)
}

// Unauthorized 创建未授权错误
func Unauthorized(reason string) *Error {
	msg := "未授权"
	if reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, reason)
	}
	return New(ErrCodeUnauthorized).WithMessage(msg)
}

// Forbidden 创建禁止访问错误
func Forbidden(reason string) *Error {
	msg := "禁止访问"
	if reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, reason)
	}
	return New(ErrCodeForbidden).WithMessage(msg)
}

// NotFound 创建资源不存在错误
func NotFound(resource string) *Error {
	msg := "资源不存在"
	if resource != "" {
		msg = fmt.Sprintf("%s: %s", msg, resource)
	}
	return New(ErrCodeNotFound).WithMessage(msg)
}

// Internal 创建内部错误
func Internal(err error) *Error {
	return Wrap(err, ErrCodeInternal)
}
