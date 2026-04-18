// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import "time"

// Response 定义标准响应结构。
type Response struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// PaginatedResponse 定义带分页信息的响应结构。
type PaginatedResponse struct {
	Code       int         `json:"code"`
	Message    string      `json:"message"`
	Data       any         `json:"data,omitempty"`
	Pagination *Pagination `json:"pagination"`
	RequestID  string      `json:"request_id,omitempty"`
	Timestamp  int64       `json:"timestamp"`
}

// Pagination 定义分页元信息。
type Pagination struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// ValidationError 定义字段级校验错误信息。
type ValidationError struct {
	Field   string `json:"field"`           // 字段名
	Tag     string `json:"tag,omitempty"`   // 验证标签（如 required, min, max）
	Value   any    `json:"value,omitempty"` // 实际值（可选，调试用）
	Param   string `json:"param,omitempty"` // 验证参数（如 min=5 中的 5）
	Message string `json:"message"`         // 错误消息
}

// ErrorResponse 定义错误响应结构。
type ErrorResponse struct {
	Code      int               `json:"code"`
	Message   string            `json:"message"`
	Errors    []ValidationError `json:"errors,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Timestamp int64             `json:"timestamp"`
}

// NewPagination 生成分页元信息。
func NewPagination(page, perPage int, total int64) *Pagination {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 1
	}
	if total < 0 {
		total = 0
	}
	totalPages := 0
	if total > 0 {
		// ceil(total / perPage)
		totalPages = int((total + int64(perPage) - 1) / int64(perPage))
	}
	return &Pagination{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}
}

func newResponse(code int, message string, data any, requestID string) Response {
	return Response{
		Code:      code,
		Message:   message,
		Data:      data,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}
}

func newPaginatedResponse(code int, message string, data any, pagination *Pagination, requestID string) PaginatedResponse {
	return PaginatedResponse{
		Code:       code,
		Message:    message,
		Data:       data,
		Pagination: pagination,
		RequestID:  requestID,
		Timestamp:  time.Now().Unix(),
	}
}

func newErrorResponse(code int, message string, errors []ValidationError, requestID string) ErrorResponse {
	return ErrorResponse{
		Code:      code,
		Message:   message,
		Errors:    errors,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}
}
