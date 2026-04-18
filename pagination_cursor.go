// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import "time"

// CursorPaginationParams 定义基于游标的分页请求参数。
type CursorPaginationParams struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

// CursorPageInfo 定义基于游标的分页响应元信息。
type CursorPageInfo struct {
	NextCursor string `json:"next_cursor,omitempty"`
	PrevCursor string `json:"prev_cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	HasMore    bool   `json:"has_more,omitempty"`
}

// CursorPaginatedResponse 定义带游标元信息的列表响应。
type CursorPaginatedResponse struct {
	Code      int             `json:"code"`
	Message   string          `json:"message"`
	Data      any             `json:"data,omitempty"`
	Cursor    *CursorPageInfo `json:"cursor,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Timestamp int64           `json:"timestamp"`
}

// CursorPaginationOption 定义游标分页配置选项。
type CursorPaginationOption func(*cursorPaginationOptions)

type cursorPaginationOptions struct {
	defaultLimit int
	maxLimit     int
}

// WithDefaultCursorLimit 设置游标分页的默认 limit。
func WithDefaultCursorLimit(limit int) CursorPaginationOption {
	return func(o *cursorPaginationOptions) {
		if limit > 0 {
			o.defaultLimit = limit
		}
	}
}

// WithMaxCursorLimit 设置游标分页的最大 limit，<=0 表示不限制。
func WithMaxCursorLimit(limit int) CursorPaginationOption {
	return func(o *cursorPaginationOptions) {
		if limit > 0 {
			o.maxLimit = limit
		}
	}
}

func defaultCursorPaginationOptions() *cursorPaginationOptions {
	return &cursorPaginationOptions{
		defaultLimit: 20,
		maxLimit:     0,
	}
}

func clampCursorLimit(limit, maxLimit int) int {
	if limit < 1 {
		limit = 1
	}
	if maxLimit > 0 && limit > maxLimit {
		return maxLimit
	}
	return limit
}

func newCursorPaginatedResponse(code int, message string, data any, cursor *CursorPageInfo, requestID string) CursorPaginatedResponse {
	return CursorPaginatedResponse{
		Code:      code,
		Message:   message,
		Data:      data,
		Cursor:    cursor,
		RequestID: requestID,
		Timestamp: time.Now().Unix(),
	}
}
