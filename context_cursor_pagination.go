// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import "net/http"

// ParseCursorPagination 解析基于游标的分页参数。
func (c *Context) ParseCursorPagination(opts ...CursorPaginationOption) *CursorPaginationParams {
	options := defaultCursorPaginationOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	limit := parsePositiveInt(c.Input("limit"), options.defaultLimit)
	limit = clampCursorLimit(limit, options.maxLimit)

	return &CursorPaginationParams{
		Cursor: c.Input("cursor"),
		Limit:  limit,
	}
}

// CursorPaginated 返回带游标元信息的列表响应。
func (c *Context) CursorPaginated(data any, info *CursorPageInfo) {
	c.JSON(http.StatusOK, newCursorPaginatedResponse(http.StatusOK, "success", data, info, c.getRequestID()))
}
