// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"net/http"

	"github.com/darkit/gin/pkg/mask"
)

// OKMasked 返回脱敏后的响应数据，opts 为脱敏选项。
func (c *Context) OKMasked(data any, opts ...mask.MaskOption) {
	masked := mask.MaskValue(data, opts...)
	c.JSON(http.StatusOK, newResponse(http.StatusOK, "success", masked, c.getRequestID()))
}

// PaginatedMasked 返回脱敏后的分页响应，opts 为脱敏选项。
func (c *Context) PaginatedMasked(data any, page, perPage int, total int64, opts ...mask.MaskOption) {
	masked := mask.MaskValue(data, opts...)
	pagination := NewPagination(page, perPage, total)
	c.JSON(http.StatusOK, newPaginatedResponse(http.StatusOK, "success", masked, pagination, c.getRequestID()))
}
