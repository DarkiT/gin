// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"strconv"
	"strings"
)

// PaginationParams 分页参数结构
// Offset 为计算结果：(Page-1)*PerPage
// 用于数据库分页查询
type PaginationParams struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Offset  int `json:"offset"`
}

// PaginationOption 定义分页配置选项。
type PaginationOption func(*paginationOptions)

type paginationOptions struct {
	defaultPage    int
	defaultPerPage int
	maxPerPage     int
}

// WithDefaultPage 设置默认页码。
func WithDefaultPage(page int) PaginationOption {
	return func(o *paginationOptions) {
		if page > 0 {
			o.defaultPage = page
		}
	}
}

// WithDefaultPerPage 设置默认每页数量。
func WithDefaultPerPage(perPage int) PaginationOption {
	return func(o *paginationOptions) {
		if perPage > 0 {
			o.defaultPerPage = perPage
		}
	}
}

// WithMaxPerPage 设置每页最大数量，<=0 表示不限制。
func WithMaxPerPage(max int) PaginationOption {
	return func(o *paginationOptions) {
		if max > 0 {
			o.maxPerPage = max
		}
	}
}

// defaultPaginationOptions 返回分页默认配置。
func defaultPaginationOptions() *paginationOptions {
	return &paginationOptions{
		defaultPage:    1,
		defaultPerPage: 20,
		maxPerPage:     0,
	}
}

func normalizeDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func parsePositiveInt(value string, def int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return def
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return def
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func applyMaxPerPage(perPage, max int) int {
	if max > 0 && perPage > max {
		return max
	}
	return perPage
}

func calculateOffset(page, perPage int) int {
	if page <= 1 {
		return 0
	}
	return (page - 1) * perPage
}
