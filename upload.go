// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// UploadConfig 定义文件上传全局配置（Engine 级别）。
type UploadConfig struct {
	// UploadDir 默认上传目录，空字符串则使用系统临时目录
	UploadDir string

	// MaxFileSize 单个文件最大大小（字节），0 表示不限制
	MaxFileSize int64

	// MaxMultipartMemory multipart 表单解析内存限制
	// 超出部分写入临时文件，默认 32MB
	MaxMultipartMemory int64

	// AllowedExts 允许的文件扩展名（不含点，如 "jpg", "png"）
	// nil 或空切片表示允许所有类型
	AllowedExts []string

	// FileNameFunc 自定义文件名生成函数
	// 参数为原始文件名，返回新文件名（不含路径）
	// nil 使用默认生成器（UUID + 原扩展名）
	FileNameFunc func(original string) string
}

// DefaultUploadConfig 返回默认上传配置。
func DefaultUploadConfig() *UploadConfig {
	return &UploadConfig{
		UploadDir:          "",       // 空则使用 os.TempDir()
		MaxFileSize:        10 << 20, // 10MB
		MaxMultipartMemory: 32 << 20, // 32MB
		AllowedExts:        nil,      // 允许所有类型
		FileNameFunc:       nil,      // 使用默认 UUID 生成器
	}
}

// UploadResult 定义上传结果信息。
type UploadResult struct {
	OriginalName string `json:"original_name"` // 原始文件名
	SavedName    string `json:"saved_name"`    // 保存后的文件名
	Path         string `json:"path"`          // 完整保存路径
	Size         int64  `json:"size"`          // 文件大小（字节）
	Ext          string `json:"ext"`           // 扩展名（不含点）
	MimeType     string `json:"mime_type"`     // MIME 类型
}

// UploadOption 定义上传选项，用于覆盖 Engine 默认配置。
type UploadOption func(*uploadOptions)

// uploadOptions 内部选项结构
type uploadOptions struct {
	dir      string   // 覆盖上传目录
	maxSize  int64    // 覆盖最大大小限制
	exts     []string // 覆盖允许的扩展名
	filename string   // 指定保存文件名（含扩展名）
}

// ToDir 指定上传目录（覆盖默认）。
func ToDir(dir string) UploadOption {
	return func(o *uploadOptions) {
		o.dir = dir
	}
}

// MaxSize 指定最大文件大小（覆盖默认）。
func MaxSize(size int64) UploadOption {
	return func(o *uploadOptions) {
		o.maxSize = size
	}
}

// AllowExts 指定允许的扩展名（覆盖默认）。
func AllowExts(exts ...string) UploadOption {
	return func(o *uploadOptions) {
		o.exts = exts
	}
}

// AsName 指定保存文件名（不含路径，含扩展名）。
func AsName(name string) UploadOption {
	return func(o *uploadOptions) {
		o.filename = name
	}
}

// 文件上传错误定义。
var (
	// ErrFileTooLarge 表示文件超过大小限制。
	ErrFileTooLarge = errors.New("文件大小超过限制")

	// ErrFileExtNotAllowed 表示文件扩展名不允许。
	ErrFileExtNotAllowed = errors.New("不允许的文件类型")

	// ErrFileNotFound 表示表单中未找到指定文件。
	ErrFileNotFound = errors.New("未找到上传文件")

	// ErrCreateUploadDir 表示创建上传目录失败。
	ErrCreateUploadDir = errors.New("创建上传目录失败")
)

// defaultFileNameFunc 默认文件名生成器（UUID + 原扩展名）。
func defaultFileNameFunc(original string) string {
	ext := filepath.Ext(original)
	return uuid.New().String() + ext
}

// normalizeExt 标准化扩展名（去除前导点并转为小写）。
func normalizeExt(ext string) string {
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

// containsExt 检查扩展名是否在允许列表中。
func containsExt(exts []string, ext string) bool {
	normalized := normalizeExt(ext)
	for _, allowed := range exts {
		if normalizeExt(allowed) == normalized {
			return true
		}
	}
	return false
}

// validateFileSize 验证文件大小。
func validateFileSize(size, maxSize int64) error {
	if maxSize > 0 && size > maxSize {
		return fmt.Errorf("%w: %d > %d", ErrFileTooLarge, size, maxSize)
	}
	return nil
}

// validateFileExt 验证文件扩展名。
func validateFileExt(filename string, allowedExts []string) error {
	if len(allowedExts) == 0 {
		return nil // 允许所有扩展名
	}

	ext := filepath.Ext(filename)
	if !containsExt(allowedExts, ext) {
		return fmt.Errorf("%w: %s", ErrFileExtNotAllowed, normalizeExt(ext))
	}
	return nil
}
