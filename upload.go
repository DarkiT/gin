// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/darkit/gin/internal/pathutil"
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
	RelativePath string `json:"relative_path"` // 相对上传根目录的路径
	Size         int64  `json:"size"`          // 文件大小（字节）
	Ext          string `json:"ext"`           // 扩展名（不含点）
	MimeType     string `json:"mime_type"`     // MIME 类型
}

// UploadOption 定义上传选项，用于覆盖 Engine 默认配置。
type UploadOption func(*uploadOptions)

// uploadOptions 内部选项结构
type uploadOptions struct {
	dir      string   // 覆盖上传目录
	subDir   string   // 在上传目录下追加的安全子目录
	maxSize  int64    // 覆盖最大大小限制
	exts     []string // 覆盖允许的扩展名
	filename string   // 指定保存文件名（含扩展名）
	nameFunc func(original string) string
}

// ToDir 指定上传目录（覆盖默认）。
func ToDir(dir string) UploadOption {
	return func(o *uploadOptions) {
		o.dir = dir
	}
}

// ToSubDir 指定上传子目录（相对于上传根目录）。
// 仅允许相对路径，禁止绝对路径、盘符路径与 ".." 目录穿越。
func ToSubDir(subDir string) UploadOption {
	return func(o *uploadOptions) {
		o.subDir = subDir
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
// 如需按目录分类保存，请配合 ToSubDir(...) 显式指定子目录。
func AsName(name string) UploadOption {
	return func(o *uploadOptions) {
		o.nameFunc = nil
		o.filename = name
	}
}

// NameBy 指定本次上传的文件名生成函数。
// 适合批量上传等需要按原始文件名动态生成唯一目标名的场景。
func NameBy(fn func(original string) string) UploadOption {
	return func(o *uploadOptions) {
		o.filename = ""
		o.nameFunc = fn
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

	// ErrInvalidUploadName 表示保存文件名非法。
	ErrInvalidUploadName = errors.New("非法的保存文件名")

	// ErrInvalidUploadSubDir 表示上传子目录非法。
	ErrInvalidUploadSubDir = errors.New("非法的上传子目录")

	// ErrDuplicateUploadTarget 表示批量上传时目标文件路径冲突。
	ErrDuplicateUploadTarget = errors.New("批量上传目标文件冲突")
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

// validateUploadName 验证最终保存文件名，防止绝对路径与目录穿越。
func validateUploadName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ErrInvalidUploadName
	}
	if strings.ContainsRune(trimmed, 0) {
		return ErrInvalidUploadName
	}
	if filepath.IsAbs(trimmed) || isWindowsDriveLikePath(trimmed) {
		return ErrInvalidUploadName
	}
	if strings.ContainsAny(trimmed, `/\`) {
		return ErrInvalidUploadName
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || cleaned != trimmed {
		return ErrInvalidUploadName
	}
	return nil
}

func isWindowsDriveLikePath(name string) bool {
	return len(name) >= 2 && name[1] == ':' && unicode.IsLetter(rune(name[0]))
}

// resolveUploadDir 解析最终上传目录，允许在基础目录下显式追加安全子目录。
func resolveUploadDir(baseDir, subDir string) (string, error) {
	base := strings.TrimSpace(baseDir)
	if base == "" {
		return "", ErrCreateUploadDir
	}

	base = filepath.Clean(base)
	trimmedSubDir := strings.TrimSpace(subDir)
	if trimmedSubDir == "" {
		return base, nil
	}
	if strings.ContainsRune(trimmedSubDir, 0) {
		return "", ErrInvalidUploadSubDir
	}

	resolved, err := pathutil.SafePath(base, trimmedSubDir)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidUploadSubDir, trimmedSubDir)
	}
	return resolved, nil
}
