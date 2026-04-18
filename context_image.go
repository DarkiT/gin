// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	imagepkg "github.com/darkit/gin/pkg/image"
)

// SaveImage 保存并处理图片，formKey 为表单字段名。
func (c *Context) SaveImage(formKey string, opts ...imagepkg.ImageOption) (*imagepkg.ImageResult, error) {
	uploadResult, err := c.SaveFile(formKey)
	if err != nil {
		return nil, err
	}
	dstPath := buildImagePathWithFormat(uploadResult.Path, opts)
	result, err := imagepkg.Process(uploadResult.Path, dstPath, uploadResult.OriginalName, opts...)
	if err != nil {
		return nil, err
	}
	if dstPath != uploadResult.Path {
		_ = removeFile(uploadResult.Path)
	}
	return result, nil
}

// ProcessImages 批量处理图片，configs 为处理配置列表。
func (c *Context) ProcessImages(formKey string, configs []imagepkg.ImageConfig) ([]*imagepkg.ImageResult, error) {
	uploadResult, err := c.SaveFile(formKey)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("图片处理配置不能为空")
	}
	results := make([]*imagepkg.ImageResult, 0, len(configs))
	for _, cfg := range configs {
		if cfg.Suffix == "" {
			return nil, fmt.Errorf("图片处理配置后缀不能为空")
		}
		dstPath := buildImagePathWithSuffix(uploadResult.Path, cfg.Suffix, cfg.Options)
		result, err := imagepkg.Process(uploadResult.Path, dstPath, uploadResult.OriginalName, cfg.Options...)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func buildImagePathWithSuffix(path, suffix string, opts []imagepkg.ImageOption) string {
	format := imagepkg.ExtractFormat(opts)
	if strings.TrimSpace(format) == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	}
	format = normalizeImageExt(format)
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	filename := base + suffix
	if format != "" {
		filename = filename + "." + format
	}
	return filepath.Join(filepath.Dir(path), filename)
}

func buildImagePathWithFormat(path string, opts []imagepkg.ImageOption) string {
	format := imagepkg.ExtractFormat(opts)
	if strings.TrimSpace(format) == "" {
		return path
	}
	format = normalizeImageExt(format)
	if format == "" {
		return path
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	filename := base + "." + format
	return filepath.Join(filepath.Dir(path), filename)
}

func normalizeImageExt(format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "jpeg" {
		return "jpg"
	}
	return format
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
