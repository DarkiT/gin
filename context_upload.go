// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type effectiveUploadConfig struct {
	dir          string
	subDir       string
	maxSize      int64
	ext          []string
	filename     string
	fileNameFunc func(original string) string
}

func (c *Context) mergeUploadOptions(opts ...UploadOption) *effectiveUploadConfig {
	cfg := DefaultUploadConfig()
	if c != nil && c.engine != nil && c.engine.uploadConfig != nil {
		cfg = c.engine.uploadConfig
	}

	applied := &uploadOptions{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(applied)
	}

	dir := cfg.UploadDir
	if applied.dir != "" {
		dir = applied.dir
	}

	maxSize := cfg.MaxFileSize
	if applied.maxSize > 0 {
		maxSize = applied.maxSize
	}

	ext := cfg.AllowedExts
	if len(applied.exts) > 0 {
		ext = applied.exts
	}

	fileNameFunc := cfg.FileNameFunc
	if applied.nameFunc != nil {
		fileNameFunc = applied.nameFunc
	}

	return &effectiveUploadConfig{
		dir:          dir,
		subDir:       applied.subDir,
		maxSize:      maxSize,
		ext:          ext,
		filename:     applied.filename,
		fileNameFunc: fileNameFunc,
	}
}

func (c *Context) buildUploadResult(header *multipart.FileHeader, target *uploadTarget) *UploadResult {
	return &UploadResult{
		OriginalName: header.Filename,
		SavedName:    target.savedName,
		Path:         target.path,
		RelativePath: target.relativePath,
		Size:         header.Size,
		Ext:          normalizeExt(filepath.Ext(header.Filename)),
		MimeType:     header.Header.Get("Content-Type"),
	}
}

type uploadTarget struct {
	dir          string
	savedName    string
	path         string
	relativePath string
}

func (c *Context) resolveUploadTarget(header *multipart.FileHeader, cfg *effectiveUploadConfig) (*uploadTarget, error) {
	if err := validateFileSize(header.Size, cfg.maxSize); err != nil {
		return nil, err
	}
	if err := validateFileExt(header.Filename, cfg.ext); err != nil {
		return nil, err
	}

	dir := cfg.dir
	if dir == "" {
		dir = os.TempDir()
	}
	rootDir := filepath.Clean(dir)
	dir, err := resolveUploadDir(rootDir, cfg.subDir)
	if err != nil {
		return nil, err
	}

	savedName := cfg.filename
	if savedName == "" {
		nameFunc := cfg.fileNameFunc
		if nameFunc == nil {
			nameFunc = defaultFileNameFunc
		}
		savedName = nameFunc(header.Filename)
	}
	if err := validateUploadName(savedName); err != nil {
		return nil, err
	}
	if err := validateFileExt(savedName, cfg.ext); err != nil {
		return nil, err
	}

	fullPath := filepath.Join(dir, savedName)
	relativePath, err := filepath.Rel(rootDir, fullPath)
	if err != nil {
		return nil, err
	}

	return &uploadTarget{
		dir:          dir,
		savedName:    savedName,
		path:         fullPath,
		relativePath: filepath.ToSlash(relativePath),
	}, nil
}

func (c *Context) persistUploadTarget(header *multipart.FileHeader, target *uploadTarget) error {
	if err := os.MkdirAll(target.dir, 0o755); err != nil {
		return err
	}
	if err := c.SaveUploadedFile(header, target.path); err != nil {
		return err
	}
	return nil
}

func (c *Context) saveFileHeader(header *multipart.FileHeader, opts ...UploadOption) (*UploadResult, error) {
	cfg := c.mergeUploadOptions(opts...)
	target, err := c.resolveUploadTarget(header, cfg)
	if err != nil {
		return nil, err
	}
	if err := c.persistUploadTarget(header, target); err != nil {
		return nil, err
	}

	return c.buildUploadResult(header, target), nil
}

// SaveFile 保存单个文件，formKey 为表单字段名。
func (c *Context) SaveFile(formKey string, opts ...UploadOption) (*UploadResult, error) {
	fileHeader, err := c.FormFile(formKey)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return c.saveFileHeader(fileHeader, opts...)
}

// SaveFiles 批量保存多文件，formKey 为表单字段名。
func (c *Context) SaveFiles(formKey string, opts ...UploadOption) ([]*UploadResult, error) {
	form, err := c.MultipartForm()
	if err != nil {
		return nil, err
	}

	files := form.File[formKey]
	if len(files) == 0 {
		return nil, ErrFileNotFound
	}

	cfg := c.mergeUploadOptions(opts...)
	targets := make([]*uploadTarget, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	for _, fileHeader := range files {
		target, err := c.resolveUploadTarget(fileHeader, cfg)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[target.path]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateUploadTarget, target.path)
		}
		seen[target.path] = struct{}{}
		targets = append(targets, target)
	}

	results := make([]*UploadResult, 0, len(files))
	for idx, fileHeader := range files {
		target := targets[idx]
		if err := c.persistUploadTarget(fileHeader, target); err != nil {
			return nil, err
		}
		results = append(results, c.buildUploadResult(fileHeader, target))
	}
	return results, nil
}

// ValidateFile 仅验证不保存，formKey 为表单字段名。
func (c *Context) ValidateFile(formKey string, opts ...UploadOption) (*multipart.FileHeader, error) {
	fileHeader, err := c.FormFile(formKey)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}

	cfg := c.mergeUploadOptions(opts...)
	if _, err := c.resolveUploadTarget(fileHeader, cfg); err != nil {
		return nil, err
	}
	return fileHeader, nil
}

// StreamFile 文件下载（attachment），filepath 为磁盘路径。
func (c *Context) StreamFile(filepath string, filename ...string) {
	name := filepath
	if len(filename) > 0 && filename[0] != "" {
		name = filename[0]
	}
	c.FileAttachment(filepath, name)
}

// StreamFileInline 文件预览（inline），filepath 为磁盘路径。
func (c *Context) StreamFileInline(filepath string) {
	c.File(filepath)
}
