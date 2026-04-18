// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"errors"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type effectiveUploadConfig struct {
	dir          string
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

	return &effectiveUploadConfig{
		dir:          dir,
		maxSize:      maxSize,
		ext:          ext,
		filename:     applied.filename,
		fileNameFunc: cfg.FileNameFunc,
	}
}

func (c *Context) buildUploadResult(header *multipart.FileHeader, dir, savedName string) *UploadResult {
	return &UploadResult{
		OriginalName: header.Filename,
		SavedName:    savedName,
		Path:         filepath.Join(dir, savedName),
		Size:         header.Size,
		Ext:          normalizeExt(filepath.Ext(header.Filename)),
		MimeType:     header.Header.Get("Content-Type"),
	}
}

func (c *Context) saveFileHeader(header *multipart.FileHeader, opts ...UploadOption) (*UploadResult, error) {
	cfg := c.mergeUploadOptions(opts...)

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

	savedName := cfg.filename
	if savedName == "" {
		nameFunc := cfg.fileNameFunc
		if nameFunc == nil {
			nameFunc = defaultFileNameFunc
		}
		savedName = nameFunc(header.Filename)
	}

	dst := filepath.Join(dir, savedName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := c.SaveUploadedFile(header, dst); err != nil {
		return nil, err
	}

	return c.buildUploadResult(header, dir, savedName), nil
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

	results := make([]*UploadResult, 0, len(files))
	for _, fileHeader := range files {
		result, err := c.saveFileHeader(fileHeader, opts...)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
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
	if err := validateFileSize(fileHeader.Size, cfg.maxSize); err != nil {
		return nil, err
	}
	if err := validateFileExt(fileHeader.Filename, cfg.ext); err != nil {
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
