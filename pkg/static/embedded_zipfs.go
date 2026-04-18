package static

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

type embeddedZipFileSystem struct {
	files    map[string]*memoryFile
	subPaths []string
}

func (z *embeddedZipFileSystem) Open(name string) (http.File, error) {
	if z == nil {
		return nil, os.ErrNotExist
	}

	target := normalizeZipOpenName(name)
	validatePath := "/"
	if target != "" {
		validatePath = "/" + target
	}
	if !matchesSubPath(validatePath, z.subPaths) {
		return nil, os.ErrNotExist
	}

	file, ok := z.files[target]
	if !ok {
		return nil, os.ErrNotExist
	}
	return file.clone(), nil
}

// NewEmbeddedZipFS 从 fs.FS 中的 ZIP 文件创建静态文件系统。
func NewEmbeddedZipFS(archive fs.FS, archivePath string, opts ...Option) (http.FileSystem, error) {
	if archive == nil {
		return nil, fmt.Errorf("嵌入式文件系统不能为空")
	}

	config := ZipFSConfig{
		IndexFile: "index.html",
	}
	applyZipFSOptions(&config, opts)
	if config.Password != "" {
		return nil, fmt.Errorf("嵌入式 ZIP 暂不支持密码保护")
	}

	targetPath := strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(archivePath)), "/")
	if targetPath == "" {
		return nil, fmt.Errorf("嵌入式 ZIP 路径不能为空")
	}

	data, err := fs.ReadFile(archive, targetPath)
	if err != nil {
		return nil, fmt.Errorf("读取嵌入式 ZIP 失败: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("解析嵌入式 ZIP 失败: %w", err)
	}

	files := make(map[string]*memoryFile, len(reader.File))
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if !matchesSubPath("/"+file.Name, config.SubPaths) {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("打开嵌入式 ZIP 文件失败: %w", err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("读取嵌入式 ZIP 文件失败: %w", err)
		}

		files[file.Name] = &memoryFile{
			name:    file.Name,
			data:    content,
			modTime: file.Modified,
		}
	}

	return &embeddedZipFileSystem{
		files:    files,
		subPaths: config.SubPaths,
	}, nil
}
