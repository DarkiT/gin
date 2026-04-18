package static

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

// ServeMode 表示静态资源服务模式。
type ServeMode int

const (
	// ServeModeAssets 表示普通静态资源模式，文件未命中时直接返回未命中结果。
	ServeModeAssets ServeMode = iota
	// ServeModeSite 表示站点模式，可启用 history fallback 和自定义 404 页面。
	ServeModeSite
)

// ServeConfig 定义静态资源服务配置。
type ServeConfig struct {
	Mode            ServeMode
	IndexFile       string
	NotFoundFile    string
	HistoryFallback bool
}

// Option 定义静态资源配置选项。
type Option interface {
	applyZipFS(*ZipFSConfig)
	applyServe(*ServeConfig)
}

type option struct {
	zipFS func(*ZipFSConfig)
	serve func(*ServeConfig)
}

func (o option) applyZipFS(config *ZipFSConfig) {
	if o.zipFS != nil {
		o.zipFS(config)
	}
}

func (o option) applyServe(config *ServeConfig) {
	if o.serve != nil {
		o.serve(config)
	}
}

// Service 封装统一的静态资源服务行为。
type Service struct {
	fs     http.FileSystem
	config ServeConfig
}

// NewAssetsService 创建普通静态资源服务。
func NewAssetsService(fileSystem http.FileSystem, opts ...Option) *Service {
	config := defaultServeConfig(ServeModeAssets)
	applyServeOptions(&config, opts)
	config.Mode = ServeModeAssets
	return &Service{
		fs:     fileSystem,
		config: config,
	}
}

// NewSiteService 创建站点资源服务。
func NewSiteService(fileSystem http.FileSystem, opts ...Option) *Service {
	config := defaultServeConfig(ServeModeSite)
	applyServeOptions(&config, opts)
	config.Mode = ServeModeSite
	return &Service{
		fs:     fileSystem,
		config: config,
	}
}

func defaultServeConfig(mode ServeMode) ServeConfig {
	config := ServeConfig{
		Mode:      mode,
		IndexFile: "index.html",
	}
	if mode == ServeModeSite {
		config.HistoryFallback = true
	}
	return config
}

func applyServeOptions(config *ServeConfig, opts []Option) {
	if config == nil {
		return
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.applyServe(config)
	}
}

func applyZipFSOptions(config *ZipFSConfig, opts []Option) {
	if config == nil {
		return
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.applyZipFS(config)
	}
}

// ServeHTTP 实现 http.Handler 接口。
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.TryServeHTTP(w, r) {
		w.WriteHeader(http.StatusNotFound)
	}
}

// TryServeHTTP 尝试按当前请求路径提供静态资源。
func (s *Service) TryServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r == nil {
		return false
	}
	requestPath := "/"
	if r.URL != nil {
		requestPath = r.URL.Path
	}
	return s.TryServePath(w, r, requestPath)
}

// TryServePath 尝试按指定路径提供静态资源，返回是否已处理。
func (s *Service) TryServePath(w http.ResponseWriter, r *http.Request, requestPath string) bool {
	if s == nil || s.fs == nil || w == nil || r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	cleanPath, hadTrailingSlash := normalizeServePath(requestPath)
	if file, stat, filename, ok := s.resolveRequestedFile(cleanPath, hadTrailingSlash); ok {
		serveStaticFile(w, r, file, stat, filename, http.StatusOK)
		return true
	}

	if s.config.Mode == ServeModeSite && s.config.HistoryFallback && shouldHistoryFallback(r, cleanPath) {
		if file, stat, filename, ok := s.openRegularFile(s.config.IndexFile); ok {
			serveStaticFile(w, r, file, stat, filename, http.StatusOK)
			return true
		}
	}

	if s.config.NotFoundFile != "" {
		if file, stat, filename, ok := s.openRegularFile(s.config.NotFoundFile); ok {
			serveStaticFile(w, r, file, stat, filename, http.StatusNotFound)
			return true
		}
	}

	return false
}

func (s *Service) resolveRequestedFile(requestPath string, hadTrailingSlash bool) (http.File, os.FileInfo, string, bool) {
	relativePath := strings.TrimPrefix(requestPath, "/")
	if relativePath == "" {
		return s.openIndexFile("")
	}

	file, stat, filename, ok := s.openRegularFile(relativePath)
	if ok {
		return file, stat, filename, true
	}

	if hadTrailingSlash || path.Ext(relativePath) == "" {
		return s.openIndexFile(relativePath)
	}

	return nil, nil, "", false
}

func (s *Service) openIndexFile(base string) (http.File, os.FileInfo, string, bool) {
	if s.config.IndexFile == "" {
		return nil, nil, "", false
	}

	target := strings.Trim(strings.TrimSpace(base), "/")
	if target == "" {
		target = s.config.IndexFile
	} else {
		target += "/" + s.config.IndexFile
	}
	return s.openRegularFile(target)
}

func (s *Service) openRegularFile(name string) (http.File, os.FileInfo, string, bool) {
	target := strings.Trim(strings.TrimSpace(name), "/")
	if target == "" {
		return nil, nil, "", false
	}

	file, err := s.fs.Open(target)
	if err != nil {
		return nil, nil, "", false
	}

	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, "", false
	}
	if stat.IsDir() {
		_ = file.Close()
		return nil, nil, "", false
	}

	return file, stat, target, true
}

func normalizeServePath(raw string) (string, bool) {
	if raw == "" {
		return "/", false
	}

	hadTrailingSlash := strings.HasSuffix(raw, "/")
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}

	cleaned := path.Clean(raw)
	if cleaned == "." {
		cleaned = "/"
	}
	if cleaned == "/" {
		return "/", false
	}

	return cleaned, hadTrailingSlash
}

func shouldHistoryFallback(r *http.Request, requestPath string) bool {
	if requestPath == "" || requestPath == "/" {
		return true
	}
	if path.Ext(strings.TrimPrefix(requestPath, "/")) != "" {
		return false
	}

	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, file http.File, stat os.FileInfo, filename string, status int) {
	defer func() { _ = file.Close() }()

	if stat != nil {
		if !stat.ModTime().IsZero() {
			w.Header().Set("Last-Modified", stat.ModTime().UTC().Format(http.TimeFormat))
		}
		if stat.Size() >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
		}
	}

	sample, reader := prepareStaticReader(file)
	if contentType := detectContentType(filename, sample); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}

	_, _ = io.Copy(w, reader)
}

func prepareStaticReader(file http.File) ([]byte, io.Reader) {
	sample := make([]byte, 512)
	n, err := file.Read(sample)
	if err != nil && err != io.EOF {
		return nil, file
	}

	sample = sample[:n]
	if _, seekErr := file.Seek(0, io.SeekStart); seekErr == nil {
		return sample, file
	}

	return sample, io.MultiReader(bytes.NewReader(sample), file)
}
