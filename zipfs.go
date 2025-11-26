package gin

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	yekazip "github.com/yeka/zip"
)

// passwordProtectedZipFS 密码保护的zip文件系统
type passwordProtectedZipFS struct {
	zipPath  string
	password string
	subPaths []string
	files    map[string]*memoryFile
	mu       sync.RWMutex
}

func newPasswordProtectedZipFS(zipPath, password string, subPaths []string) (*passwordProtectedZipFS, error) {
	pzfs := &passwordProtectedZipFS{
		zipPath:  zipPath,
		password: password,
		subPaths: subPaths,
		files:    make(map[string]*memoryFile),
	}
	if err := pzfs.load(); err != nil {
		return nil, err
	}
	return pzfs, nil
}

// Open 实现http.FileSystem接口
func (pzfs *passwordProtectedZipFS) Open(name string) (http.File, error) {
	name = strings.TrimPrefix(name, "/")

	if !pzfs.isValidSubPath("/" + name) {
		return nil, os.ErrNotExist
	}

	pzfs.mu.RLock()
	mf, ok := pzfs.files[name]
	pzfs.mu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return mf.clone(), nil
}

// 预加载 zip 文件内容，只在初始化或热更新时调用
func (pzfs *passwordProtectedZipFS) load() error {
	yekaReader, err := yekazip.OpenReader(pzfs.zipPath)
	if err != nil {
		return fmt.Errorf("无法打开zip文件: %w", err)
	}
	defer func() { _ = yekaReader.Close() }()

	files := make(map[string]*memoryFile)

	for _, file := range yekaReader.File {
		// 跳过目录
		if file.FileInfo().IsDir() {
			continue
		}

		if !pzfs.isValidSubPath("/" + file.Name) {
			continue
		}

		if file.IsEncrypted() {
			file.SetPassword(pzfs.password)
		}

		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("无法打开zip中的文件: %w", err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return fmt.Errorf("读取文件内容失败: %w", err)
		}

		files[file.Name] = &memoryFile{
			name:    file.Name,
			data:    data,
			modTime: file.FileInfo().ModTime(),
		}
	}

	pzfs.mu.Lock()
	pzfs.files = files
	pzfs.mu.Unlock()

	return nil
}

// isValidSubPath 检查路径是否在允许的子路径中
func (pzfs *passwordProtectedZipFS) isValidSubPath(path string) bool {
	// 如果没有配置子路径限制，则允许所有路径
	if len(pzfs.subPaths) == 0 {
		return true
	}

	// 确保路径以/开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 检查路径是否匹配任一子路径前缀
	for _, subPath := range pzfs.subPaths {
		// 确保子路径以/开头
		if !strings.HasPrefix(subPath, "/") {
			subPath = "/" + subPath
		}

		// 精确匹配或前缀匹配
		if path == subPath || strings.HasPrefix(path, subPath+"/") || strings.HasPrefix(path, subPath) {
			return true
		}
	}

	return false
}

// memoryFile 内存中的文件实现
type memoryFile struct {
	name    string
	data    []byte
	offset  int64
	modTime time.Time
}

func (mf *memoryFile) clone() *memoryFile {
	return &memoryFile{
		name:    mf.name,
		data:    mf.data,
		offset:  0,
		modTime: mf.modTime,
	}
}

func (mf *memoryFile) Read(p []byte) (int, error) {
	if mf.offset >= int64(len(mf.data)) {
		return 0, io.EOF
	}
	n := copy(p, mf.data[mf.offset:])
	mf.offset += int64(n)
	return n, nil
}

func (mf *memoryFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		mf.offset = offset
	case io.SeekCurrent:
		mf.offset += offset
	case io.SeekEnd:
		mf.offset = int64(len(mf.data)) + offset
	}
	if mf.offset < 0 {
		mf.offset = 0
	}
	if mf.offset > int64(len(mf.data)) {
		mf.offset = int64(len(mf.data))
	}
	return mf.offset, nil
}

func (mf *memoryFile) Close() error {
	return nil
}

func (mf *memoryFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("不支持目录读取")
}

func (mf *memoryFile) Stat() (os.FileInfo, error) {
	return &memoryFileInfo{
		name:    mf.name,
		size:    int64(len(mf.data)),
		modTime: mf.modTime,
	}, nil
}

// memoryFileInfo 内存文件信息
type memoryFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (mfi *memoryFileInfo) Name() string       { return mfi.name }
func (mfi *memoryFileInfo) Size() int64        { return mfi.size }
func (mfi *memoryFileInfo) Mode() os.FileMode  { return 0o644 }
func (mfi *memoryFileInfo) ModTime() time.Time { return mfi.modTime }
func (mfi *memoryFileInfo) IsDir() bool        { return false }
func (mfi *memoryFileInfo) Sys() any           { return nil }

// ZipFSConfig zip文件系统配置
type ZipFSConfig struct {
	// 基础配置
	ZipPath   string   // zip文件路径
	URLPrefix string   // URL路径前缀
	SubPaths  []string // 子路径列表（可选）

	// 安全配置
	Password string // zip文件密码（可选）

	// 热更新配置
	HotReload     bool          // 是否启用热更新
	CheckInterval time.Duration // 检查间隔，默认3秒

	// 行为配置
	IndexFile   string // 首页文件名，默认index.html
	StripPrefix bool   // 是否移除URL前缀

	// 回退配置
	FallbackFS      http.FileSystem // 回退文件系统
	FallbackHandler gin.HandlerFunc // 回退处理器
}

// ZipFileConfig 单文件配置
type ZipFileConfig struct {
	Password      string        // zip文件密码（可选）
	HotReload     bool          // 是否启用热更新
	CheckInterval time.Duration // 检查间隔
	ContentType   string        // 内容类型
}

// ZipFileOption 单文件配置选项
type ZipFileOption func(*ZipFileConfig)

// ZipFileSystem zip文件系统管理器
type ZipFileSystem struct {
	config      ZipFSConfig
	fs          http.FileSystem
	zipReader   *zip.ReadCloser
	lastModTime time.Time
	mu          sync.RWMutex
	stopChan    chan struct{}
	isRunning   bool
	metrics     ZipFSMetrics
	logger      Logger
}

// ZipFile 单个zip文件管理器
type ZipFile struct {
	zipPath     string
	filePath    string
	config      *ZipFileConfig
	data        []byte
	contentType string
	lastModTime time.Time
	mu          sync.RWMutex
	stopChan    chan struct{}
	isRunning   bool
	logger      Logger
}

// ZipFSMetrics zip文件系统监控指标
type ZipFSMetrics struct {
	ReloadCount  int64     // 重载次数
	LastReload   time.Time // 最后重载时间
	ErrorCount   int64     // 错误次数
	RequestCount int64     // 请求次数
}

// NewZipFileSystem 创建新的zip文件系统
func NewZipFileSystem(config ZipFSConfig) (*ZipFileSystem, error) {
	// 参数验证
	if config.ZipPath == "" {
		return nil, fmt.Errorf("zip文件路径不能为空")
	}
	if config.URLPrefix == "" {
		return nil, fmt.Errorf("URL前缀不能为空")
	}

	// 设置默认值
	if config.CheckInterval == 0 {
		config.CheckInterval = 3 * time.Second
	}
	if config.IndexFile == "" {
		config.IndexFile = "index.html"
	}

	// 确保URL前缀格式正确
	if !strings.HasPrefix(config.URLPrefix, "/") {
		config.URLPrefix = "/" + config.URLPrefix
	}
	config.URLPrefix = strings.TrimSuffix(config.URLPrefix, "/")

	zfs := &ZipFileSystem{
		config: config,
		logger: NewGinCompatLogger("ZIP-FS"),
	}

	// 初始加载zip文件
	if err := zfs.loadZipFS(); err != nil {
		return nil, fmt.Errorf("初始加载zip文件失败: %w", err)
	}

	return zfs, nil
}

// NewZipFile 创建新的zip文件管理器
func NewZipFile(zipPath, filePath string, config *ZipFileConfig) (*ZipFile, error) {
	if zipPath == "" || filePath == "" {
		return nil, fmt.Errorf("zip文件路径和文件路径不能为空")
	}

	if config == nil {
		config = &ZipFileConfig{
			CheckInterval: 3 * time.Second,
		}
	}

	zf := &ZipFile{
		zipPath:  zipPath,
		filePath: filePath,
		config:   config,
		logger:   NewGinCompatLogger("ZIP-FILE"),
	}

	// 初始加载文件
	if err := zf.loadFile(); err != nil {
		return nil, fmt.Errorf("初始加载文件失败: %w", err)
	}

	return zf, nil
}

// loadZipFS 加载zip文件系统
func (zfs *ZipFileSystem) loadZipFS() error {
	// 获取文件信息
	stat, err := os.Stat(zfs.config.ZipPath)
	if err != nil {
		return fmt.Errorf("无法访问zip文件: %w", err)
	}

	// 关闭旧的读取器
	zfs.mu.Lock()
	if zfs.zipReader != nil {
		_ = zfs.zipReader.Close()
	}
	zfs.mu.Unlock()

	// 根据是否有密码选择不同的加载方式
	if zfs.config.Password != "" {
		pzfs, err := newPasswordProtectedZipFS(zfs.config.ZipPath, zfs.config.Password, zfs.config.SubPaths)
		if err != nil {
			return err
		}

		zfs.mu.Lock()
		zfs.zipReader = nil // 密码保护的zip不使用标准reader
		zfs.fs = pzfs
		zfs.lastModTime = stat.ModTime()
		zfs.metrics.ReloadCount++
		zfs.metrics.LastReload = time.Now()
		zfs.mu.Unlock()

		zfs.logger.Info("带密码的zip文件系统加载成功", "path", zfs.config.ZipPath)
	} else {
		// 使用标准库打开普通zip文件
		reader, err := zip.OpenReader(zfs.config.ZipPath)
		if err != nil {
			return fmt.Errorf("无法打开zip文件: %w", err)
		}

		// 创建文件系统（SubPaths仅作为访问控制，不创建子文件系统）
		fileSystem := http.FS(&reader.Reader)

		// 更新状态
		zfs.mu.Lock()
		zfs.zipReader = reader
		zfs.fs = fileSystem
		zfs.lastModTime = stat.ModTime()
		zfs.metrics.ReloadCount++
		zfs.metrics.LastReload = time.Now()
		zfs.mu.Unlock()

		zfs.logger.Info("zip文件系统加载成功", "path", zfs.config.ZipPath)
	}
	return nil
}

// loadFile 加载zip中的单个文件
func (zf *ZipFile) loadFile() error {
	// 获取zip文件信息
	stat, err := os.Stat(zf.zipPath)
	if err != nil {
		return fmt.Errorf("无法访问zip文件: %w", err)
	}

	var data []byte
	var contentType string

	// 根据是否有密码选择不同的打开方式
	if zf.config.Password != "" {
		// 使用yeka/zip库打开带密码的zip文件
		yekaReader, err := yekazip.OpenReader(zf.zipPath)
		if err != nil {
			return fmt.Errorf("无法打开zip文件: %w", err)
		}
		defer func() { _ = yekaReader.Close() }()

		// 查找目标文件
		var targetFile *yekazip.File
		for _, file := range yekaReader.File {
			if file.Name == zf.filePath {
				targetFile = file
				break
			}
		}

		if targetFile == nil {
			return fmt.Errorf("在zip文件中未找到文件: %s", zf.filePath)
		}

		// 如果文件是加密的，设置密码
		if targetFile.IsEncrypted() {
			targetFile.SetPassword(zf.config.Password)
		}

		// 读取文件内容
		rc, err := targetFile.Open()
		if err != nil {
			return fmt.Errorf("无法打开zip中的文件: %w", err)
		}
		defer func() { _ = rc.Close() }()

		data, err = io.ReadAll(rc)
		if err != nil {
			return fmt.Errorf("读取文件内容失败: %w", err)
		}
	} else {
		// 使用标准库打开普通zip文件
		reader, err := zip.OpenReader(zf.zipPath)
		if err != nil {
			return fmt.Errorf("无法打开zip文件: %w", err)
		}
		defer func() { _ = reader.Close() }()

		// 查找目标文件
		var targetFile *zip.File
		for _, file := range reader.File {
			if file.Name == zf.filePath {
				targetFile = file
				break
			}
		}

		if targetFile == nil {
			return fmt.Errorf("在zip文件中未找到文件: %s", zf.filePath)
		}

		// 读取文件内容
		rc, err := targetFile.Open()
		if err != nil {
			return fmt.Errorf("无法打开zip中的文件: %w", err)
		}
		defer func() { _ = rc.Close() }()

		data, err = io.ReadAll(rc)
		if err != nil {
			return fmt.Errorf("读取文件内容失败: %w", err)
		}
	}

	// 确定内容类型
	contentType = zf.config.ContentType
	if contentType == "" {
		contentType = detectContentType(zf.filePath, data)
	}

	// 更新状态
	zf.mu.Lock()
	zf.data = data
	zf.contentType = contentType
	zf.lastModTime = stat.ModTime()
	zf.mu.Unlock()

	if zf.config.Password != "" {
		zf.logger.Info("带密码的zip文件加载成功", "zip", zf.zipPath, "file", zf.filePath)
	} else {
		zf.logger.Info("zip文件加载成功", "zip", zf.zipPath, "file", zf.filePath)
	}
	return nil
}

// StartHotReload 启动热更新监控
func (zfs *ZipFileSystem) StartHotReload() {
	if !zfs.config.HotReload || zfs.isRunning {
		return
	}

	zfs.isRunning = true
	zfs.stopChan = make(chan struct{})

	go func() {
		ticker := time.NewTicker(zfs.config.CheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				zfs.checkAndReload()
			case <-zfs.stopChan:
				zfs.logger.Info("热更新监控已停止", "path", zfs.config.ZipPath)
				return
			}
		}
	}()

	zfs.logger.Info("热更新监控已启动", "interval", zfs.config.CheckInterval)
}

// StartHotReload 启动文件热更新监控
func (zf *ZipFile) StartHotReload() {
	if !zf.config.HotReload || zf.isRunning {
		return
	}

	zf.isRunning = true
	zf.stopChan = make(chan struct{})

	go func() {
		ticker := time.NewTicker(zf.config.CheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				zf.checkAndReload()
			case <-zf.stopChan:
				zf.logger.Info("文件热更新监控已停止", "path", zf.zipPath)
				return
			}
		}
	}()

	zf.logger.Info("文件热更新监控已启动", "interval", zf.config.CheckInterval)
}

// checkAndReload 检查并重载zip文件系统
func (zfs *ZipFileSystem) checkAndReload() {
	stat, err := os.Stat(zfs.config.ZipPath)
	if err != nil {
		zfs.mu.Lock()
		zfs.metrics.ErrorCount++
		zfs.mu.Unlock()
		zfs.logger.Error("检查zip文件状态失败", "error", err)
		return
	}

	zfs.mu.RLock()
	lastMod := zfs.lastModTime
	zfs.mu.RUnlock()

	if stat.ModTime().After(lastMod) {
		zfs.logger.Info("检测到zip文件更新，正在重载...", "path", zfs.config.ZipPath)
		if err := zfs.loadZipFS(); err != nil {
			zfs.mu.Lock()
			zfs.metrics.ErrorCount++
			zfs.mu.Unlock()
			zfs.logger.Error("重载zip文件失败", "error", err)
		} else {
			zfs.logger.Info("zip文件重载成功", "path", zfs.config.ZipPath)
		}
	}
}

// checkAndReload 检查并重载文件
func (zf *ZipFile) checkAndReload() {
	stat, err := os.Stat(zf.zipPath)
	if err != nil {
		zf.logger.Error("检查zip文件状态失败", "error", err)
		return
	}

	zf.mu.RLock()
	lastMod := zf.lastModTime
	zf.mu.RUnlock()

	if stat.ModTime().After(lastMod) {
		zf.logger.Info("检测到zip文件更新，正在重载文件...", "zip", zf.zipPath, "file", zf.filePath)
		if err := zf.loadFile(); err != nil {
			zf.logger.Error("重载文件失败", "error", err)
		} else {
			zf.logger.Info("文件重载成功", "zip", zf.zipPath, "file", zf.filePath)
		}
	}
}

// ServeHTTP 实现http.Handler接口
func (zfs *ZipFileSystem) ServeHTTP(c *gin.Context) {
	zfs.mu.RLock()
	fs := zfs.fs
	zfs.mu.RUnlock()

	// 增加请求计数
	zfs.mu.Lock()
	zfs.metrics.RequestCount++
	zfs.mu.Unlock()

	if fs == nil {
		zfs.handleFallback(c)
		return
	}

	path := c.Request.URL.Path

	// 移除URL前缀
	if zfs.config.URLPrefix != "" {
		path = strings.TrimPrefix(path, zfs.config.URLPrefix)
	}

	// 处理根路径重定向
	if path == "" || path == "/" {
		if zfs.config.IndexFile != "" {
			path = zfs.config.IndexFile
		} else {
			path = "index.html" // 默认首页
		}
	} else {
		// 移除开头的斜杠，因为zip文件中的路径通常不以/开头
		path = strings.TrimPrefix(path, "/")
	}

	// 子路径验证（使用带/的路径进行验证）
	validatePath := "/" + path
	if !zfs.isValidSubPath(validatePath) {
		zfs.logger.Debug("子路径验证失败", "path", path, "validatePath", validatePath, "subPaths", zfs.config.SubPaths)
		c.Status(http.StatusNotFound)
		return
	}

	// 尝试从zip文件系统打开文件
	file, err := fs.Open(path)
	if err != nil {
		zfs.logger.Debug("文件打开失败", "path", path, "error", err)
		c.Status(http.StatusNotFound)
		return
	}
	defer func() { _ = file.Close() }()

	// 获取文件信息
	stat, err := file.Stat()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	// 检查是否是目录
	if stat.IsDir() {
		// 如果是目录，尝试查找索引文件
		indexPath := path
		if indexPath != "" {
			indexPath += "/"
		}
		indexPath += zfs.config.IndexFile

		indexFile, err := fs.Open(indexPath)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		defer func() { _ = indexFile.Close() }()

		indexStat, err := indexFile.Stat()
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}

		file = indexFile
		stat = indexStat
		path = indexPath
	}

	// 读取文件头部少量数据用于类型检测，使用 MultiReader 避免额外内存占用
	peekSize := int64(512)
	if stat.Size() >= 0 && stat.Size() < peekSize {
		peekSize = stat.Size()
	}
	var sample []byte
	reader := io.Reader(file)
	if peekSize > 0 {
		buf := make([]byte, int(peekSize))
		limited := io.LimitReader(file, peekSize)
		n, err := io.ReadFull(limited, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			c.Status(http.StatusInternalServerError)
			return
		}
		sample = buf[:n]
		reader = io.MultiReader(bytes.NewReader(sample), file)
	}

	contentType := detectContentType(path, sample)
	if contentType != "" {
		c.Header("Content-Type", contentType)
	}

	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, reader); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
}

// ServeHTTP 文件服务处理
func (zf *ZipFile) ServeHTTP(c *gin.Context) {
	zf.mu.RLock()
	data := zf.data
	contentType := zf.contentType
	zf.mu.RUnlock()

	if data == nil {
		c.Status(http.StatusNotFound)
		return
	}

	c.Header("Content-Type", contentType)
	c.Data(http.StatusOK, contentType, data)
}

// handleFallback 处理回退逻辑
func (zfs *ZipFileSystem) handleFallback(c *gin.Context) {
	if zfs.config.FallbackHandler != nil {
		zfs.config.FallbackHandler(c)
		return
	}

	if zfs.config.FallbackFS != nil {
		http.FileServer(zfs.config.FallbackFS).ServeHTTP(c.Writer, c.Request)
		return
	}

	c.JSON(http.StatusServiceUnavailable, H{
		"error": "zip文件系统不可用",
		"path":  zfs.config.ZipPath,
	})
}

// isValidSubPath 检查路径是否在允许的子路径中
func (zfs *ZipFileSystem) isValidSubPath(path string) bool {
	// 如果没有配置子路径限制，则允许所有路径
	if len(zfs.config.SubPaths) == 0 {
		return true
	}

	// 确保路径以/开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 检查路径是否匹配任一子路径前缀
	for _, subPath := range zfs.config.SubPaths {
		// 确保子路径以/开头
		if !strings.HasPrefix(subPath, "/") {
			subPath = "/" + subPath
		}

		// 精确匹配或前缀匹配
		if path == subPath || strings.HasPrefix(path, subPath+"/") || strings.HasPrefix(path, subPath) {
			return true
		}
	}

	return false
}

// Stop 停止热更新监控
func (zfs *ZipFileSystem) Stop() {
	if zfs.isRunning {
		close(zfs.stopChan)
		zfs.isRunning = false
	}

	// 关闭zip读取器
	zfs.mu.Lock()
	if zfs.zipReader != nil {
		_ = zfs.zipReader.Close()
		zfs.zipReader = nil
	}
	zfs.mu.Unlock()
}

// Stop 停止文件热更新监控
func (zf *ZipFile) Stop() {
	if zf.isRunning {
		close(zf.stopChan)
		zf.isRunning = false
	}
}

// GetMetrics 获取监控指标
func (zfs *ZipFileSystem) GetMetrics() ZipFSMetrics {
	zfs.mu.RLock()
	defer zfs.mu.RUnlock()
	return zfs.metrics
}

// detectContentType 检测内容类型
func detectContentType(filename string, data []byte) string {
	// 首先根据扩展名检测
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	}

	// 如果扩展名不能确定类型，使用内容检测
	return http.DetectContentType(data)
}

// ========== 配置选项函数 ==========

// WithHotReload 启用热更新
func WithHotReload(interval time.Duration) func(*ZipFSConfig) {
	return func(config *ZipFSConfig) {
		config.HotReload = true
		config.CheckInterval = interval
	}
}

// WithIndexFile 设置首页文件
func WithIndexFile(filename string) func(*ZipFSConfig) {
	return func(config *ZipFSConfig) {
		config.IndexFile = filename
	}
}

// WithFallback 设置回退处理器
func WithFallback(handler gin.HandlerFunc) func(*ZipFSConfig) {
	return func(config *ZipFSConfig) {
		config.FallbackHandler = handler
	}
}

// WithSubPaths 设置子路径限制
func WithSubPaths(paths ...string) func(*ZipFSConfig) {
	return func(config *ZipFSConfig) {
		config.SubPaths = paths
	}
}

// WithPassword 设置zip文件密码
func WithPassword(password string) func(*ZipFSConfig) {
	return func(config *ZipFSConfig) {
		config.Password = password
	}
}

// NewZipFSConfig 创建zip文件系统配置
func NewZipFSConfig(zipPath, urlPrefix string, opts ...func(*ZipFSConfig)) ZipFSConfig {
	config := ZipFSConfig{
		ZipPath:       zipPath,
		URLPrefix:     urlPrefix,
		CheckInterval: 3 * time.Second,
		IndexFile:     "index.html",
		StripPrefix:   true,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return config
}

// ========== 单文件选项函数 ==========

// WithFileHotReload 启用文件热更新
func WithFileHotReload(interval time.Duration) ZipFileOption {
	return func(config *ZipFileConfig) {
		config.HotReload = true
		config.CheckInterval = interval
	}
}

// WithContentType 设置内容类型
func WithContentType(contentType string) ZipFileOption {
	return func(config *ZipFileConfig) {
		config.ContentType = contentType
	}
}

// WithFilePassword 设置单文件zip密码
func WithFilePassword(password string) ZipFileOption {
	return func(config *ZipFileConfig) {
		config.Password = password
	}
}
