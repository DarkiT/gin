package middleware

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/darkit/gin"
)

// compressOptions 压缩配置选项
type compressOptions struct {
	level      int      // 压缩级别 1-9
	mimeTypes  []string // 允许压缩的 MIME 类型
	minLength  int      // 最小压缩长度（字节）
	algorithms []string // 支持的压缩算法，按优先级排序
}

// defaultCompressOptions 默认压缩选项
func defaultCompressOptions() *compressOptions {
	return &compressOptions{
		level: gzip.DefaultCompression,
		mimeTypes: []string{
			"text/html",
			"text/css",
			"text/javascript",
			"application/javascript",
			"application/json",
			"application/xml",
			"text/xml",
			"text/plain",
		},
		minLength:  1024, // 1KB
		algorithms: []string{"gzip"},
	}
}

// CompressOption 压缩选项函数
type CompressOption func(*compressOptions)

// WithCompressLevel 设置压缩级别（1-9）
// 1 = 最快速度，9 = 最高压缩率，默认为 gzip.DefaultCompression (-1)
func WithCompressLevel(level int) CompressOption {
	return func(o *compressOptions) {
		if level >= flate.NoCompression && level <= flate.BestCompression {
			o.level = level
		}
	}
}

// WithCompressTypes 设置允许压缩的 MIME 类型
func WithCompressTypes(types ...string) CompressOption {
	return func(o *compressOptions) {
		if len(types) > 0 {
			o.mimeTypes = types
		}
	}
}

// WithCompressMinLength 设置最小压缩长度（小于此长度不压缩）
func WithCompressMinLength(length int) CompressOption {
	return func(o *compressOptions) {
		if length > 0 {
			o.minLength = length
		}
	}
}

// WithCompressAlgorithm 设置压缩算法（gzip, deflate, br）
// 可多次调用以设置优先级顺序，如：WithCompressAlgorithm("br")、WithCompressAlgorithm("gzip")
// 实际使用时会根据客户端 Accept-Encoding 选择最佳匹配
func WithCompressAlgorithm(algo string) CompressOption {
	return func(o *compressOptions) {
		// 重置并设置新算法
		o.algorithms = []string{algo}
	}
}

// compressWriter 压缩写入器
type compressWriter struct {
	gin.ResponseWriter
	writer      io.Writer
	compressor  io.WriteCloser
	algorithm   string
	options     *compressOptions
	wroteHeader bool
	bodyBuf     []byte
	lastErr     error
}

// WriteHeader 写入响应头
func (w *compressWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	// 设置 Vary 头
	w.Header().Set("Vary", "Accept-Encoding")

	w.ResponseWriter.WriteHeader(code)
}

// Write 写入压缩数据
func (w *compressWriter) Write(data []byte) (int, error) {
	if w.lastErr != nil {
		return 0, w.lastErr
	}

	// 确保已写入 Header
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// 如果已经初始化了压缩器，直接写入
	if w.compressor != nil {
		return w.compressor.Write(data)
	}

	// 如果已经决定不压缩，直接写入
	if w.bodyBuf == nil {
		return w.ResponseWriter.Write(data)
	}

	// 缓存数据
	w.bodyBuf = append(w.bodyBuf, data...)

	// 检查是否满足压缩条件
	if w.shouldCompress() {
		// 初始化压缩器
		if err := w.initCompressor(); err != nil {
			// 初始化失败，直接写入原始数据
			n, err := w.ResponseWriter.Write(w.bodyBuf)
			w.bodyBuf = nil
			return n, err
		}

		// 设置 Content-Encoding
		w.Header().Set("Content-Encoding", w.algorithm)
		w.Header().Del("Content-Length")

		// 写入缓存的数据
		_, err := w.compressor.Write(w.bodyBuf)
		w.bodyBuf = nil

		// 返回原始数据的长度（这是 Write 的语义）
		return len(data), err
	}

	// 继续缓冲，返回写入的长度
	return len(data), nil
}

// WriteString 写入字符串
func (w *compressWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// Hijack 实现 http.Hijacker 接口
func (w *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush 实现 http.Flusher 接口
func (w *compressWriter) Flush() {
	if w.compressor != nil {
		if flusher, ok := w.compressor.(interface{ Flush() error }); ok {
			w.recordError(flusher.Flush())
		}
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Close 关闭压缩器
func (w *compressWriter) Close() error {
	var closeErr error

	// 如果有未写入的缓冲数据，写入到响应
	if len(w.bodyBuf) > 0 {
		if _, err := w.ResponseWriter.Write(w.bodyBuf); err != nil {
			closeErr = err
		}
		w.bodyBuf = nil
	}

	// 关闭压缩器
	if w.compressor != nil {
		if err := w.compressor.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if closeErr != nil {
		return closeErr
	}
	return w.lastErr
}

// shouldCompress 判断响应是否应该被压缩
func (w *compressWriter) shouldCompress() bool {
	// 检查是否已经有 Content-Encoding
	if w.Header().Get("Content-Encoding") != "" {
		return false
	}

	// 检查 Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType == "" && len(w.bodyBuf) > 0 {
		// 尝试检测 Content-Type
		contentType = http.DetectContentType(w.bodyBuf)
		w.Header().Set("Content-Type", contentType)
	}

	if contentType == "" {
		return false
	}

	// 提取主类型（去除参数）
	if idx := strings.Index(contentType, ";"); idx > 0 {
		contentType = contentType[:idx]
	}
	contentType = strings.TrimSpace(contentType)

	// 检查是否在白名单中
	found := false
	for _, mt := range w.options.mimeTypes {
		if strings.HasPrefix(contentType, mt) || contentType == mt {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// 检查内容长度
	contentLength := w.Header().Get("Content-Length")
	if contentLength != "" {
		length, err := strconv.Atoi(contentLength)
		if err == nil && length < w.options.minLength {
			return false
		}
	} else if len(w.bodyBuf) < w.options.minLength {
		// 如果没有 Content-Length，检查缓存数据的长度
		return false
	}

	return true
}

// initCompressor 初始化压缩器
func (w *compressWriter) initCompressor() error {
	var err error
	switch w.algorithm {
	case "br":
		w.compressor = brotli.NewWriterLevel(w.ResponseWriter, w.options.level)
	case "gzip":
		w.compressor, err = gzip.NewWriterLevel(w.ResponseWriter, w.options.level)
	case "deflate":
		w.compressor, err = flate.NewWriter(w.ResponseWriter, w.options.level)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	w.writer = w.compressor
	return nil
}

// Compress 响应压缩中间件
// 根据客户端 Accept-Encoding 请求头自动选择压缩算法（gzip/deflate/br）
// 仅压缩配置的 MIME 类型且长度超过最小值的响应
func Compress(opts ...CompressOption) gin.HandlerFunc {
	options := defaultCompressOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// 解析客户端支持的编码
		acceptEncoding := c.GetHeader("Accept-Encoding")
		if acceptEncoding == "" {
			c.Next()
			return
		}

		// 选择最佳压缩算法
		algorithm := selectBestEncoding(acceptEncoding, options.algorithms)
		if algorithm == "" {
			c.Next()
			return
		}

		// 创建包装 Writer
		cw := &compressWriter{
			ResponseWriter: c.Writer,
			algorithm:      algorithm,
			options:        options,
			bodyBuf:        make([]byte, 0, 512),
		}

		c.Writer = cw

		// 延迟关闭压缩器
		defer func() {
			if err := cw.Close(); err != nil {
				_ = c.Error(err)
			}
		}()

		// 处理请求
		c.Next()
	}
}

// recordError 记录首个压缩过程错误。
func (w *compressWriter) recordError(err error) {
	if err != nil && w.lastErr == nil {
		w.lastErr = err
	}
}

// selectBestEncoding 选择最佳压缩算法
// 根据客户端支持的编码和服务器配置的优先级选择
func selectBestEncoding(acceptEncoding string, algorithms []string) string {
	// 解析 Accept-Encoding 头
	encodings := parseAcceptEncoding(acceptEncoding)

	// 按照服务器配置的优先级查找
	for _, algo := range algorithms {
		if _, ok := encodings[algo]; ok {
			return algo
		}
	}

	return ""
}

// parseAcceptEncoding 解析 Accept-Encoding 请求头
// 返回支持的编码 map（不处理 q 值权重，简化实现）
func parseAcceptEncoding(header string) map[string]bool {
	encodings := make(map[string]bool)
	parts := strings.Split(header, ",")
	for _, part := range parts {
		// 移除空格和 q 值
		encoding := strings.TrimSpace(part)
		if idx := strings.Index(encoding, ";"); idx > 0 {
			encoding = encoding[:idx]
		}
		encoding = strings.TrimSpace(encoding)
		if encoding != "" && encoding != "*" {
			encodings[encoding] = true
		}
	}
	return encodings
}
