package middleware

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/darkit/gin"
)

// TestCompress_Gzip 测试 Gzip 压缩
func TestCompress_Gzip(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress())
	r.GET("/", func(c *gin.Context) {
		// 生成足够长的内容以触发压缩（超过 minLength）
		data := strings.Repeat("Hello, World! ", 100)
		c.String(http.StatusOK, data)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	// 检查响应头
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding=gzip, got %s", w.Header().Get("Content-Encoding"))
	}

	if w.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("expected Vary=Accept-Encoding, got %s", w.Header().Get("Vary"))
	}

	// 解压缩并验证内容
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			t.Errorf("failed to close gzip reader: %v", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read gzip data: %v", err)
	}

	expected := strings.Repeat("Hello, World! ", 100)
	if string(decompressed) != expected {
		t.Fatalf("decompressed content mismatch")
	}
}

// TestCompress_Deflate 测试 Deflate 压缩
func TestCompress_Deflate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressAlgorithm("deflate")))
	r.GET("/", func(c *gin.Context) {
		data := strings.Repeat("Test deflate compression. ", 100)
		c.String(http.StatusOK, data)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "deflate")
	r.ServeHTTP(w, req)

	// 检查响应头
	if w.Header().Get("Content-Encoding") != "deflate" {
		t.Fatalf("expected Content-Encoding=deflate, got %s", w.Header().Get("Content-Encoding"))
	}

	// 解压缩并验证内容
	fr := flate.NewReader(w.Body)
	defer func() {
		if closeErr := fr.Close(); closeErr != nil {
			t.Errorf("failed to close flate reader: %v", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("failed to read deflate data: %v", err)
	}

	expected := strings.Repeat("Test deflate compression. ", 100)
	if string(decompressed) != expected {
		t.Fatalf("decompressed content mismatch")
	}
}

// TestCompress_Brotli 测试 Brotli 压缩
func TestCompress_Brotli(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressAlgorithm("br")))
	r.GET("/", func(c *gin.Context) {
		data := strings.Repeat("Test brotli compression! ", 100)
		c.String(http.StatusOK, data)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "br")
	r.ServeHTTP(w, req)

	// 检查响应头
	if w.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("expected Content-Encoding=br, got %s", w.Header().Get("Content-Encoding"))
	}

	// 解压缩并验证内容
	br := brotli.NewReader(w.Body)
	decompressed, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("failed to read brotli data: %v", err)
	}

	expected := strings.Repeat("Test brotli compression! ", 100)
	if string(decompressed) != expected {
		t.Fatalf("decompressed content mismatch")
	}
}

// TestCompress_MinLength 测试最小长度限制
func TestCompress_MinLength(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressMinLength(2048))) // 设置最小长度为 2KB
	r.GET("/short", func(c *gin.Context) {
		c.String(http.StatusOK, "short response")
	})
	r.GET("/long", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("long response ", 200))
	})

	// 测试短响应（不应压缩）
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/short", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("short response should not be compressed")
	}

	if w.Body.String() != "short response" {
		t.Fatalf("short response content mismatch")
	}

	// 测试长响应（应该压缩）
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/long", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("long response should be compressed")
	}
}

// TestCompress_MimeType 测试 MIME 类型过滤
func TestCompress_MimeType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(
		WithCompressTypes("application/json"),
		WithCompressMinLength(100),
	))

	r.GET("/json", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": strings.Repeat("test ", 50),
		})
	})

	r.GET("/image", func(c *gin.Context) {
		c.Data(http.StatusOK, "image/png", []byte(strings.Repeat("x", 2000)))
	})

	// 测试 JSON（应该压缩）
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/json", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("JSON response should be compressed")
	}

	// 测试图片（不应压缩）
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/image", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("image response should not be compressed")
	}
}

// TestCompress_AcceptEncoding 测试内容协商
func TestCompress_AcceptEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressAlgorithm("gzip")))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("content negotiation test ", 100))
	})

	tests := []struct {
		name             string
		acceptEncoding   string
		expectedEncoding string
	}{
		{
			name:             "支持 gzip",
			acceptEncoding:   "gzip, deflate, br",
			expectedEncoding: "gzip",
		},
		{
			name:             "仅支持 gzip",
			acceptEncoding:   "gzip",
			expectedEncoding: "gzip",
		},
		{
			name:             "不支持压缩",
			acceptEncoding:   "",
			expectedEncoding: "",
		},
		{
			name:             "不匹配的编码",
			acceptEncoding:   "compress, identity",
			expectedEncoding: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}
			r.ServeHTTP(w, req)

			encoding := w.Header().Get("Content-Encoding")
			if encoding != tt.expectedEncoding {
				t.Fatalf("expected Content-Encoding=%s, got %s", tt.expectedEncoding, encoding)
			}
		})
	}
}

// TestCompress_WithLevel 测试压缩级别
func TestCompress_WithLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	levels := []int{1, 5, 9}
	for _, level := range levels {
		t.Run(string(rune('0'+level)), func(t *testing.T) {
			r := gin.New()
			r.Use(Compress(WithCompressLevel(level)))
			r.GET("/", func(c *gin.Context) {
				c.String(http.StatusOK, strings.Repeat("compression level test ", 100))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			r.ServeHTTP(w, req)

			if w.Header().Get("Content-Encoding") != "gzip" {
				t.Fatalf("response should be compressed")
			}

			// 验证可以正确解压
			gr, err := gzip.NewReader(w.Body)
			if err != nil {
				t.Fatalf("failed to decompress: %v", err)
			}
			defer func() {
				if closeErr := gr.Close(); closeErr != nil {
					t.Errorf("failed to close gzip reader: %v", closeErr)
				}
			}()

			_, err = io.ReadAll(gr)
			if err != nil {
				t.Fatalf("failed to read decompressed data: %v", err)
			}
		})
	}
}

// TestCompress_NoAcceptEncoding 测试没有 Accept-Encoding 头的情况
func TestCompress_NoAcceptEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress())
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("test ", 200))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// 不设置 Accept-Encoding
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("response should not be compressed without Accept-Encoding")
	}
}

// TestCompress_AlreadyEncoded 测试已经编码的响应
func TestCompress_AlreadyEncoded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress())
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Encoding", "identity")
		c.String(http.StatusOK, strings.Repeat("test ", 200))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	// 应该保持原有的 Content-Encoding
	if w.Header().Get("Content-Encoding") != "identity" {
		t.Fatalf("expected Content-Encoding=identity, got %s", w.Header().Get("Content-Encoding"))
	}
}

// TestCompress_JSON 测试 JSON 响应压缩
func TestCompress_JSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressMinLength(100)))
	r.GET("/", func(c *gin.Context) {
		data := make([]string, 100)
		for i := range data {
			data[i] = "item"
		}
		c.JSON(http.StatusOK, gin.H{"items": data})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("JSON response should be compressed")
	}

	// 解压并验证是有效的 JSON
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			t.Errorf("failed to close gzip reader: %v", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if !bytes.Contains(decompressed, []byte("items")) {
		t.Fatalf("decompressed JSON is invalid")
	}
}

// TestCompress_MultipleWrites 测试多次写入
func TestCompress_MultipleWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(WithCompressMinLength(500))) // 降低最小长度
	r.GET("/", func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusOK)
		// 模拟多次写入，确保第一次写入的数据足够长
		for i := 0; i < 10; i++ {
			if _, err := c.Writer.Write([]byte(strings.Repeat("line ", 50))); err != nil {
				t.Fatalf("failed to write response chunk: %v", err)
			}
		}
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("response should be compressed")
	}

	// 验证可以正确解压
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			t.Errorf("failed to close gzip reader: %v", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	expected := strings.Repeat(strings.Repeat("line ", 50), 10)
	if string(decompressed) != expected {
		t.Fatalf("decompressed content mismatch")
	}
}

// BenchmarkCompress_Gzip 性能基准测试 - Gzip
func BenchmarkCompress_Gzip(b *testing.B) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress())
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("benchmark test data ", 100))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		r.ServeHTTP(w, req)
	}
}

// BenchmarkCompress_NoCompression 性能基准测试 - 无压缩
func BenchmarkCompress_NoCompression(b *testing.B) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("benchmark test data ", 100))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		r.ServeHTTP(w, req)
	}
}

// TestCompress_WriteString 测试 WriteString 方法
func TestCompress_WriteString(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress())
	r.GET("/", func(c *gin.Context) {
		// 使用 WriteString
		if _, err := c.Writer.WriteString(strings.Repeat("test write string ", 100)); err != nil {
			t.Fatalf("failed to write string response: %v", err)
		}
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("response should be compressed")
	}

	// 解压验证
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			t.Errorf("failed to close gzip reader: %v", closeErr)
		}
	}()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	expected := strings.Repeat("test write string ", 100)
	if string(decompressed) != expected {
		t.Fatalf("content mismatch")
	}
}

// TestCompress_ErrorCases 测试错误情况
func TestCompress_ErrorCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 测试无效的压缩级别（应该被忽略，使用默认值）
	r := gin.New()
	r.Use(Compress(
		WithCompressLevel(-10), // 超出范围，应该被忽略
		WithCompressLevel(5),   // 有效值
	))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("test ", 300)) // 1500 字节
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("response should be compressed")
	}
}

// TestCompress_InvalidMinLength 测试无效的最小长度
func TestCompress_InvalidMinLength(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(Compress(
		WithCompressMinLength(-100), // 无效值，应该被忽略
	))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("test ", 300)) // 1500 字节
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	r.ServeHTTP(w, req)

	// 应该使用默认的最小长度（1024）
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("response should be compressed with default minLength")
	}
}
