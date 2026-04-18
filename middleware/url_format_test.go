package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darkit/gin"
)

func TestURLFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestPath    string
		routePath      string
		expectedFormat string
		expectedMatch  bool
	}{
		{
			name:           "JSON format",
			requestPath:    "/articles/123.json",
			routePath:      "/articles/:id",
			expectedFormat: "json",
			expectedMatch:  true,
		},
		{
			name:           "XML format",
			requestPath:    "/articles/123.xml",
			routePath:      "/articles/:id",
			expectedFormat: "xml",
			expectedMatch:  true,
		},
		{
			name:           "No format",
			requestPath:    "/articles/123",
			routePath:      "/articles/:id",
			expectedFormat: "",
			expectedMatch:  true,
		},
		{
			name:           "CSV format",
			requestPath:    "/users/export.csv",
			routePath:      "/users/*path", // 使用通配符匹配
			expectedFormat: "csv",
			expectedMatch:  true,
		},
		{
			name:           "Path with dots",
			requestPath:    "/files/document.tar.gz",
			routePath:      "/files/*path", // 使用通配符匹配
			expectedFormat: "gz",
			expectedMatch:  true,
		},
		{
			name:           "HTML format",
			requestPath:    "/page.html",
			routePath:      "/*path", // 使用通配符匹配
			expectedFormat: "html",
			expectedMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(URLFormat())

			var receivedFormat string

			router.GET(tt.routePath, func(c *gin.Context) {
				receivedFormat = GetURLFormat(c)
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.requestPath, nil)
			router.ServeHTTP(w, req)

			if tt.expectedMatch {
				if w.Code != 200 {
					t.Errorf("status code = %d, want 200", w.Code)
				}

				if receivedFormat != tt.expectedFormat {
					t.Errorf("format = %q, want %q", receivedFormat, tt.expectedFormat)
				}
			} else {
				if w.Code == 200 {
					t.Error("expected route not to match, but it did")
				}
			}
		})
	}
}

func TestGetURLFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(URLFormat())

	router.GET("/*path", func(c *gin.Context) {
		format := GetURLFormat(c)
		c.String(200, format)
	})

	tests := []struct {
		name           string
		path           string
		expectedFormat string
	}{
		{
			name:           "json extension",
			path:           "/test.json",
			expectedFormat: "json",
		},
		{
			name:           "xml extension",
			path:           "/test.xml",
			expectedFormat: "xml",
		},
		{
			name:           "no extension",
			path:           "/test",
			expectedFormat: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			router.ServeHTTP(w, req)

			if w.Body.String() != tt.expectedFormat {
				t.Errorf("response = %q, want %q", w.Body.String(), tt.expectedFormat)
			}
		})
	}
}

func TestGetURLFormat_NoMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	// 没有使用 URLFormat 中间件

	router.GET("/test", func(c *gin.Context) {
		format := GetURLFormat(c)
		if format != "" {
			t.Errorf("format = %q, want empty string", format)
		}
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
}

func TestURLFormatWithFormats(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		allowedFormats []string
		requestPath    string
		routePath      string
		expectedFormat string
		shouldStripExt bool
		expectedCode   int
	}{
		{
			name:           "allowed format - json",
			allowedFormats: []string{"json", "xml"},
			requestPath:    "/articles/123.json",
			routePath:      "/articles/*path", // 使用通配符匹配
			expectedFormat: "json",
			shouldStripExt: true,
			expectedCode:   200,
		},
		{
			name:           "allowed format - xml",
			allowedFormats: []string{"json", "xml"},
			requestPath:    "/articles/123.xml",
			routePath:      "/articles/*path", // 使用通配符匹配
			expectedFormat: "xml",
			shouldStripExt: true,
			expectedCode:   200,
		},
		{
			name:           "disallowed format - csv",
			allowedFormats: []string{"json", "xml"},
			requestPath:    "/articles/123.csv",
			routePath:      "/articles/*path", // 使用通配符匹配
			expectedFormat: "",
			shouldStripExt: false,
			expectedCode:   200, // 路由正常匹配，只是格式未被识别
		},
		{
			name:           "disallowed format - tar.gz",
			allowedFormats: []string{"json", "xml"},
			requestPath:    "/files/document.tar.gz",
			routePath:      "/files/*path", // 使用通配符匹配
			expectedFormat: "",
			shouldStripExt: false,
			expectedCode:   200, // 路由正常匹配，只是格式未被识别
		},
		{
			name:           "no extension",
			allowedFormats: []string{"json", "xml"},
			requestPath:    "/articles/123",
			routePath:      "/articles/:id",
			expectedFormat: "",
			shouldStripExt: false,
			expectedCode:   200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(URLFormatWithFormats(tt.allowedFormats...))

			var receivedFormat string

			router.GET(tt.routePath, func(c *gin.Context) {
				receivedFormat = GetURLFormat(c)
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.requestPath, nil)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}

			if w.Code == 200 && receivedFormat != tt.expectedFormat {
				t.Errorf("format = %q, want %q", receivedFormat, tt.expectedFormat)
			}
		})
	}
}

func TestURLFormat_MultipleFormats(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(URLFormat())

	results := make(map[string]string)

	router.GET("/articles/*path", func(c *gin.Context) {
		// 从路径中提取 ID
		path := c.Param("path")
		format := GetURLFormat(c)

		// 移除前导斜杠和格式后缀
		id := strings.TrimPrefix(path, "/")
		if format != "" {
			id = strings.TrimSuffix(id, "."+format)
		}

		results[id] = format
		c.String(200, "ok")
	})

	testCases := []struct {
		path   string
		id     string
		format string
	}{
		{"/articles/1.json", "1", "json"},
		{"/articles/2.xml", "2", "xml"},
		{"/articles/3", "3", ""},
		{"/articles/4.csv", "4", "csv"},
	}

	for _, tc := range testCases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", tc.path, nil)
		router.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("path %s: status code = %d, want 200", tc.path, w.Code)
		}

		if results[tc.id] != tc.format {
			t.Errorf("path %s: format = %q, want %q", tc.path, results[tc.id], tc.format)
		}
	}
}

func TestURLFormat_EdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		path           string
		expectedFormat string
	}{
		{
			name:           "multiple dots in filename",
			path:           "/files/my.backup.file.json",
			expectedFormat: "json",
		},
		{
			name:           "dot in directory name",
			path:           "/api/v1.0/users/123.json",
			expectedFormat: "json",
		},
		{
			name:           "no slash after dot",
			path:           "/api.json",
			expectedFormat: "json",
		},
		{
			name:           "empty extension",
			path:           "/file.",
			expectedFormat: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(URLFormat())

			var receivedFormat string

			router.GET("/*path", func(c *gin.Context) {
				receivedFormat = GetURLFormat(c)
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			router.ServeHTTP(w, req)

			if receivedFormat != tt.expectedFormat {
				t.Errorf("format = %q, want %q", receivedFormat, tt.expectedFormat)
			}
		})
	}
}

// BenchmarkURLFormat 性能基准测试
func BenchmarkURLFormat(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(URLFormat())

	router.GET("/test", func(c *gin.Context) {
		_ = GetURLFormat(c)
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test.json", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}

// BenchmarkURLFormatWithFormats 白名单模式性能测试
func BenchmarkURLFormatWithFormats(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(URLFormatWithFormats("json", "xml", "csv"))

	router.GET("/test", func(c *gin.Context) {
		_ = GetURLFormat(c)
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test.json", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}
