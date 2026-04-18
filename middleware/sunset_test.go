package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/darkit/gin"
)

func TestSunset(t *testing.T) {
	gin.SetMode(gin.TestMode)

	sunsetTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	expectedDate := sunsetTime.Format(http.TimeFormat)

	tests := []struct {
		name            string
		sunsetAt        time.Time
		links           []string
		expectSunset    bool
		expectLinkCount int
	}{
		{
			name:            "with sunset time and single link",
			sunsetAt:        sunsetTime,
			links:           []string{"<https://api.example.com/v2>; rel=\"successor-version\""},
			expectSunset:    true,
			expectLinkCount: 1,
		},
		{
			name:     "with sunset time and multiple links",
			sunsetAt: sunsetTime,
			links: []string{
				"<https://api.example.com/v2>; rel=\"successor-version\"",
				"<https://docs.example.com/migration>; rel=\"alternate\"",
			},
			expectSunset:    true,
			expectLinkCount: 2,
		},
		{
			name:            "with sunset time but no links",
			sunsetAt:        sunsetTime,
			links:           nil,
			expectSunset:    true,
			expectLinkCount: 0,
		},
		{
			name:            "without sunset time (zero value)",
			sunsetAt:        time.Time{},
			links:           []string{"<https://api.example.com/v2>; rel=\"successor-version\""},
			expectSunset:    false,
			expectLinkCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(Sunset(tt.sunsetAt, tt.links...))

			router.GET("/test", func(c *gin.Context) {
				c.String(200, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Errorf("status code = %d, want 200", w.Code)
			}

			// 检查 Sunset 头
			if tt.expectSunset {
				if sunset := w.Header().Get("Sunset"); sunset != expectedDate {
					t.Errorf("Sunset header = %q, want %q", sunset, expectedDate)
				}
				if deprecation := w.Header().Get("Deprecation"); deprecation != expectedDate {
					t.Errorf("Deprecation header = %q, want %q", deprecation, expectedDate)
				}
			} else {
				if sunset := w.Header().Get("Sunset"); sunset != "" {
					t.Errorf("Sunset header should not be set, got %q", sunset)
				}
				if deprecation := w.Header().Get("Deprecation"); deprecation != "" {
					t.Errorf("Deprecation header should not be set, got %q", deprecation)
				}
			}

			// 检查 Link 头数量
			links := w.Header().Values("Link")
			if len(links) != tt.expectLinkCount {
				t.Errorf("Link header count = %d, want %d", len(links), tt.expectLinkCount)
			}

			// 验证 Link 头内容
			if tt.expectLinkCount > 0 {
				for i, expectedLink := range tt.links {
					if i < len(links) && links[i] != expectedLink {
						t.Errorf("Link[%d] = %q, want %q", i, links[i], expectedLink)
					}
				}
			}
		})
	}
}

// TestSunset_Group 测试在路由组中使用
func TestSunset_Group(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()

	sunsetTime := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	v1 := router.Group("/v1")
	v1.Use(Sunset(
		sunsetTime,
		"<https://api.example.com/v2>; rel=\"successor-version\"",
	))

	v1.GET("/users", func(c *gin.Context) {
		c.JSON(200, gin.H{"version": "v1"})
	})

	v2 := router.Group("/v2")
	v2.GET("/users", func(c *gin.Context) {
		c.JSON(200, gin.H{"version": "v2"})
	})

	// 测试 v1 端点应该有 Sunset 头
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/users", nil)
	router.ServeHTTP(w, req)

	if w.Header().Get("Sunset") == "" {
		t.Error("v1 endpoint should have Sunset header")
	}
	if w.Header().Get("Deprecation") == "" {
		t.Error("v1 endpoint should have Deprecation header")
	}
	if len(w.Header().Values("Link")) != 1 {
		t.Error("v1 endpoint should have one Link header")
	}

	// 测试 v2 端点不应该有 Sunset 头
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/v2/users", nil)
	router.ServeHTTP(w, req)

	if w.Header().Get("Sunset") != "" {
		t.Error("v2 endpoint should not have Sunset header")
	}
	if w.Header().Get("Deprecation") != "" {
		t.Error("v2 endpoint should not have Deprecation header")
	}
	if len(w.Header().Values("Link")) != 0 {
		t.Error("v2 endpoint should not have Link headers")
	}
}

// TestSunset_FormatValidation 验证 HTTP-date 格式
func TestSunset_FormatValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	sunsetTime := time.Date(2025, 3, 15, 14, 30, 0, 0, time.UTC)

	router := gin.New()
	router.Use(Sunset(sunsetTime))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	sunset := w.Header().Get("Sunset")

	// 尝试解析为 HTTP-date 格式
	parsed, err := time.Parse(http.TimeFormat, sunset)
	if err != nil {
		t.Errorf("Sunset header is not valid HTTP-date format: %v", err)
	}

	// 验证解析后的时间与原时间一致
	if !parsed.Equal(sunsetTime) {
		t.Errorf("parsed time = %v, want %v", parsed, sunsetTime)
	}
}

// BenchmarkSunset 性能基准测试
func BenchmarkSunset(b *testing.B) {
	gin.SetMode(gin.TestMode)

	sunsetTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	router := gin.New()
	router.Use(Sunset(
		sunsetTime,
		"<https://api.example.com/v2>; rel=\"successor-version\"",
	))

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		w.Header().Del("Sunset")
		w.Header().Del("Deprecation")
		w.Header().Del("Link")
		router.ServeHTTP(w, req)
	}
}
