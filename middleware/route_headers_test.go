package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/darkit/gin"
)

func TestRouteHeaders_Route(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var executedMiddleware string

	mw1 := func(c *gin.Context) {
		executedMiddleware = "mw1"
		c.Next()
	}

	mw2 := func(c *gin.Context) {
		executedMiddleware = "mw2"
		c.Next()
	}

	router := gin.New()
	router.Use(RouteHeaders().
		Route("X-API-Version", "v1", mw1).
		Route("X-API-Version", "v2", mw2).
		Handler())

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	tests := []struct {
		name               string
		headerValue        string
		expectedMiddleware string
	}{
		{
			name:               "match v1",
			headerValue:        "v1",
			expectedMiddleware: "mw1",
		},
		{
			name:               "match v2",
			headerValue:        "v2",
			expectedMiddleware: "mw2",
		},
		{
			name:               "no match",
			headerValue:        "v3",
			expectedMiddleware: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executedMiddleware = ""
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-API-Version", tt.headerValue)

			router.ServeHTTP(w, req)

			if executedMiddleware != tt.expectedMiddleware {
				t.Errorf("executed middleware = %q, want %q", executedMiddleware, tt.expectedMiddleware)
			}

			if w.Code != 200 {
				t.Errorf("status code = %d, want 200", w.Code)
			}
		})
	}
}

func TestRouteHeaders_RouteAny(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var executedMiddleware string

	mobileMW := func(c *gin.Context) {
		executedMiddleware = "mobile"
		c.Next()
	}

	desktopMW := func(c *gin.Context) {
		executedMiddleware = "desktop"
		c.Next()
	}

	router := gin.New()
	router.Use(RouteHeaders().
		RouteAny("User-Agent", []string{"*Mobile*", "*Android*", "*iPhone*"}, mobileMW).
		Route("User-Agent", "*", desktopMW).
		Handler())

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	tests := []struct {
		name               string
		userAgent          string
		expectedMiddleware string
	}{
		{
			name:               "mobile - contains Mobile",
			userAgent:          "Mozilla/5.0 (Mobile; rv:26.0) Gecko/26.0 Firefox/26.0",
			expectedMiddleware: "mobile",
		},
		{
			name:               "mobile - contains Android",
			userAgent:          "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
			expectedMiddleware: "mobile",
		},
		{
			name:               "mobile - contains iPhone",
			userAgent:          "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
			expectedMiddleware: "mobile",
		},
		{
			name:               "desktop",
			userAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectedMiddleware: "desktop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executedMiddleware = ""
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("User-Agent", tt.userAgent)

			router.ServeHTTP(w, req)

			if executedMiddleware != tt.expectedMiddleware {
				t.Errorf("executed middleware = %q, want %q", executedMiddleware, tt.expectedMiddleware)
			}
		})
	}
}

func TestRouteHeaders_RouteDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var executedMiddleware string

	specificMW := func(c *gin.Context) {
		executedMiddleware = "specific"
		c.Next()
	}

	defaultMW := func(c *gin.Context) {
		executedMiddleware = "default"
		c.Next()
	}

	router := gin.New()
	router.Use(RouteHeaders().
		Route("X-Special", "yes", specificMW).
		RouteDefault(defaultMW).
		Handler())

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	tests := []struct {
		name               string
		headerValue        string
		expectedMiddleware string
	}{
		{
			name:               "specific match",
			headerValue:        "yes",
			expectedMiddleware: "specific",
		},
		{
			name:               "no match - use default",
			headerValue:        "no",
			expectedMiddleware: "default",
		},
		{
			name:               "empty header - use default",
			headerValue:        "",
			expectedMiddleware: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executedMiddleware = ""
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.headerValue != "" {
				req.Header.Set("X-Special", tt.headerValue)
			}

			router.ServeHTTP(w, req)

			if executedMiddleware != tt.expectedMiddleware {
				t.Errorf("executed middleware = %q, want %q", executedMiddleware, tt.expectedMiddleware)
			}
		})
	}
}

func TestPattern_Match(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		value       string
		shouldMatch bool
	}{
		// 精确匹配
		{
			name:        "exact match",
			pattern:     "example.com",
			value:       "example.com",
			shouldMatch: true,
		},
		{
			name:        "exact no match",
			pattern:     "example.com",
			value:       "other.com",
			shouldMatch: false,
		},
		// 前缀匹配
		{
			name:        "prefix match",
			pattern:     "api.*",
			value:       "api.example.com",
			shouldMatch: true,
		},
		{
			name:        "prefix no match",
			pattern:     "api.*",
			value:       "web.example.com",
			shouldMatch: false,
		},
		// 后缀匹配
		{
			name:        "suffix match",
			pattern:     "*.example.com",
			value:       "api.example.com",
			shouldMatch: true,
		},
		{
			name:        "suffix no match",
			pattern:     "*.example.com",
			value:       "example.org",
			shouldMatch: false,
		},
		// 前后缀匹配
		{
			name:        "prefix and suffix match",
			pattern:     "api.*.com",
			value:       "api.example.com",
			shouldMatch: true,
		},
		{
			name:        "prefix and suffix no match",
			pattern:     "api.*.com",
			value:       "web.example.org",
			shouldMatch: false,
		},
		// 通配符 * 匹配任意
		{
			name:        "wildcard matches anything",
			pattern:     "*",
			value:       "any-value-here",
			shouldMatch: true,
		},
		// 包含匹配
		{
			name:        "contains match",
			pattern:     "*mobile*",
			value:       "Mozilla/5.0 (Mobile; rv:26.0)",
			shouldMatch: true,
		},
		{
			name:        "contains no match",
			pattern:     "*mobile*",
			value:       "Mozilla/5.0 (Windows NT 10.0)",
			shouldMatch: false,
		},
		// 大小写不敏感
		{
			name:        "case insensitive",
			pattern:     "Example.COM",
			value:       "example.com",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPattern(tt.pattern)
			matched := p.Match(tt.value)

			if matched != tt.shouldMatch {
				t.Errorf("pattern %q match %q = %v, want %v",
					tt.pattern, tt.value, matched, tt.shouldMatch)
			}
		})
	}
}

func TestRouteHeaders_HostBased(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var executedHandler string

	apiHandler := func(c *gin.Context) {
		executedHandler = "api"
		c.JSON(200, gin.H{"service": "api"})
	}

	webHandler := func(c *gin.Context) {
		executedHandler = "web"
		c.JSON(200, gin.H{"service": "web"})
	}

	router := gin.New()
	router.Use(RouteHeaders().
		Route("Host", "api.example.com", apiHandler).
		Route("Host", "*.example.com", webHandler).
		Handler())

	router.GET("/", func(c *gin.Context) {
		c.String(200, "default")
	})

	tests := []struct {
		name            string
		host            string
		expectedHandler string
	}{
		{
			name:            "api subdomain",
			host:            "api.example.com",
			expectedHandler: "api",
		},
		{
			name:            "web subdomain",
			host:            "web.example.com",
			expectedHandler: "web",
		},
		{
			name:            "other subdomain",
			host:            "blog.example.com",
			expectedHandler: "web",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executedHandler = ""
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host

			router.ServeHTTP(w, req)

			if executedHandler != tt.expectedHandler {
				t.Errorf("executed handler = %q, want %q", executedHandler, tt.expectedHandler)
			}
		})
	}
}

// BenchmarkRouteHeaders 性能基准测试
func BenchmarkRouteHeaders(b *testing.B) {
	gin.SetMode(gin.TestMode)

	mw := func(c *gin.Context) {
		c.Next()
	}

	router := gin.New()
	router.Use(RouteHeaders().
		Route("X-API-Version", "v1", mw).
		Route("X-API-Version", "v2", mw).
		Handler())

	router.GET("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Version", "v1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		router.ServeHTTP(w, req)
	}
}
