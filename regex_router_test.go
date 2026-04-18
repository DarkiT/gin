package gin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCompilePattern 测试模式编译
func TestCompilePattern(t *testing.T) {
	tests := []struct {
		name           string
		pattern        string
		expectPanic    bool
		checkPath      string // 用于测试编译后的正则
		shouldMatch    bool
		expectedParams map[string]string
	}{
		{
			name:           "numeric id",
			pattern:        "/users/{id:[0-9]+}",
			checkPath:      "/users/123",
			shouldMatch:    true,
			expectedParams: map[string]string{"id": "123"},
		},
		{
			name:        "numeric id not match",
			pattern:     "/users/{id:[0-9]+}",
			checkPath:   "/users/abc",
			shouldMatch: false,
		},
		{
			name:           "slug without regex",
			pattern:        "/posts/{slug}",
			checkPath:      "/posts/hello-world",
			shouldMatch:    true,
			expectedParams: map[string]string{"slug": "hello-world"},
		},
		{
			name:        "slug should not cross slash",
			pattern:     "/posts/{slug}",
			checkPath:   "/posts/hello/world",
			shouldMatch: false,
		},
		{
			name:           "complex path with version",
			pattern:        "/api/v{version:[0-9]+}/users/{id:[0-9]+}",
			checkPath:      "/api/v2/users/123",
			shouldMatch:    true,
			expectedParams: map[string]string{"version": "2", "id": "123"},
		},
		{
			name:           "slug pattern",
			pattern:        "/posts/{slug:[a-z0-9-]+}",
			checkPath:      "/posts/hello-world-123",
			shouldMatch:    true,
			expectedParams: map[string]string{"slug": "hello-world-123"},
		},
		{
			name:           "wildcard at end",
			pattern:        "/files/{path:.*}",
			checkPath:      "/files/a/b/c.txt",
			shouldMatch:    true,
			expectedParams: map[string]string{"path": "a/b/c.txt"},
		},
		{
			name:        "missing closing brace",
			pattern:     "/users/{id",
			expectPanic: true,
		},
		{
			name:           "anonymous param name",
			pattern:        "/users/{}",
			checkPath:      "/users/123",
			shouldMatch:    true,
			expectedParams: map[string]string{"": "123"},
		},
		{
			name:        "duplicate param names",
			pattern:     "/users/{id}/posts/{id}",
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("expected panic but didn't get one")
					}
				}()
				compilePattern(tt.pattern)
				return
			}

			regex, params := compilePattern(tt.pattern)
			if regex == nil {
				t.Fatal("regex is nil")
			}

			if tt.checkPath != "" {
				matches := regex.FindStringSubmatch(tt.checkPath)
				matched := matches != nil

				if matched != tt.shouldMatch {
					t.Errorf("path %q match = %v, want %v", tt.checkPath, matched, tt.shouldMatch)
				}

				if matched && tt.expectedParams != nil {
					actualParams := make(map[string]string)
					for i, name := range params {
						if i+1 < len(matches) {
							actualParams[name] = matches[i+1]
						}
					}

					for key, expected := range tt.expectedParams {
						if actual, ok := actualParams[key]; !ok {
							t.Errorf("missing param %q", key)
						} else if actual != expected {
							t.Errorf("param %q = %q, want %q", key, actual, expected)
						}
					}
				}
			}
		})
	}
}

// TestRegexRouter_Match 测试路由匹配
func TestRegexRouter_Match(t *testing.T) {
	router := NewRegexRouter()

	var handlerCalled string
	handler := func(name string) HandlerFunc {
		return func(c *Context) {
			handlerCalled = name
		}
	}

	// 注册路由
	router.GET("/users/{id:[0-9]+}", handler("user-id"))
	router.GET("/posts/{slug:[a-z-]+}", handler("post-slug"))
	router.POST("/articles/{id:[0-9]+}", handler("article-post"))
	router.Any("/catch/{path:.*}", handler("catch-all"))

	tests := []struct {
		name            string
		method          string
		path            string
		shouldMatch     bool
		expectedParams  map[string]string
		expectedHandler string
	}{
		{
			name:            "match user id",
			method:          "GET",
			path:            "/users/123",
			shouldMatch:     true,
			expectedParams:  map[string]string{"id": "123"},
			expectedHandler: "user-id",
		},
		{
			name:        "user id not numeric",
			method:      "GET",
			path:        "/users/abc",
			shouldMatch: false,
		},
		{
			name:            "match post slug",
			method:          "GET",
			path:            "/posts/hello-world",
			shouldMatch:     true,
			expectedParams:  map[string]string{"slug": "hello-world"},
			expectedHandler: "post-slug",
		},
		{
			name:        "post slug with numbers",
			method:      "GET",
			path:        "/posts/hello123",
			shouldMatch: false,
		},
		{
			name:            "match article post",
			method:          "POST",
			path:            "/articles/456",
			shouldMatch:     true,
			expectedParams:  map[string]string{"id": "456"},
			expectedHandler: "article-post",
		},
		{
			name:        "wrong method",
			method:      "GET",
			path:        "/articles/456",
			shouldMatch: false,
		},
		{
			name:            "catch all route",
			method:          "DELETE",
			path:            "/catch/any/path/here",
			shouldMatch:     true,
			expectedParams:  map[string]string{"path": "any/path/here"},
			expectedHandler: "catch-all",
		},
		{
			name:        "no match",
			method:      "GET",
			path:        "/unknown/path",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled = ""
			handler, params, found := router.Match(tt.method, tt.path)

			if found != tt.shouldMatch {
				t.Errorf("Match() found = %v, want %v", found, tt.shouldMatch)
				return
			}

			if !found {
				return
			}

			// 验证参数
			if tt.expectedParams != nil {
				for key, expected := range tt.expectedParams {
					if actual, ok := params[key]; !ok {
						t.Errorf("missing param %q", key)
					} else if actual != expected {
						t.Errorf("param %q = %q, want %q", key, actual, expected)
					}
				}
			}

			router.root().paramsPool.Put(params)

			// 验证处理器
			if tt.expectedHandler != "" {
				// 创建真正的 gin.Context 来调用处理器
				gin.SetMode(gin.TestMode)
				w := httptest.NewRecorder()
				ginCtx, _ := gin.CreateTestContext(w)
				ginCtx.Request = httptest.NewRequest(tt.method, tt.path, nil)

				c := &Context{Context: ginCtx}
				handler(c)

				if handlerCalled != tt.expectedHandler {
					t.Errorf("handler called = %q, want %q", handlerCalled, tt.expectedHandler)
				}
			}
		})
	}
}

// TestRegexRouter_Handler 测试 NoRoute 处理器
func TestRegexRouter_Handler(t *testing.T) {
	router := NewRegexRouter()

	var callLog []string
	router.GET("/users/{id:[0-9]+}", func(c *Context) {
		id := c.Param("id")
		callLog = append(callLog, "handler:"+id)
		c.JSON(200, H{"id": id})
	})

	router.NotFound(func(c *Context) {
		callLog = append(callLog, "notfound")
		c.JSON(404, H{"error": "not found"})
	})

	handler := router.Handler()

	tests := []struct {
		name           string
		path           string
		expectHandler  bool
		expectNotFound bool
	}{
		{
			name:          "match route",
			path:          "/users/123",
			expectHandler: true,
		},
		{
			name:           "no match",
			path:           "/unknown",
			expectNotFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callLog = nil
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(w)
			ginCtx.Request = httptest.NewRequest("GET", tt.path, nil)

			c := &Context{Context: ginCtx}
			handler(c)

			if tt.expectHandler {
				if len(callLog) == 0 || !contains(callLog[0], "handler:") {
					t.Errorf("expected handler to be called, got log: %v", callLog)
				}
			}

			if tt.expectNotFound {
				if len(callLog) == 0 || callLog[0] != "notfound" {
					t.Errorf("expected notfound to be called, got log: %v", callLog)
				}
			}
		})
	}
}

// TestRegexRouter_Concurrency 测试并发安全性
func TestRegexRouter_Concurrency(t *testing.T) {
	router := NewRegexRouter()

	var wg sync.WaitGroup
	concurrency := 100

	// 并发注册路由
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			pattern := fmt.Sprintf("/route%d/{id:[0-9]+}", n)
			router.GET(pattern, func(c *Context) {
				c.JSON(200, H{"n": n})
			})
		}(i)
	}

	wg.Wait()

	// 并发匹配路由
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			path := fmt.Sprintf("/route%d/123", n)
			handler, params, found := router.Match("GET", path)
			if !found {
				t.Errorf("route %d not found", n)
				return
			}
			if params["id"] != "123" {
				t.Errorf("wrong id for route %d: %v", n, params)
			}
			if handler == nil {
				t.Errorf("nil handler for route %d", n)
			}
			router.root().paramsPool.Put(params)
		}(i)
	}

	wg.Wait()
}

// TestRegexRouter_Methods 测试各种 HTTP 方法
func TestRegexRouter_MultiLevelParams(t *testing.T) {
	router := NewRegexRouter()
	pattern := "/posts/{slug:[a-z0-9-]+}/{type:[a-z0-9-]+}/{name:[a-z0-9-]+}"
	router.GET(pattern, func(c *Context) {})

	path := "/posts/hello-world/tech/go"
	_, params, ok := router.Match("GET", path)
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["slug"] != "hello-world" || params["type"] != "tech" || params["name"] != "go" {
		t.Fatalf("正则参数=%v, 期望 slug=hello-world type=tech name=go", params)
	}
	router.root().paramsPool.Put(params)
}

func TestRegexRouter_GroupAndMiddleware(t *testing.T) {
	router := NewRegexRouter()

	var order []string
	rootMW := func(c *Context) {
		order = append(order, "root-before")
		c.Next()
		order = append(order, "root-after")
	}
	groupMW := func(c *Context) {
		order = append(order, "group-before")
		c.Next()
		order = append(order, "group-after")
	}

	router.Use(rootMW)
	api := router.Group("/api", groupMW)
	api.GET("/users/{id:[0-9]+}", func(c *Context) {
		order = append(order, "handler")
	})

	handler, params, ok := router.Match("GET", "/api/users/123")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["id"] != "123" {
		t.Fatalf("正则参数 id=%q, 期望=123", params["id"])
	}
	router.root().paramsPool.Put(params)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
	handler(&Context{Context: ctx})

	want := []string{"root-before", "group-before", "handler", "group-after", "root-after"}
	if len(order) != len(want) {
		t.Fatalf("中间件顺序=%v, 期望=%v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("中间件顺序=%v, 期望=%v", order, want)
		}
	}
}

func TestRegexRouter_Methods(t *testing.T) {
	router := NewRegexRouter()

	methods := []struct {
		name   string
		method string
		fn     func(string, ...HandlerFunc)
	}{
		{"GET", "GET", router.GET},
		{"POST", "POST", router.POST},
		{"PUT", "PUT", router.PUT},
		{"DELETE", "DELETE", router.DELETE},
		{"PATCH", "PATCH", router.PATCH},
		{"HEAD", "HEAD", router.HEAD},
		{"OPTIONS", "OPTIONS", router.OPTIONS},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			pattern := "/test/{id:[0-9]+}"
			m.fn(pattern, func(c *Context) {})

			_, _, found := router.Match(m.method, "/test/123")
			if !found {
				t.Errorf("route not found for method %s", m.method)
			}

			// 验证其他方法不匹配
			_, _, found = router.Match("INVALID", "/test/123")
			if found {
				t.Errorf("route should not match invalid method")
			}
		})
	}
}

// TestRegexRouter_Any 测试 Any 方法
func TestRegexRouter_Any(t *testing.T) {
	router := NewRegexRouter()

	router.Any("/any/{id:[0-9]+}", func(c *Context) {})

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			_, _, found := router.Match(method, "/any/123")
			if !found {
				t.Errorf("Any route should match method %s", method)
			}
		})
	}
}

// TestRegexRouter_ChiPatterns 全面测试 Chi 风格模式（复刻自 Chi 验证）
func TestRegexRouter_WildcardMustBeLast(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("预期 panic，但未发生")
		}
	}()
	compilePattern("/files/*/extra")
}

func TestRegexRouter_DuplicateParamKeys(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("预期 panic，但未发生")
		}
	}()
	compilePattern("/users/{id:[0-9]+}/{id:[0-9]+}")
}

func TestRegexRouter_MissingClosingBrace(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("预期 panic，但未发生")
		}
	}()
	compilePattern("/users/{id:[0-9]+")
}

func TestRegexRouter_ParamWithoutRegex(t *testing.T) {
	router := NewRegexRouter()
	router.GET("/posts/{slug}", func(c *Context) {})
	_, params, ok := router.Match("GET", "/posts/abc")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["slug"] != "abc" {
		t.Fatalf("正则参数 slug=%q, 期望=abc", params["slug"])
	}
	router.root().paramsPool.Put(params)
	_, _, ok = router.Match("GET", "/posts/a/b")
	if ok {
		t.Fatalf("正则路由不应跨 / 匹配")
	}
}

func TestRegexRouter_InternalCaptureGroupsDoNotBreakParams(t *testing.T) {
	router := NewRegexRouter()
	router.GET("/items/{kind:(foo|bar)}/{id:[0-9]+}", func(c *Context) {})

	_, params, ok := router.Match("GET", "/items/foo/42")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["kind"] != "foo" {
		t.Fatalf("kind=%q, 期望=foo", params["kind"])
	}
	if params["id"] != "42" {
		t.Fatalf("id=%q, 期望=42", params["id"])
	}
	router.root().paramsPool.Put(params)
}

func TestRegexRouter_ChiPriority(t *testing.T) {
	router := NewRegexRouter()

	var called string
	router.GET("/articles/search", func(c *Context) { called = "static" })
	router.GET("/articles/{id:[0-9]+}", func(c *Context) { called = "regex" })
	router.GET("/articles/{slug}", func(c *Context) { called = "param" })

	tests := []struct {
		path string
		want string
	}{
		{path: "/articles/search", want: "static"},
		{path: "/articles/123", want: "regex"},
		{path: "/articles/hello", want: "param"},
	}

	for _, tt := range tests {
		handler, params, ok := router.Match(http.MethodGet, tt.path)
		if !ok {
			t.Fatalf("path %s 未匹配", tt.path)
		}
		router.root().paramsPool.Put(params)

		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(w)
		ginCtx.Request = httptest.NewRequest(http.MethodGet, tt.path, nil)

		called = ""
		handler(&Context{Context: ginCtx})
		if called != tt.want {
			t.Fatalf("path %s handler=%s, 期望=%s", tt.path, called, tt.want)
		}
	}
}

func TestRegexRouter_RegexAnchorsTrimmed(t *testing.T) {
	router := NewRegexRouter()
	router.GET("/items/{id:^\\d+$}", func(c *Context) {})
	_, params, ok := router.Match("GET", "/items/123")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["id"] != "123" {
		t.Fatalf("正则参数 id=%q, 期望=123", params["id"])
	}
	router.root().paramsPool.Put(params)
}

func TestRegexRouter_WhitespacePattern(t *testing.T) {
	router := NewRegexRouter()
	router.GET(" /posts/{slug:[a-z0-9-]+} ", func(c *Context) {})
	_, _, ok := router.Match("GET", "/posts/hello-world")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
}

func TestRegexRouter_ChiPatterns(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		testPath    string
		shouldMatch bool
		params      map[string]string
	}{
		// 基础参数
		{
			name:        "basic param",
			pattern:     "/users/{id}",
			testPath:    "/users/123",
			shouldMatch: true,
			params:      map[string]string{"id": "123"},
		},
		{
			name:        "basic param not cross slash",
			pattern:     "/users/{id}",
			testPath:    "/users/123/posts",
			shouldMatch: false,
		},

		// 数字正则
		{
			name:        "numeric regex",
			pattern:     "/users/{id:[0-9]+}",
			testPath:    "/users/123",
			shouldMatch: true,
			params:      map[string]string{"id": "123"},
		},
		{
			name:        "numeric regex fail",
			pattern:     "/users/{id:[0-9]+}",
			testPath:    "/users/abc",
			shouldMatch: false,
		},

		// Slug 正则
		{
			name:        "slug regex",
			pattern:     "/posts/{slug:[a-z0-9-]+}",
			testPath:    "/posts/hello-world",
			shouldMatch: true,
			params:      map[string]string{"slug": "hello-world"},
		},
		{
			name:        "slug regex fail uppercase",
			pattern:     "/posts/{slug:[a-z0-9-]+}",
			testPath:    "/posts/Hello-World",
			shouldMatch: false,
		},
		{
			name:        "slug regex fail underscore",
			pattern:     "/posts/{slug:[a-z0-9-]+}",
			testPath:    "/posts/hello_world",
			shouldMatch: false,
		},

		// UUID 正则
		{
			name:        "uuid regex",
			pattern:     "/items/{id:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}",
			testPath:    "/items/550e8400-e29b-41d4-a716-446655440000",
			shouldMatch: true,
			params:      map[string]string{"id": "550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name:        "uuid regex fail",
			pattern:     "/items/{id:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}",
			testPath:    "/items/not-a-uuid",
			shouldMatch: false,
		},

		// 版本化 API
		{
			name:        "versioned api",
			pattern:     "/api/v{version:[0-9]+}/users",
			testPath:    "/api/v2/users",
			shouldMatch: true,
			params:      map[string]string{"version": "2"},
		},
		{
			name:        "versioned api fail",
			pattern:     "/api/v{version:[0-9]+}/users",
			testPath:    "/api/v2.0/users",
			shouldMatch: false,
		},

		// 复合路径
		{
			name:        "compound path",
			pattern:     "/api/v{version:[0-9]+}/{resource}/{id:[0-9]+}",
			testPath:    "/api/v2/users/123",
			shouldMatch: true,
			params:      map[string]string{"version": "2", "resource": "users", "id": "123"},
		},
		{
			name:        "compound path partial match",
			pattern:     "/api/v{version:[0-9]+}/{resource}/{id:[0-9]+}",
			testPath:    "/api/v2/users",
			shouldMatch: false,
		},

		// Wildcard（使用 .* 正则实现）
		{
			name:        "wildcard path",
			pattern:     "/files/{path:.*}",
			testPath:    "/files/a/b/c.txt",
			shouldMatch: true,
			params:      map[string]string{"path": "a/b/c.txt"},
		},
		{
			name:        "wildcard empty",
			pattern:     "/files/{path:.*}",
			testPath:    "/files/",
			shouldMatch: true,
			params:      map[string]string{"path": ""},
		},

		// 邮箱正则（复杂）
		{
			name:        "email regex",
			pattern:     "/users/{email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}}",
			testPath:    "/users/test@example.com",
			shouldMatch: true,
			params:      map[string]string{"email": "test@example.com"},
		},
		{
			name:        "email regex complex",
			pattern:     "/users/{email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}}",
			testPath:    "/users/user.name+tag@sub.domain.co.uk",
			shouldMatch: true,
			params:      map[string]string{"email": "user.name+tag@sub.domain.co.uk"},
		},
		{
			name:        "email regex fail",
			pattern:     "/users/{email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}}",
			testPath:    "/users/not-an-email",
			shouldMatch: false,
		},

		// 日期正则
		{
			name:        "date regex",
			pattern:     "/posts/{date:[0-9]{4}-[0-9]{2}-[0-9]{2}}",
			testPath:    "/posts/2024-12-22",
			shouldMatch: true,
			params:      map[string]string{"date": "2024-12-22"},
		},
		{
			name:        "date regex fail",
			pattern:     "/posts/{date:[0-9]{4}-[0-9]{2}-[0-9]{2}}",
			testPath:    "/posts/2024-12-32",
			shouldMatch: true, // 正则不验证语义，只验证格式
			params:      map[string]string{"date": "2024-12-32"},
		},

		// 混合参数
		{
			name:        "mixed params",
			pattern:     "/{lang:[a-z]{2}}/posts/{slug:[a-z0-9-]+}",
			testPath:    "/en/posts/hello-world",
			shouldMatch: true,
			params:      map[string]string{"lang": "en", "slug": "hello-world"},
		},
		{
			name:        "mixed params fail lang",
			pattern:     "/{lang:[a-z]{2}}/posts/{slug:[a-z0-9-]+}",
			testPath:    "/eng/posts/hello-world",
			shouldMatch: false,
		},

		// 嵌套花括号（测试 curl count）
		{
			name:        "nested braces in regex",
			pattern:     "/codes/{code:[a-z]{2,4}}",
			testPath:    "/codes/abc",
			shouldMatch: true,
			params:      map[string]string{"code": "abc"},
		},
		{
			name:        "nested braces min length",
			pattern:     "/codes/{code:[a-z]{2,4}}",
			testPath:    "/codes/a",
			shouldMatch: false,
		},
		{
			name:        "nested braces max length",
			pattern:     "/codes/{code:[a-z]{2,4}}",
			testPath:    "/codes/abcde",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 为每个测试创建独立的 router，避免路由冲突
			router := NewRegexRouter()
			handler := func(c *Context) {
				c.JSON(200, H{"matched": true})
			}
			router.Handle("GET", tt.pattern, handler)

			handler, params, found := router.Match("GET", tt.testPath)

			if found != tt.shouldMatch {
				t.Errorf("Match found=%v, want %v (pattern: %s, path: %s)",
					found, tt.shouldMatch, tt.pattern, tt.testPath)
			}

			if !tt.shouldMatch {
				return
			}

			if handler == nil {
				t.Error("handler is nil but should match")
				return
			}

			// 验证参数
			for key, expectedValue := range tt.params {
				if actualValue, ok := params[key]; !ok {
					t.Errorf("param %q not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("param %q = %q, want %q", key, actualValue, expectedValue)
				}
			}

			// 验证没有额外的参数
			if len(params) != len(tt.params) {
				t.Errorf("got %d params, want %d: %v", len(params), len(tt.params), params)
			}

			router.root().paramsPool.Put(params)
		})
	}
}

// TestRegexRouter_ChiPanicCases 测试应该 panic 的情况（复刻自 Chi）
func TestRegexRouter_ChiPanicCases(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{
			name:    "missing closing brace",
			pattern: "/users/{id",
		},
		{
			name:    "duplicate param names",
			pattern: "/users/{id}/posts/{id}",
		},
		{
			name:    "wildcard not at end",
			pattern: "/files/*/extra",
		},
		{
			name:    "wildcard before param",
			pattern: "/files/*/{id}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic but didn't get one for pattern: %s", tt.pattern)
				}
			}()

			router := NewRegexRouter()
			router.Handle("GET", tt.pattern, func(c *Context) {})
		})
	}
}

// 辅助函数

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && contains(s[1:], substr)
}

func TestRegexRouter_NamedCatchAllPattern(t *testing.T) {
	router := NewRegexRouter()
	router.GET("/{config_id}/*path", func(c *Context) {})

	handler, params, ok := router.Match("GET", "/42/a/b.txt")
	if !ok {
		t.Fatalf("named catch-all route should match")
	}
	if handler == nil {
		t.Fatalf("handler is nil")
	}
	if params["config_id"] != "42" {
		t.Fatalf("config_id=%q, want=42", params["config_id"])
	}
	if params["path"] != "/a/b.txt" {
		t.Fatalf("path=%q, want=/a/b.txt", params["path"])
	}
	router.root().paramsPool.Put(params)
}

func TestRegexRouter_RootNamedCatchAllPattern(t *testing.T) {
	router := NewRegexRouter()
	router.GET("/*path", func(c *Context) {})

	handler, params, ok := router.Match("GET", "/assets/app.js")
	if !ok {
		t.Fatalf("root named catch-all route should match")
	}
	if handler == nil {
		t.Fatalf("handler is nil")
	}
	if params["path"] != "/assets/app.js" {
		t.Fatalf("path=%q, want=/assets/app.js", params["path"])
	}
	router.root().paramsPool.Put(params)
}

func TestIsRegexPattern_WithNamedCatchAll(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "chi regex param", pattern: "/users/{id:[0-9]+}", want: true},
		{name: "chi bare catch all", pattern: "/files/*", want: true},
		{name: "gin root named catch all", pattern: "/*path", want: false},
		{name: "gin param + named catch all", pattern: "/:config_id/*path", want: false},
		{name: "mixed named catch all", pattern: "/{config_id}/*path", want: true},
		{name: "standard gin param", pattern: "/users/:id", want: false},
		{name: "plain static path", pattern: "/users/me", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRegexPattern(tt.pattern); got != tt.want {
				t.Fatalf("IsRegexPattern(%q)=%v, want=%v", tt.pattern, got, tt.want)
			}
		})
	}
}
