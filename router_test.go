package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	engine "github.com/darkit/gin"
	"github.com/gin-gonic/gin"
)

func TestRouterMethods(t *testing.T) {
	e := engine.New()
	r := e.Router()
	called := false
	r.GET("/ping", func(c *engine.Context) {
		called = true
		c.String(http.StatusOK, "pong")
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("router GET failed")
	}
}

func TestRouterMethods_VariadicHandlers(t *testing.T) {
	e := engine.New()
	r := e.Router()

	called := make([]string, 0, 5)
	r.GET("/chain",
		func(c *engine.Context) {
			called = append(called, "mw1-before")
			c.Header("X-MW-1", "1")
			c.Next()
			called = append(called, "mw1-after")
		},
		func(c *engine.Context) {
			called = append(called, "mw2-before")
			c.Header("X-MW-2", "2")
			c.Next()
			called = append(called, "mw2-after")
		},
		func(c *engine.Context) {
			called = append(called, "handler")
			c.String(http.StatusOK, "ok")
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/chain", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != "ok" {
		t.Fatalf("body=%q, want=ok", body)
	}
	if w.Header().Get("X-MW-1") != "1" || w.Header().Get("X-MW-2") != "2" {
		t.Fatalf("variadic middlewares not executed")
	}
	want := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	if len(called) != len(want) {
		t.Fatalf("call order=%v, want=%v", called, want)
	}
	for i := range want {
		if called[i] != want[i] {
			t.Fatalf("call order=%v, want=%v", called, want)
		}
	}
}

func TestRouterMethods_AutoRegexRoute(t *testing.T) {
	e := engine.New()
	r := e.Router()

	r.GET("/users/{id:[0-9]+}",
		func(c *engine.Context) {
			c.Header("X-Regex-Before", "1")
			c.Header("X-Regex-MW", "1")
			c.Next()
			c.Header("X-Regex-After", "1")
		},
		func(c *engine.Context) {
			c.JSON(http.StatusOK, engine.H{
				"id": c.Param("id"),
			})
		},
	)

	ok := httptest.NewRecorder()
	e.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/users/123", nil))
	if ok.Code != http.StatusOK {
		t.Fatalf("regex GET status=%d", ok.Code)
	}
	if body := ok.Body.String(); body != `{"id":"123"}` {
		t.Fatalf("regex GET body=%q", body)
	}
	if ok.Header().Get("X-Regex-MW") != "1" {
		t.Fatalf("regex middleware not executed")
	}
	if ok.Header().Get("X-Regex-Before") != "1" || ok.Header().Get("X-Regex-After") != "1" {
		t.Fatalf("regex middleware chain not preserved")
	}

	notFound := httptest.NewRecorder()
	e.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "/users/abc", nil))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("invalid regex path status=%d, want=404", notFound.Code)
	}
}

func TestRouterMethods_MixedNamedCatchAllPreservesGinPathValue(t *testing.T) {
	e := engine.New()
	r := e.Router()

	r.GET("/{config_id}/*path", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{
			"config_id": c.Param("config_id"),
			"path":      c.Param("path"),
		})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/42/a/b.txt", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != `{"config_id":"42","path":"/a/b.txt"}` {
		t.Fatalf("body=%q", body)
	}
}

func TestRouterMethods_GinNamedCatchAllPreservesSlash(t *testing.T) {
	e := engine.New()
	r := e.Router()

	r.GET("/:config_id/*path", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{
			"config_id": c.Param("config_id"),
			"path":      c.Param("path"),
		})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/42/a/b.txt", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != `{"config_id":"42","path":"/a/b.txt"}` {
		t.Fatalf("body=%q", body)
	}
}

func TestRouterMethods_RootNamedCatchAllPreservesSlash(t *testing.T) {
	e := engine.New()
	r := e.Router()

	r.GET("/*path", func(c *engine.Context) {
		c.String(http.StatusOK, c.Param("path"))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != "/assets/app.js" {
		t.Fatalf("body=%q", body)
	}
}

func TestRouterGroupAndUse(t *testing.T) {
	e := engine.New()
	r := e.Router()
	r.Use(func(c *engine.Context) {
		c.Header("X-MW", "1")
		c.Next()
	})
	g := r.Group("/v1")
	g.POST("/items", func(c *engine.Context) {
		c.String(http.StatusCreated, "ok")
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/items", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("group post status")
	}
	if w.Header().Get("X-MW") != "1" {
		t.Fatalf("middleware not executed")
	}
}

func TestRouterGroup_VariadicHandlers(t *testing.T) {
	e := engine.New()
	r := e.Router()
	g := r.Group("/v1",
		func(c *engine.Context) {
			c.Header("X-Group-Before", "1")
			c.Next()
			c.Header("X-Group-After", "1")
		},
	)

	order := make([]string, 0, 3)
	g.GET("/items",
		func(c *engine.Context) {
			order = append(order, "route-before")
			c.Next()
			order = append(order, "route-after")
		},
		func(c *engine.Context) {
			order = append(order, "handler")
			c.String(http.StatusOK, "ok")
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/items", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("X-Group-Before") != "1" || w.Header().Get("X-Group-After") != "1" {
		t.Fatalf("group middleware chain not preserved")
	}

	want := []string{"route-before", "handler", "route-after"}
	if len(order) != len(want) {
		t.Fatalf("order=%v, want=%v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order=%v, want=%v", order, want)
		}
	}
}

func TestRouterGroupAndUse_AutoRegexRoute(t *testing.T) {
	e := engine.New()
	api := e.Router().Group("/api")
	api.Use(func(c *engine.Context) {
		c.Header("X-Scoped", "1")
		c.Next()
	})
	api.GET("/users/{id:[0-9]+}", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{"id": c.Param("id")})
	})

	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/users/7", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != `{"id":"7"}` {
		t.Fatalf("body=%q", body)
	}
	if w.Header().Get("X-Scoped") != "1" {
		t.Fatalf("group middleware not executed for regex route")
	}
}

func TestRouter_GetHead(t *testing.T) {
	e := engine.New()
	r := e.Router()

	// 使用 GetHead 注册路由
	r.GetHead("/test", func(c *engine.Context) {
		c.JSON(200, engine.H{"message": "hello"})
	})

	r.GetHead("/users/:id", func(c *engine.Context) {
		c.JSON(200, engine.H{
			"id":   c.Param("id"),
			"name": "张三",
		})
	})

	tests := []struct {
		name           string
		method         string
		path           string
		expectedCode   int
		expectedBody   string
		checkEmptyBody bool
	}{
		{
			name:           "GET request with body",
			method:         "GET",
			path:           "/test",
			expectedCode:   200,
			expectedBody:   `{"message":"hello"}`,
			checkEmptyBody: false,
		},
		{
			name:           "HEAD request no body",
			method:         "HEAD",
			path:           "/test",
			expectedCode:   200,
			expectedBody:   "",
			checkEmptyBody: true,
		},
		{
			name:           "HEAD with params",
			method:         "HEAD",
			path:           "/users/123",
			expectedCode:   200,
			expectedBody:   "",
			checkEmptyBody: true,
		},
		{
			name:           "GET with params",
			method:         "GET",
			path:           "/users/123",
			expectedCode:   200,
			expectedBody:   `{"id":"123","name":"张三"}`,
			checkEmptyBody: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			e.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.expectedCode)
			}

			body := w.Body.String()
			if tt.checkEmptyBody {
				if body != "" {
					t.Errorf("HEAD request body = %q, want empty", body)
				}
			} else {
				if body != tt.expectedBody {
					t.Errorf("body = %q, want %q", body, tt.expectedBody)
				}
			}

			// HEAD 请求应该保留 Content-Type 头
			if tt.method == "HEAD" {
				contentType := w.Header().Get("Content-Type")
				if contentType == "" {
					t.Error("HEAD request missing Content-Type header")
				}
			}
		})
	}
}

func TestRouter_GetHead_StatusCodes(t *testing.T) {
	e := engine.New()
	r := e.Router()

	r.GetHead("/ok", func(c *engine.Context) {
		c.JSON(200, engine.H{"status": "ok"})
	})

	r.GetHead("/error", func(c *engine.Context) {
		c.JSON(400, engine.H{"error": "bad request"})
	})

	tests := []struct {
		name         string
		path         string
		expectedCode int
	}{
		{"200 OK", "/ok", 200},
		{"400 Bad Request", "/error", 400},
	}

	for _, tt := range tests {
		t.Run(tt.name+" GET", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			e.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("GET status code = %d, want %d", w.Code, tt.expectedCode)
			}
		})

		t.Run(tt.name+" HEAD", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("HEAD", tt.path, nil)
			e.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("HEAD status code = %d, want %d", w.Code, tt.expectedCode)
			}

			if w.Body.Len() > 0 {
				t.Errorf("HEAD request has body, want empty")
			}
		})
	}
}

// TestRouter_HTTPMiddleware 测试 Chi 风格 / 标准 http.Handler 中间件适配
func TestRouter_HTTPMiddleware(t *testing.T) {
	t.Run("middleware calls next", func(t *testing.T) {
		e := engine.New()
		r := e.Router()

		// Chi 风格中间件: 在 header 添加标记并调用 next
		chiMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-Chi-Middleware", "called")
				next.ServeHTTP(w, req)
			})
		}

		r.UseAny(chiMiddleware)

		r.GET("/test", func(c *engine.Context) {
			c.JSON(200, engine.H{"message": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("status code = %d, want 200", w.Code)
		}

		if w.Header().Get("X-Chi-Middleware") != "called" {
			t.Error("Chi middleware was not executed")
		}

		if w.Body.String() != `{"message":"ok"}` {
			t.Errorf("body = %q, want %q", w.Body.String(), `{"message":"ok"}`)
		}
	})

	t.Run("middleware aborts (no next call)", func(t *testing.T) {
		e := engine.New()
		r := e.Router()

		// Chi 风格中间件: 直接返回 403，不调用 next
		blockingMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				if _, err := w.Write([]byte("blocked")); err != nil {
					t.Errorf("write blocked response: %v", err)
				}
				// 注意: 不调用 next.ServeHTTP，表示中断执行链
			})
		}

		r.UseAny(blockingMiddleware)

		handlerCalled := false
		r.GET("/test", func(c *engine.Context) {
			handlerCalled = true
			c.JSON(200, engine.H{"message": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("status code = %d, want %d", w.Code, http.StatusForbidden)
		}

		if w.Body.String() != "blocked" {
			t.Errorf("body = %q, want %q", w.Body.String(), "blocked")
		}

		if handlerCalled {
			t.Error("handler should not be called when middleware aborts")
		}
	})

	t.Run("middleware writes response then calls next", func(t *testing.T) {
		e := engine.New()
		r := e.Router()

		chiMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				if _, err := w.Write([]byte("unauthorized")); err != nil {
					t.Errorf("write unauthorized response: %v", err)
				}
				next.ServeHTTP(w, req)
			})
		}

		r.UseAny(chiMiddleware)

		handlerCalled := false
		r.GET("/test", func(c *engine.Context) {
			handlerCalled = true
			c.JSON(200, engine.H{"message": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status code = %d, want %d", w.Code, http.StatusUnauthorized)
		}

		if w.Body.String() != "unauthorized" {
			t.Errorf("body = %q, want %q", w.Body.String(), "unauthorized")
		}

		if handlerCalled {
			t.Error("handler should not be called after response is written")
		}
	})

	t.Run("multiple http middlewares", func(t *testing.T) {
		e := engine.New()
		r := e.Router()

		// 第一个中间件
		mw1 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-MW1", "1")
				next.ServeHTTP(w, req)
			})
		}

		// 第二个中间件
		mw2 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-MW2", "2")
				next.ServeHTTP(w, req)
			})
		}

		r.UseAny(mw1, mw2)

		r.GET("/test", func(c *engine.Context) {
			c.JSON(200, engine.H{"message": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("status code = %d, want 200", w.Code)
		}

		if w.Header().Get("X-MW1") != "1" {
			t.Error("first middleware not executed")
		}

		if w.Header().Get("X-MW2") != "2" {
			t.Error("second middleware not executed")
		}
	})

	t.Run("mixed middleware types", func(t *testing.T) {
		e := engine.New()
		r := e.Router()

		// Chi 风格中间件
		httpMw := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-HTTP-MW", "http")
				next.ServeHTTP(w, req)
			})
		}

		// 增强型中间件
		enhancedMw := func(c *engine.Context) {
			c.Header("X-Enhanced-MW", "enhanced")
			c.Next()
		}

		// 原始 gin 中间件
		ginMw := func(c *gin.Context) {
			c.Header("X-Gin-MW", "gin")
			c.Next()
		}

		r.UseAny(httpMw, enhancedMw, ginMw)

		r.GET("/test", func(c *engine.Context) {
			c.JSON(200, engine.H{"message": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("status code = %d, want 200", w.Code)
		}

		if w.Header().Get("X-HTTP-MW") != "http" {
			t.Error("http middleware not executed")
		}

		if w.Header().Get("X-Enhanced-MW") != "enhanced" {
			t.Error("enhanced middleware not executed")
		}

		if w.Header().Get("X-Gin-MW") != "gin" {
			t.Error("gin middleware not executed")
		}
	})
}

func TestRouter_Any(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			e := engine.New()
			r := e.Router()

			r.Any("/test", func(c *engine.Context) {
				c.JSON(200, engine.H{"method": method})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/test", nil)
			e.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Errorf("%s request: status code = %d, want 200", method, w.Code)
			}
		})
	}
}
