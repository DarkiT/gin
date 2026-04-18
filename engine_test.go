package gin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	engine "github.com/darkit/gin"
	"github.com/darkit/gin/middleware"
	"github.com/darkit/gin/pkg/cache"
	"github.com/darkit/gin/pkg/lifecycle"
	gin "github.com/gin-gonic/gin"
)

func TestEngineDefaults(t *testing.T) {
	e := engine.New()
	if readConfig(e).Addr != ":8080" {
		t.Fatalf("default addr")
	}
	if readLogger(e) == nil || readCache(e) == nil || readLifecycle(e) == nil || readRegistry(e) == nil {
		t.Fatalf("default components")
	}
}

func TestEngineWithLoggerCache(t *testing.T) {
	e := engine.New()
	c := cache.NewMemoryCache()
	e.WithLogger(testLogger{}).WithCache(c)
	if readLogger(e) == nil || readCache(e) == nil {
		t.Fatalf("with logger/cache failed")
	}
}

func TestEngineRouterAndHandle(t *testing.T) {
	e := engine.New()
	e.GET("/ok", func(c *engine.Context) {
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("engine GET failed")
	}

	order := make([]string, 0, 3)
	e.GET("/chain",
		func(c *engine.Context) {
			order = append(order, "before")
			c.Next()
			order = append(order, "after")
		},
		func(c *engine.Context) {
			order = append(order, "handler")
			c.String(http.StatusOK, "chain")
		},
	)

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/chain", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("engine chained GET failed")
	}
	wantOrder := []string{"before", "handler", "after"}
	if len(order) != len(wantOrder) {
		t.Fatalf("engine call order=%v, want=%v", order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("engine call order=%v, want=%v", order, wantOrder)
		}
	}

	r := e.Router()
	r.POST("/post", func(c *engine.Context) {
		c.String(http.StatusCreated, "post")
	})
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/post", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("router POST failed")
	}
}

func TestEngineGroup(t *testing.T) {
	e := engine.New()
	g := e.Group("/v1", func(c *engine.Context) {
		c.Header("X-Group", "1")
		c.Next()
		c.Header("X-Group-After", "1")
	})
	order := make([]string, 0, 3)
	g.GET("/ping",
		func(c *engine.Context) {
			order = append(order, "route-before")
			c.Next()
			order = append(order, "route-after")
		},
		func(c *engine.Context) {
			order = append(order, "handler")
			c.String(http.StatusOK, "pong")
		},
	)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("group get failed")
	}
	if w.Header().Get("X-Group") != "1" {
		t.Fatalf("group middleware missing")
	}
	if w.Header().Get("X-Group-After") != "1" {
		t.Fatalf("group middleware after-chain missing")
	}
	wantOrder := []string{"route-before", "handler", "route-after"}
	if len(order) != len(wantOrder) {
		t.Fatalf("group call order=%v, want=%v", order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("group call order=%v, want=%v", order, wantOrder)
		}
	}
}

func TestEngineRegexRoute_VariadicHandlers(t *testing.T) {
	e := engine.New()
	order := make([]string, 0, 3)

	e.GET("/users/{id:[0-9]+}",
		func(c *engine.Context) {
			order = append(order, "before")
			c.Next()
			order = append(order, "after")
		},
		func(c *engine.Context) {
			order = append(order, "handler")
			c.JSON(http.StatusOK, engine.H{"id": c.Param("id")})
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if body := w.Body.String(); body != `{"id":"42"}` {
		t.Fatalf("body=%q", body)
	}
	wantOrder := []string{"before", "handler", "after"}
	if len(order) != len(wantOrder) {
		t.Fatalf("regex call order=%v, want=%v", order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("regex call order=%v, want=%v", order, wantOrder)
		}
	}
}

func readLifecycle(e *engine.Engine) *lifecycle.Manager {
	field := reflect.ValueOf(e).Elem().FieldByName("lifecycle")
	return *(**lifecycle.Manager)(unsafe.Pointer(field.UnsafeAddr()))
}

func readRegistry(e *engine.Engine) *middleware.Registry {
	field := reflect.ValueOf(e).Elem().FieldByName("middleware")
	return *(**middleware.Registry)(unsafe.Pointer(field.UnsafeAddr()))
}

func TestNoRouteOrderIndependent(t *testing.T) {
	assertJSONBody := func(t *testing.T, w *httptest.ResponseRecorder, want map[string]string) {
		t.Helper()
		var got map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("invalid json response: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected json body: got=%v want=%v", got, want)
		}
	}

	assertRegexOK := func(t *testing.T, e *engine.Engine) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/regex/123", nil)
		e.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("regex route status: got=%d want=%d", w.Code, http.StatusOK)
		}
		assertJSONBody(t, w, map[string]string{"from": "regex", "id": "123"})
	}

	assertCustom404 := func(t *testing.T, e *engine.Engine, path string) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		e.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("custom 404 status: got=%d want=%d", w.Code, http.StatusNotFound)
		}
		assertJSONBody(t, w, map[string]string{"error": "custom 404"})
	}

	assertDefault404 := func(t *testing.T, e *engine.Engine, path string) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		e.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("default 404 status: got=%d want=%d", w.Code, http.StatusNotFound)
		}
		assertJSONBody(t, w, map[string]string{"error": "not found"})
	}

	t.Run("OrderA: NoRoute then RegexRouter", func(t *testing.T) {
		e := engine.New()

		// 场景 A：先设置 NoRoute，再创建 RegexRouter，验证顺序无关性。
		e.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "custom 404"})
		})

		rx := e.RegexRouter()
		rx.GET("/regex/{id:[0-9]+}", func(c *engine.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, engine.H{"from": "regex", "id": id})
		})

		assertRegexOK(t, e)
		assertCustom404(t, e, "/not-found")
	})

	t.Run("OrderB: RegexRouter then NoRoute", func(t *testing.T) {
		e := engine.New()

		// 场景 B：先创建 RegexRouter，再设置 NoRoute，结果必须与场景 A 完全一致。
		rx := e.RegexRouter()
		rx.GET("/regex/{id:[0-9]+}", func(c *engine.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, engine.H{"from": "regex", "id": id})
		})

		e.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "custom 404"})
		})

		assertRegexOK(t, e)
		assertCustom404(t, e, "/not-found")
	})

	t.Run("OnlyNoRoute", func(t *testing.T) {
		e := engine.New()

		// 场景 C：只设置 NoRoute，任意路径都应走用户 404。
		e.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "custom 404"})
		})

		assertCustom404(t, e, "/any-path")
	})

	t.Run("OnlyRegexRouter", func(t *testing.T) {
		e := engine.New()

		// 场景 D：只使用 RegexRouter，未匹配时应返回默认 404。
		rx := e.RegexRouter()
		rx.GET("/regex/{id:[0-9]+}", func(c *engine.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, engine.H{"from": "regex", "id": id})
		})

		assertRegexOK(t, e)
		assertDefault404(t, e, "/not-found")
	})
}

func TestEngine_NoMethod(t *testing.T) {
	e := engine.New()
	e.HandleMethodNotAllowed = true

	// 只注册 GET 方法
	e.GET("/test", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{"method": "GET"})
	})

	// 设置 NoMethod 处理器
	e.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
	})

	// 测试：GET 请求应该成功
	t.Run("GET_allowed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("GET status code = %d, want %d", w.Code, http.StatusOK)
		}
	})

	// 测试：POST 请求应该返回 405
	t.Run("POST_not_allowed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST status code = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid json response: %v", err)
		}

		if resp["error"] != "method not allowed" {
			t.Errorf("response error = %q, want %q", resp["error"], "method not allowed")
		}
	})

	// 测试：PUT 请求也应该返回 405
	t.Run("PUT_not_allowed", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/test", nil)
		e.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("PUT status code = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestEngine_NoMethod_RegexRoute(t *testing.T) {
	e := engine.New()
	e.HandleMethodNotAllowed = true

	e.GET("/regex/{id:[0-9]+}", func(c *engine.Context) {
		c.JSON(http.StatusOK, engine.H{"id": c.Param("id")})
	})

	e.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "regex method not allowed"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/regex/123", nil)
	e.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status code = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow header = %q, want %q", allow, http.MethodGet)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["error"] != "regex method not allowed" {
		t.Fatalf("response error = %q, want %q", resp["error"], "regex method not allowed")
	}
}

func TestEngine_RoutesIncludeRegexRoutes(t *testing.T) {
	e := engine.New()
	e.GET("/plain", func(c *engine.Context) {
		c.String(http.StatusOK, "plain")
	})
	e.GET("/users/{id:[0-9]+}", func(c *engine.Context) {
		c.String(http.StatusOK, c.Param("id"))
	})
	e.Any("/files/*", func(c *engine.Context) {
		c.Status(http.StatusNoContent)
	})

	routes := e.Routes()
	assertRouteExists(t, routes, http.MethodGet, "/plain")
	assertRouteExists(t, routes, http.MethodGet, "/users/{id:[0-9]+}")
	assertRouteExists(t, routes, http.MethodDelete, "/files/*")
	assertRouteExists(t, routes, http.MethodTrace, "/files/*")
}

func assertRouteExists(t *testing.T, routes gin.RoutesInfo, method, routePath string) {
	t.Helper()
	for _, route := range routes {
		if route.Method == method && route.Path == routePath {
			if route.Handler == "" {
				t.Fatalf("route %s %s handler empty", method, routePath)
			}
			return
		}
	}
	t.Fatalf("route %s %s not found", method, routePath)
}
