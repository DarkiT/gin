package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"
)

type responseEnvelope struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func setupTestEngine() *Engine {
	return New()
}

func performRequest(e *Engine, method, path string) *httptest.ResponseRecorder {
	return performRequestWithHeaders(e, method, path, nil)
}

func performRequestWithHeaders(e *Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	e.ServeHTTP(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) responseEnvelope {
	t.Helper()
	var resp responseEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	return resp
}

func assertStatusAndData(t *testing.T, w *httptest.ResponseRecorder, status int, key, expected string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP 状态码=%d, 期望=%d", w.Code, status)
	}
	resp := decodeResponse(t, w)
	if resp.Code != status {
		t.Fatalf("响应 code=%d, 期望=%d", resp.Code, status)
	}
	value, ok := resp.Data[key]
	if !ok {
		t.Fatalf("响应 data 缺少字段: %s", key)
	}
	strValue, ok := value.(string)
	if !ok {
		t.Fatalf("响应 data[%s] 类型=%T, 期望 string", key, value)
	}
	if strValue != expected {
		t.Fatalf("响应 data[%s]=%q, 期望=%q", key, strValue, expected)
	}
}

func TestParseMethodName(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		httpMethod string
		path       string
		isRegex    bool
	}{
		{"Get", "GetPing", "GET", "/ping", false},
		{"Post", "PostLogin", "POST", "/login", false},
		{"Put", "PutItem", "PUT", "/item", false},
		{"Delete", "DeleteItem", "DELETE", "/item", false},
		{"Patch", "PatchItem", "PATCH", "/item", false},
		{"Head", "HeadItem", "HEAD", "/item", false},
		{"Options", "OptionsItem", "OPTIONS", "/item", false},
		{"CamelPath", "GetUserProfile", "GET", "/user/profile", false},
		{"Regex", "GetUserIDRegex", "GET", "/user/id", true},
		{"Invalid", "FooBar", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method, path, isRegex := parseMethodName(tc.input)
			if method != tc.httpMethod {
				t.Fatalf("method=%q, 期望=%q", method, tc.httpMethod)
			}
			if path != tc.path {
				t.Fatalf("path=%q, 期望=%q", path, tc.path)
			}
			if isRegex != tc.isRegex {
				t.Fatalf("isRegex=%v, 期望=%v", isRegex, tc.isRegex)
			}
		})
	}
}

func TestCamelToSlashPath(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple", "Test", "/test"},
		{"UserProfile", "UserProfile", "/user/profile"},
		{"ID", "ID", "/id"},
		{"UserID", "UserID", "/user/id"},
		{"APIVersion", "APIVersion", "/api/version"},
		{"GetHTTPStatus", "GetHTTPStatus", "/get/http/status"},
		{"Version2", "Version2", "/version2"},
		{"V2API", "V2API", "/v2/api"},
		{"Empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := camelToSlashPath(tc.input); got != tc.expected {
				t.Fatalf("结果=%q, 期望=%q", got, tc.expected)
			}
		})
	}
}

type TestController struct{}

func (t *TestController) GetTest(c *Context) {
	c.Success(H{"msg": "test"})
}

func (t *TestController) PostLogin(c *Context) {
	c.Created(H{"token": "xxx"})
}

func (t *TestController) GetUserProfile(c *Context) {
	c.Success(H{"profile": "user"})
}

type AnyController struct{}

func (a *AnyController) AnyTest(c *Context) {
	c.Success(H{"msg": "any"})
}

func TestAutoRegister_Any(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&AnyController{})

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut}
	for _, method := range methods {
		w := performRequest(e, method, "/anycontroller/test")
		assertStatusAndData(t, w, http.StatusOK, "msg", "any")
	}
}

func TestAutoRegister_Basic(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&TestController{})

	cases := []struct {
		name        string
		method      string
		path        string
		status      int
		dataKey     string
		dataValue   string
		statusInRes int
	}{
		{"GetTest", http.MethodGet, "/testcontroller/test", http.StatusOK, "msg", "test", http.StatusOK},
		{"PostLogin", http.MethodPost, "/testcontroller/login", http.StatusCreated, "token", "xxx", http.StatusCreated},
		{"GetUserProfile", http.MethodGet, "/testcontroller/user/profile", http.StatusOK, "profile", "user", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := performRequest(e, tc.method, tc.path)
			assertStatusAndData(t, w, tc.status, tc.dataKey, tc.dataValue)
		})
	}
}

func TestAutoRegister_WithPrefix(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&TestController{}, WithPrefix("/api/v1"))

	w := performRequest(e, http.MethodGet, "/api/v1/test")
	assertStatusAndData(t, w, http.StatusOK, "msg", "test")
}

type GroupedRegexController struct{}

func (g *GroupedRegexController) RoutePrefix() string {
	return "/users"
}

func (g *GroupedRegexController) GetByIDRegex(c *Context) {
	c.Success(H{"id": c.Param("id")})
}

func TestAutoRegister_GroupRegexUsesRouterBasePath(t *testing.T) {
	e := setupTestEngine()
	api := e.Router().Group("/api")
	api.AutoRegister(&GroupedRegexController{})

	w := performRequest(e, http.MethodGet, "/api/users/by/123")
	assertStatusAndData(t, w, http.StatusOK, "id", "123")
}

func TestAutoRegister_GroupRegexInheritsMiddleware(t *testing.T) {
	e := setupTestEngine()
	api := e.Router().Group("/api")
	api.Use(func(c *Context) {
		if c.GetHeader("X-Test-Auth") != "ok" {
			c.Unauthorized("unauthorized")
			c.Abort()
			return
		}
		c.Next()
	})
	api.AutoRegister(&GroupedRegexController{})

	unauthorized := performRequest(e, http.MethodGet, "/api/users/by/123")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("未携带认证头时状态码=%d, 期望=%d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorized := performRequestWithHeaders(e, http.MethodGet, "/api/users/by/123", map[string]string{
		"X-Test-Auth": "ok",
	})
	assertStatusAndData(t, authorized, http.StatusOK, "id", "123")
}

type RegexDefaultController struct{}

func (t *RegexDefaultController) GetUserIDRegex(c *Context) {
	value := c.Param("id")
	c.Success(H{"id": value})
}

func TestAutoRegister_RegexDefault(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&RegexDefaultController{})
	_ = e.RegexRouter()
	rx := e.regexRouter
	if rx == nil {
		t.Fatalf("regexRouter 为空")
	}
	// 检查按方法分组的路由（GET 方法）
	if len(rx.routesByMethod["GET"]) == 0 && len(rx.routes) == 0 {
		t.Fatalf("regexRouter 路由为空")
	}
	// 检查 GET 方法的路由
	for _, route := range rx.routesByMethod["GET"] {
		if got := route.Pattern.String(); got == "" {
			t.Fatalf("regex pattern 为空")
		}
	}
	_, params, ok := rx.Match(http.MethodGet, "/regexdefaultcontroller/user/123")
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["id"] != "123" {
		t.Fatalf("正则参数 id=%q, 期望=123", params["id"])
	}
	w := performRequest(e, http.MethodGet, "/regexdefaultcontroller/user/123")
	assertStatusAndData(t, w, http.StatusOK, "id", "123")
}

type UserController struct{}

func (u *UserController) RegexPatterns() map[string]string {
	return map[string]string{
		"GetByEmailRegex": "/usercontroller/by/{email:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}}",
	}
}

func (u *UserController) GetByEmailRegex(c *Context) {
	email := c.Param("email")
	c.Success(H{"email": email})
}

func TestAutoRegister_RegexPatternProvider(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&UserController{})

	path := "/usercontroller/by/test@example.com"
	rx := e.RegexRouter()
	_, params, ok := rx.Match(http.MethodGet, path)
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["email"] != "test@example.com" {
		t.Fatalf("正则参数 email=%q, 期望=test@example.com", params["email"])
	}

	w := performRequest(e, http.MethodGet, path)
	assertStatusAndData(t, w, http.StatusOK, "email", "test@example.com")
}

type SlugController struct{}

func (s *SlugController) RegexPatterns() map[string]string {
	return map[string]string{
		"GetBySlugRegex": "/slugcontroller/slug/{slug:[0-9]+}",
	}
}

func (s *SlugController) GetBySlugRegex(c *Context) {
	slug := c.Param("slug")
	c.Success(H{"slug": slug})
}

func TestAutoRegister_WithRegexPattern(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(
		&SlugController{},
		WithRegexPattern("GetBySlugRegex", "/slugcontroller/slug/{slug:[a-z]+}"),
	)

	path := "/slugcontroller/slug/abc"
	rx := e.RegexRouter()
	_, params, ok := rx.Match(http.MethodGet, path)
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["slug"] != "abc" {
		t.Fatalf("正则参数 slug=%q, 期望=abc", params["slug"])
	}

	w := performRequest(e, http.MethodGet, path)
	assertStatusAndData(t, w, http.StatusOK, "slug", "abc")
}

type CacheController struct{}

func (c *CacheController) GetPing(ctx *Context) {
	ctx.Success(H{"pong": "pong"})
}

func TestAutoRegister_Cache(t *testing.T) {
	routeCache.Lock()
	oldEntries := routeCache.entries
	routeCache.entries = make(map[reflect.Type][]cachedRoute)
	routeCache.Unlock()
	defer func() {
		routeCache.Lock()
		routeCache.entries = oldEntries
		routeCache.Unlock()
	}()

	e1 := setupTestEngine()
	r1 := e1.Router()
	r1.AutoRegister(&CacheController{})

	ctrlType := reflect.TypeOf(&CacheController{})
	routes1, ok := routeCache.entries[ctrlType]
	if !ok || len(routes1) == 0 {
		t.Fatalf("缓存未写入")
	}
	ptr1 := unsafe.Pointer(&routes1[0])

	e2 := setupTestEngine()
	r2 := e2.Router()
	r2.AutoRegister(&CacheController{})

	routes2, ok := routeCache.entries[ctrlType]
	if !ok || len(routes2) == 0 {
		t.Fatalf("缓存未命中")
	}
	ptr2 := unsafe.Pointer(&routes2[0])

	if ptr1 != ptr2 {
		t.Fatalf("缓存未复用")
	}
}

type MiddlewareController struct{}

func (m *MiddlewareController) GetPing(c *Context) {
	c.Success(H{"pong": "pong"})
}

func TestAutoRegister_WithMiddleware_RegexPrefix(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&RegexDefaultController{}, WithMiddleware(func(c *Context) { c.Next() }))

	path := "/regexdefaultcontroller/user/123"
	rx := e.RegexRouter()
	_, params, ok := rx.Match(http.MethodGet, path)
	if !ok {
		t.Fatalf("正则路由未匹配")
	}
	if params["id"] != "123" {
		t.Fatalf("正则参数 id=%q, 期望=123", params["id"])
	}

	w := performRequest(e, http.MethodGet, path)
	assertStatusAndData(t, w, http.StatusOK, "id", "123")
}

func TestAutoRegister_WithMiddleware(t *testing.T) {
	called := false
	mw := func(c *Context) {
		called = true
		c.Next()
	}

	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&MiddlewareController{}, WithMiddleware(mw))

	w := performRequest(e, http.MethodGet, "/middlewarecontroller/ping")
	assertStatusAndData(t, w, http.StatusOK, "pong", "pong")
	if !called {
		t.Fatalf("中间件未调用")
	}
}

type CustomController struct{}

func (c *CustomController) RoutePrefix() string { return "/custom" }

func (c *CustomController) GetPing(ctx *Context) {
	ctx.Success(H{"pong": "pong"})
}

func TestAutoRegister_AutoController(t *testing.T) {
	e := setupTestEngine()
	r := e.Router()
	r.AutoRegister(&CustomController{})

	w := performRequest(e, http.MethodGet, "/custom/ping")
	assertStatusAndData(t, w, http.StatusOK, "pong", "pong")
}
