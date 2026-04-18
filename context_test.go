package gin_test

import (
	stdcontext "context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engine "github.com/darkit/gin"
	"github.com/gin-gonic/gin"
)

func newTestContext(t *testing.T, method, path string, body string) (*engine.Context, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(w)
	ginCtx.Request = req
	e := engine.New()
	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(e)
	return ctx, w
}

func TestContextRequestInfo(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("X-Real-IP", " 1.2.3.4 ")
	ctx.Request.Header.Set("User-Agent", "agent")
	if ctx.GetIP() != "1.2.3.4" {
		t.Fatalf("get ip with X-Real-IP")
	}

	// 测试 X-Forwarded-For
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Request.Header.Set("X-Forwarded-For", "2.3.4.5, 3.4.5.6")
	if ctx2.GetIP() != "2.3.4.5" {
		t.Fatalf("get ip with X-Forwarded-For, got %s", ctx2.GetIP())
	}

	if ctx.GetUserAgent() != "agent" {
		t.Fatalf("get user agent")
	}
	ctx.Request.Header.Set("X-Requested-With", "XMLHttpRequest")
	if !ctx.IsAjax() {
		t.Fatalf("is ajax")
	}
	ctx.Request.Header.Set("Content-Type", "application/json; charset=utf-8")
	if !ctx.IsJSON() {
		t.Fatalf("is json")
	}
}

func TestContextImplementsStdContextAfterRequestRelease(t *testing.T) {
	reqCtx, cancel := stdcontext.WithCancel(stdcontext.WithValue(stdcontext.Background(), "trace_id", "trace-001"))
	defer cancel()

	w := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(w)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(reqCtx)

	e := engine.New()
	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(e)

	// 模拟请求结束后底层 gin.Context 被回收。
	ctx.Context = nil

	cancel()

	select {
	case <-ctx.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("done channel should be closed after cancel")
	}

	if err := ctx.Err(); err != stdcontext.Canceled {
		t.Fatalf("unexpected context err: %v", err)
	}
	if value := ctx.Value("trace_id"); value != "trace-001" {
		t.Fatalf("unexpected context value: %v", value)
	}
}

func TestContextParamHelpers(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/?q=1&price=19.99&active=true", "a=2")
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	if ctx.Param("id") != "10" {
		t.Fatalf("param from path")
	}
	if ctx.Input("q") != "1" {
		t.Fatalf("input from query")
	}
	if ctx.Input("a") != "2" {
		t.Fatalf("input from form")
	}
	if ctx.Input("missing", "d") != "d" {
		t.Fatalf("param default")
	}
	if ctx.ParamInt("id") != 10 {
		t.Fatalf("param int")
	}
	// 测试 ParamInt 默认值
	if ctx.ParamInt("missing_int") != 0 {
		t.Fatalf("param int default should be 0")
	}
	if ctx.ParamInt("missing_int", 99) != 99 {
		t.Fatalf("param int custom default")
	}
	if ctx.ParamInt64("id") != 10 {
		t.Fatalf("param int64")
	}
	// 测试 ParamInt64 默认值
	if ctx.ParamInt64("missing_int64") != 0 {
		t.Fatalf("param int64 default should be 0")
	}
	if ctx.ParamInt64("missing_int64", 999) != 999 {
		t.Fatalf("param int64 custom default")
	}
	if ctx.ParamFloat("price") != 19.99 {
		t.Fatalf("param float")
	}
	if ctx.ParamFloat("missing", 9.99) != 9.99 {
		t.Fatalf("param float default")
	}
	if ctx.ParamBool("active") != true {
		t.Fatalf("param bool")
	}
	if ctx.ParamBool("inactive", false) != false {
		t.Fatalf("param bool default")
	}
	if err := ctx.RequireParams("id", "q", "a"); err != nil {
		t.Fatalf("require params should pass")
	}
	if err := ctx.RequireParams("missing"); err == nil {
		t.Fatalf("require params should fail")
	}
}

func TestBindJSONOrAbortValidationErrors(t *testing.T) {
	type payload struct {
		Name string `json:"name" binding:"required"`
	}
	ctx, w := newTestContext(t, http.MethodPost, "/", `{}`)
	ctx.Request.Header.Set("Content-Type", "application/json")
	var p payload
	if ctx.BindJSONOrAbort(&p) {
		t.Fatalf("expected bind to fail")
	}
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
	var resp engine.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatalf("expected validation errors")
	}
}

func TestContextBindAndValidate(t *testing.T) {
	type payload struct {
		Name string `json:"name" binding:"required"`
	}
	ctx, _ := newTestContext(t, http.MethodPost, "/", `{"name":"ok"}`)
	ctx.Request.Header.Set("Content-Type", "application/json")
	var p payload
	if err := ctx.BindAndValidate(&p); err != nil {
		t.Fatalf("bind and validate: %v", err)
	}
	if p.Name != "ok" {
		t.Fatalf("bind value")
	}
}

func TestContextOKHelpers(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.Success([]int{1, 2})
	if w.Code != http.StatusOK {
		t.Fatalf("ok list status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Success(map[string]any{"a": 1})
	if w.Code != http.StatusOK {
		t.Fatalf("ok map status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Paginated([]int{1}, 1, 10, 11)
	if w.Code != http.StatusOK {
		t.Fatalf("ok page status")
	}
}

func TestContextErrorResponsesUnified(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("request_id", "rid")
	ctx.MethodNotAllowed("method not allowed")
	var errResp engine.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode method not allowed: %v", err)
	}
	if errResp.RequestID != "rid" {
		t.Fatalf("request id missing in error response")
	}
	if errResp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("error code=%d, want=%d", errResp.Code, http.StatusMethodNotAllowed)
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("request_id", "rid2")
	ctx.SuccessWithMessage(map[string]string{"k": "v"}, "ok")
	var resp engine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ok with message: %v", err)
	}
	if resp.RequestID != "rid2" || resp.Message != "ok" {
		t.Fatalf("unexpected ok response: %+v", resp)
	}
}

func TestContextResponses(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("request_id", "rid")
	ctx.Success(map[string]any{"k": "v"})
	if w.Code != http.StatusOK {
		t.Fatalf("ok status")
	}
	var resp engine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ok: %v", err)
	}
	if resp.RequestID != "rid" {
		t.Fatalf("request id")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Created("c")
	if w.Code != http.StatusCreated {
		t.Fatalf("created status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Accepted("a")
	if w.Code != http.StatusAccepted {
		t.Fatalf("accepted status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.NoContent()
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("no content status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Paginated([]int{1}, 1, 10, 11)
	if w.Code != http.StatusOK {
		t.Fatalf("paginated status")
	}
	var paged engine.PaginatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &paged); err != nil {
		t.Fatalf("decode paginated: %v", err)
	}
	if paged.Pagination == nil || paged.Pagination.TotalPages != 2 {
		t.Fatalf("pagination total pages")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.BadRequest("bad")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad request status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Unauthorized("unauth")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Forbidden("forbidden")
	if w.Code != http.StatusForbidden {
		t.Fatalf("forbidden status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.NotFound("missing")
	if w.Code != http.StatusNotFound {
		t.Fatalf("not found status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.Conflict("conflict")
	if w.Code != http.StatusConflict {
		t.Fatalf("conflict status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.ValidationError([]engine.ValidationError{{Field: "f", Message: "m"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("validation error status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.InternalError("err")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("internal error status")
	}

	ctx, w = newTestContext(t, http.MethodGet, "/", "")
	ctx.ErrorResponse(418, "teapot")
	if w.Code != 418 {
		t.Fatalf("error status")
	}
}

func TestSetCookieWithOptions(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.SetCookieWithOptions("token", "abc", engine.CookieOptions{Path: "/api", MaxAge: 60, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	values := ctx.Writer.Header().Values("Set-Cookie")
	if len(values) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(values))
	}
	if values[0] == "" {
		t.Fatalf("empty Set-Cookie header")
	}
}

func TestSetSecureCookieAddsHeader(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.SetSecureCookie("a", "1", 0)
	ctx.SetSecureCookie("b", "2", 0)
	values := ctx.Writer.Header().Values("Set-Cookie")
	if len(values) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d", len(values))
	}
}

func TestRequestIDHelpers(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.SetRequestID("rid")
	if ctx.RequestID() != "rid" {
		t.Fatalf("request id mismatch")
	}
	if ctx.Writer.Header().Get("X-Request-ID") != "rid" {
		t.Fatalf("header request id mismatch")
	}
}

func TestContextLoggerCache(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	if ctx.Logger() == nil {
		t.Fatalf("logger missing")
	}
	if ctx.Cache() == nil {
		t.Fatalf("cache missing")
	}

	// 测试 engine 为 nil 的情况
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.SetEngine(nil)
	if ctx2.Logger() == nil {
		t.Fatalf("logger should return noop logger when engine is nil")
	}
	if ctx2.Cache() != nil {
		t.Fatalf("cache should return nil when engine is nil")
	}
}

// TestRequireParamsOrAbort 测试批量参数校验并自动中止
func TestRequireParamsOrAbort(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/?username=alice", "")

	// 缺少参数
	if ctx.RequireParamsOrAbort("username", "password") {
		t.Fatalf("should abort when missing params")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// 所有参数存在
	ctx2, _ := newTestContext(t, http.MethodPost, "/?username=alice", "password=secret123")
	ctx2.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !ctx2.RequireParamsOrAbort("username", "password") {
		t.Fatalf("should not abort when all params present")
	}
}

// TestGetQueryInt 测试获取整型 Query 参数
func TestGetQueryInt(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?age=25&invalid=abc", "")

	if val := ctx.GetQueryInt("age"); val != 25 {
		t.Fatalf("expected 25, got %d", val)
	}

	if val := ctx.GetQueryInt("missing", 18); val != 18 {
		t.Fatalf("expected default 18, got %d", val)
	}

	if val := ctx.GetQueryInt("invalid"); val != 0 {
		t.Fatalf("expected 0 for invalid, got %d", val)
	}
}

// TestGetQueryBool 测试获取布尔型 Query 参数
func TestGetQueryBool(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?active=true&verified=1&enabled=yes&disabled=no", "")

	if !ctx.GetQueryBool("active") {
		t.Fatalf("expected true for active=true")
	}

	if !ctx.GetQueryBool("verified") {
		t.Fatalf("expected true for verified=1")
	}

	if !ctx.GetQueryBool("enabled") {
		t.Fatalf("expected true for enabled=yes")
	}

	if ctx.GetQueryBool("disabled") {
		t.Fatalf("expected false for disabled=no")
	}

	// 参数缺失 + 有默认值
	if ctx.GetQueryBool("missing", true) != true {
		t.Fatalf("expected default true")
	}

	// 参数缺失 + 无默认值（返回 false）
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	if ctx2.GetQueryBool("missing") != false {
		t.Fatalf("expected false for missing param without default")
	}
}

// TestJSONOrAbort 测试 JSON 绑定并自动中止
func TestJSONOrAbort(t *testing.T) {
	type req struct {
		Name string `json:"name"`
	}

	// 有效 JSON
	ctx, _ := newTestContext(t, http.MethodPost, "/", `{"name":"alice"}`)
	ctx.Request.Header.Set("Content-Type", "application/json")
	var r req
	if !ctx.JSONOrAbort(&r) {
		t.Fatalf("should not abort for valid JSON")
	}
	if r.Name != "alice" {
		t.Fatalf("expected alice, got %s", r.Name)
	}

	// 无效 JSON
	ctx2, w := newTestContext(t, http.MethodPost, "/", `{invalid}`)
	ctx2.Request.Header.Set("Content-Type", "application/json")
	var r2 req
	if ctx2.JSONOrAbort(&r2) {
		t.Fatalf("should abort for invalid JSON")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestOKIf 测试条件响应
func TestOKIf(t *testing.T) {
	// 条件为真
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.OKIf(true, map[string]string{"status": "found"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 条件为假（默认消息）
	ctx2, w2 := newTestContext(t, http.MethodGet, "/", "")
	ctx2.OKIf(false, nil)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w2.Code)
	}

	// 条件为假（自定义消息）
	ctx3, w3 := newTestContext(t, http.MethodGet, "/", "")
	ctx3.OKIf(false, nil, "用户不存在")
	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w3.Code)
	}
}

// TestRedirectPermanent 测试永久重定向
func TestRedirectPermanent(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/old", "")
	ctx.RedirectPermanent("/new")
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", w.Code)
	}
}

// TestRedirectTemporary 测试临时重定向
func TestRedirectTemporary(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/temp", "")
	ctx.RedirectTemporary("/new")
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
}

// TestSetSecureCookie 测试安全 Cookie 设置
func TestSetSecureCookie(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.SetSecureCookie("session", "abc123", 3600)

	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatalf("Set-Cookie header not set")
	}

	if !strings.Contains(cookie, "session=abc123") {
		t.Fatalf("cookie value not set correctly")
	}

	if !strings.Contains(cookie, "Secure") {
		t.Fatalf("Secure flag not set")
	}

	if !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("HttpOnly flag not set")
	}

	if !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("SameSite flag not set")
	}
}

// TestGetCookieOr 测试获取 Cookie 或默认值
func TestGetCookieOr(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")

	// Cookie 不存在
	if val := ctx.GetCookieOr("missing", "default"); val != "default" {
		t.Fatalf("expected default, got %s", val)
	}

	// Cookie 存在
	ctx.Request.Header.Set("Cookie", "token=xyz789")
	if val := ctx.GetCookieOr("token", "default"); val != "xyz789" {
		t.Fatalf("expected xyz789, got %s", val)
	}
}

// TestDeleteCookie 测试删除 Cookie
func TestDeleteCookie(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.DeleteCookie("session")

	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "Max-Age=-1") && !strings.Contains(cookie, "session=;") {
		t.Fatalf("cookie not deleted correctly: %s", cookie)
	}
}

// TestIsMethod 测试请求方法判断
func TestIsMethod(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", "")

	if !ctx.IsMethod("POST") {
		t.Fatalf("expected POST")
	}

	if ctx.IsMethod("GET") {
		t.Fatalf("not GET")
	}
}

// TestIsGET 测试 GET 请求判断
func TestIsGET(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	if !ctx.IsGET() {
		t.Fatalf("expected GET")
	}

	ctx2, _ := newTestContext(t, http.MethodPost, "/", "")
	if ctx2.IsGET() {
		t.Fatalf("not GET")
	}
}

// TestIsPOST 测试 POST 请求判断
func TestIsPOST(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", "")
	if !ctx.IsPOST() {
		t.Fatalf("expected POST")
	}

	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	if ctx2.IsPOST() {
		t.Fatalf("not POST")
	}
}

// TestAcceptsJSON 测试 JSON Accept 头判断
func TestAcceptsJSON(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Accept", "application/json")

	if !ctx.AcceptsJSON() {
		t.Fatalf("expected AcceptsJSON true")
	}

	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Request.Header.Set("Accept", "text/html")

	if ctx2.AcceptsJSON() {
		t.Fatalf("expected AcceptsJSON false")
	}
}

// TestAcceptsHTML 测试 HTML Accept 头判断
func TestAcceptsHTML(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Accept", "text/html")

	if !ctx.AcceptsHTML() {
		t.Fatalf("expected AcceptsHTML true")
	}

	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Request.Header.Set("Accept", "application/json")

	if ctx2.AcceptsHTML() {
		t.Fatalf("expected AcceptsHTML false")
	}
}

// TestNegotiate 测试内容协商
func TestNegotiate(t *testing.T) {
	// JSON 响应
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Accept", "application/json")
	ctx.AutoNegotiate(map[string]string{"message": "hello"})

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected JSON content type, got %s", contentType)
	}

	// 默认 JSON 响应（无 Accept 头）
	ctx2, w2 := newTestContext(t, http.MethodGet, "/", "")
	ctx2.AutoNegotiate(map[string]string{"message": "world"})

	if w2.Code != 200 {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// HTML Accept 头检测（不调用 Negotiate 以避免模板 panic）
	ctx3, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx3.Request.Header.Set("Accept", "text/html")
	if !ctx3.AcceptsHTML() {
		t.Fatal("expected AcceptsHTML true")
	}
}

// ============================================================
// P0 - RESTful API 必备方法测试
// ============================================================

func TestIsPUT(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPut, "/", "")
	if !ctx.IsPUT() {
		t.Fatal("expected IsPUT true")
	}

	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	if ctx2.IsPUT() {
		t.Fatal("expected IsPUT false")
	}
}

func TestIsPATCH(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPatch, "/", "")
	if !ctx.IsPATCH() {
		t.Fatal("expected IsPATCH true")
	}
}

func TestIsDELETE(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodDelete, "/", "")
	if !ctx.IsDELETE() {
		t.Fatal("expected IsDELETE true")
	}
}

func TestIsOPTIONS(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodOptions, "/", "")
	if !ctx.IsOPTIONS() {
		t.Fatal("expected IsOPTIONS true")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.MethodNotAllowed("Method Not Allowed")

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestTooManyRequests(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.TooManyRequests("Rate Limit Exceeded")

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

// ============================================================
// P1 - 认证与安全方法测试
// ============================================================

func TestGetBearerToken(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Authorization", "Bearer abc123")

	token := ctx.GetBearerToken()
	if token != "abc123" {
		t.Fatalf("expected abc123, got %s", token)
	}

	// 无 Bearer 前缀
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Request.Header.Set("Authorization", "Basic xyz")
	if ctx2.GetBearerToken() != "" {
		t.Fatal("expected empty token")
	}
}

func TestGetBasicAuth(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.SetBasicAuth("user", "pass")

	username, password, ok := ctx.GetBasicAuth()
	if !ok || username != "user" || password != "pass" {
		t.Fatal("expected basic auth user/pass")
	}
}

func TestIsSecure(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("X-Forwarded-Proto", "https")

	if !ctx.IsSecure() {
		t.Fatal("expected IsSecure true")
	}
}

func TestGetReferer(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Referer", "https://example.com")

	if ctx.GetReferer() != "https://example.com" {
		t.Fatal("expected referer https://example.com")
	}
}

func TestGetOrigin(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Origin", "https://example.com")

	if ctx.GetOrigin() != "https://example.com" {
		t.Fatal("expected origin https://example.com")
	}
}

// ============================================================
// P2 - 参数处理增强方法测试
// ============================================================

func TestParamSlice(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/test?ids=1,2,3", "")
	ctx.Params = gin.Params{{Key: "ids", Value: "1,2,3"}}

	slice := ctx.ParamSlice("ids")
	if len(slice) != 3 || slice[0] != "1" || slice[2] != "3" {
		t.Fatalf("expected [1 2 3], got %v", slice)
	}

	// 自定义分隔符
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Params = gin.Params{{Key: "tags", Value: "a|b|c"}}
	slice2 := ctx2.ParamSlice("tags", "|")
	if len(slice2) != 3 || slice2[1] != "b" {
		t.Fatalf("expected [a b c], got %v", slice2)
	}
}

func TestParamIntSlice(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Params = gin.Params{{Key: "ids", Value: "10,20,30"}}

	intSlice := ctx.ParamIntSlice("ids")
	if len(intSlice) != 3 || intSlice[0] != 10 || intSlice[2] != 30 {
		t.Fatalf("expected [10 20 30], got %v", intSlice)
	}
}

func TestParamTime(t *testing.T) {
	// 有效时间值
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Params = gin.Params{{Key: "date", Value: "2024-01-15"}}
	tm := ctx.ParamTime("date", "2006-01-02")
	if tm.Year() != 2024 || tm.Month() != 1 || tm.Day() != 15 {
		t.Fatalf("expected 2024-01-15, got %v", tm)
	}

	// 无效时间 + 有默认值
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Params = gin.Params{{Key: "date", Value: "invalid"}}
	defTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	tm2 := ctx2.ParamTime("date", "2006-01-02", defTime)
	if tm2 != defTime {
		t.Fatal("expected default time")
	}

	// 无效时间 + 无默认值（返回零值）
	ctx3, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx3.Params = gin.Params{{Key: "date", Value: "invalid"}}
	tm3 := ctx3.ParamTime("date", "2006-01-02")
	if !tm3.IsZero() {
		t.Fatal("expected zero time")
	}

	// 参数缺失 + 有默认值
	ctx4, _ := newTestContext(t, http.MethodGet, "/", "")
	tm4 := ctx4.ParamTime("missing", "2006-01-02", defTime)
	if tm4 != defTime {
		t.Fatal("expected default time for missing param")
	}

	// 参数缺失 + 无默认值（返回零值）
	ctx5, _ := newTestContext(t, http.MethodGet, "/", "")
	tm5 := ctx5.ParamTime("missing", "2006-01-02")
	if !tm5.IsZero() {
		t.Fatal("expected zero time for missing param")
	}
}

func TestParamDuration(t *testing.T) {
	// 有效时长值
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Params = gin.Params{{Key: "timeout", Value: "5s"}}
	d := ctx.ParamDuration("timeout")
	if d != 5*time.Second {
		t.Fatalf("expected 5s, got %v", d)
	}

	// 无效时长 + 有默认值
	ctx2, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx2.Params = gin.Params{{Key: "timeout", Value: "invalid"}}
	defDuration := 10 * time.Minute
	d2 := ctx2.ParamDuration("timeout", defDuration)
	if d2 != defDuration {
		t.Fatalf("expected default duration, got %v", d2)
	}

	// 无效时长 + 无默认值（返回 0）
	ctx3, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx3.Params = gin.Params{{Key: "timeout", Value: "invalid"}}
	d3 := ctx3.ParamDuration("timeout")
	if d3 != 0 {
		t.Fatalf("expected 0, got %v", d3)
	}

	// 参数缺失 + 有默认值
	ctx4, _ := newTestContext(t, http.MethodGet, "/", "")
	d4 := ctx4.ParamDuration("missing", defDuration)
	if d4 != defDuration {
		t.Fatalf("expected default duration for missing param, got %v", d4)
	}

	// 参数缺失 + 无默认值（返回 0）
	ctx5, _ := newTestContext(t, http.MethodGet, "/", "")
	d5 := ctx5.ParamDuration("missing")
	if d5 != 0 {
		t.Fatalf("expected 0 for missing param, got %v", d5)
	}
}

func TestGetQueryFloat(t *testing.T) {
	// 有效浮点值
	ctx, _ := newTestContext(t, http.MethodGet, "/test?price=19.99", "")
	price := ctx.GetQueryFloat("price")
	if price != 19.99 {
		t.Fatalf("expected 19.99, got %f", price)
	}

	// 参数缺失 + 有默认值
	def := ctx.GetQueryFloat("missing", 0.0)
	if def != 0.0 {
		t.Fatal("expected default 0.0")
	}

	// 参数缺失 + 无默认值（返回 0）
	ctx2, _ := newTestContext(t, http.MethodGet, "/test", "")
	val := ctx2.GetQueryFloat("missing")
	if val != 0 {
		t.Fatalf("expected 0, got %f", val)
	}

	// 无效浮点值 + 有默认值
	ctx3, _ := newTestContext(t, http.MethodGet, "/test?price=invalid", "")
	val2 := ctx3.GetQueryFloat("price", 99.99)
	if val2 != 99.99 {
		t.Fatalf("expected default 99.99, got %f", val2)
	}

	// 无效浮点值 + 无默认值（返回 0）
	ctx4, _ := newTestContext(t, http.MethodGet, "/test?price=invalid", "")
	val3 := ctx4.GetQueryFloat("price")
	if val3 != 0 {
		t.Fatalf("expected 0 for invalid, got %f", val3)
	}
}

func TestGetHeaderOr(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("X-Custom", "value")

	val := ctx.GetHeaderOr("X-Custom", "default")
	if val != "value" {
		t.Fatal("expected value")
	}

	val2 := ctx.GetHeaderOr("Missing", "default")
	if val2 != "default" {
		t.Fatal("expected default")
	}
}

// ============================================================
// P3 - 响应增强方法测试
// ============================================================

func TestServiceUnavailable(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.ServiceUnavailable("Service Unavailable")

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestGatewayTimeout(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.GatewayTimeout("Gateway Timeout")

	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", w.Code)
	}
}

func TestGone(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.Gone("Resource Gone")

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

func TestSuccessWithMessage(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.SuccessWithMessage(map[string]string{"id": "123"}, "Success")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Success") || !strings.Contains(body, "123") {
		t.Fatal("expected message and data in response")
	}
}

func TestCreatedWithLocation(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodPost, "/", "")
	ctx.CreatedWithLocation(map[string]string{"id": "456"}, "/api/v1/users/456")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/api/v1/users/456" {
		t.Fatalf("expected Location header, got %s", location)
	}
}

// ============================================================
// P4 - 请求检测增强方法测试
// ============================================================

func TestIsForm(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", "")
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !ctx.IsForm() {
		t.Fatal("expected IsForm true")
	}
}

func TestIsMultipart(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", "")
	ctx.Request.Header.Set("Content-Type", "multipart/form-data; boundary=123")

	if !ctx.IsMultipart() {
		t.Fatal("expected IsMultipart true")
	}
}

func TestIsWebSocket(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Request.Header.Set("Connection", "Upgrade")
	ctx.Request.Header.Set("Upgrade", "websocket")

	if !ctx.IsWebSocket() {
		t.Fatal("expected IsWebSocket true")
	}
}

func TestGetContentLength(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", `{"test":"data"}`)

	length := ctx.GetContentLength()
	if length <= 0 {
		t.Fatalf("expected positive content length, got %d", length)
	}
}

// ============================================================
// P5 - 上下文操作增强方法测试
// ============================================================

func TestMustGet(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("key1", "value1")

	val := ctx.MustGet("key1")
	if val != "value1" {
		t.Fatal("expected value1")
	}

	// panic 测试
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for missing key")
		}
	}()
	ctx.MustGet("missing")
}

func TestGetStringOr(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("str", "hello")

	val := ctx.GetStringOr("str", "default")
	if val != "hello" {
		t.Fatal("expected hello")
	}

	val2 := ctx.GetStringOr("missing", "default")
	if val2 != "default" {
		t.Fatal("expected default")
	}
}

func TestGetIntOr(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("num", 42)

	val := ctx.GetIntOr("num", 0)
	if val != 42 {
		t.Fatalf("expected 42, got %d", val)
	}

	val2 := ctx.GetIntOr("missing", 10)
	if val2 != 10 {
		t.Fatal("expected default 10")
	}
}

func TestHasKey(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/", "")
	ctx.Set("exists", "value")

	if !ctx.HasKey("exists") {
		t.Fatal("expected HasKey true")
	}

	if ctx.HasKey("missing") {
		t.Fatal("expected HasKey false")
	}
}
