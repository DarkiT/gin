package gin_test

import (
	stdcontext "context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	engine "github.com/darkit/gin"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

func TestContextProblemHelpers(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/users/1", "")
	ctx.Set("request_id", "rid-problem")

	ctx.Problem(http.StatusBadRequest, "about:blank", "", "参数错误")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/problem+json; charset=utf-8" {
		t.Fatalf("unexpected content type: %s", got)
	}

	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode problem details: %v", err)
	}
	if payload["title"] != http.StatusText(http.StatusBadRequest) {
		t.Fatalf("unexpected title: %v", payload["title"])
	}
	if payload["detail"] != "参数错误" {
		t.Fatalf("unexpected detail: %v", payload["detail"])
	}
	if payload["request_id"] != "rid-problem" {
		t.Fatalf("unexpected request_id: %v", payload["request_id"])
	}

	ctx, w = newTestContext(t, http.MethodPost, "/users", "")
	ctx.ValidationProblem([]engine.ValidationError{{Field: "name", Message: "必填"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
	var validation map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &validation); err != nil {
		t.Fatalf("decode validation problem: %v", err)
	}
	errorsValue, ok := validation["errors"].([]any)
	if !ok || len(errorsValue) != 1 {
		t.Fatalf("expected one validation error, got %+v", validation["errors"])
	}
}

func TestContextStreamingHelpers(t *testing.T) {
	ctx, w := newTestContext(t, http.MethodGet, "/stream", "")
	if err := ctx.SSE("update", gin.H{"ok": true}); err != nil {
		t.Fatalf("write sse: %v", err)
	}
	if got := w.Header().Get("Content-Type"); got != "text/event-stream; charset=utf-8" {
		t.Fatalf("unexpected SSE content type: %s", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, "event: update\n") {
		t.Fatalf("unexpected SSE body: %s", body)
	}
	if !strings.Contains(body, `"ok":true`) {
		t.Fatalf("unexpected SSE data: %s", body)
	}

	ctx, w = newTestContext(t, http.MethodGet, "/stream", "")
	if err := ctx.SSEHeartbeat(); err != nil {
		t.Fatalf("write sse heartbeat: %v", err)
	}
	if !strings.Contains(w.Body.String(), ":heartbeat\n\n") {
		t.Fatalf("unexpected heartbeat body: %s", w.Body.String())
	}

	ctx, w = newTestContext(t, http.MethodGet, "/stream", "")
	if err := ctx.StreamNDJSON(gin.H{"ok": true}); err != nil {
		t.Fatalf("write ndjson: %v", err)
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-ndjson; charset=utf-8" {
		t.Fatalf("unexpected NDJSON content type: %s", got)
	}
	if strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("unexpected NDJSON body: %q", w.Body.String())
	}
}

func TestContextCursorPaginationHelpers(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodGet, "/?cursor=next-token&limit=200", "")
	params := ctx.ParseCursorPagination(
		engine.WithDefaultCursorLimit(10),
		engine.WithMaxCursorLimit(50),
	)
	if params.Cursor != "next-token" {
		t.Fatalf("unexpected cursor: %s", params.Cursor)
	}
	if params.Limit != 50 {
		t.Fatalf("unexpected clamped limit: %d", params.Limit)
	}

	ctx, w := newTestContext(t, http.MethodGet, "/", "")
	ctx.CursorPaginated([]int{1, 2}, &engine.CursorPageInfo{
		NextCursor: "cursor-2",
		Limit:      2,
		HasMore:    true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp engine.CursorPaginatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode cursor response: %v", err)
	}
	if resp.Cursor == nil || resp.Cursor.NextCursor != "cursor-2" || !resp.Cursor.HasMore {
		t.Fatalf("unexpected cursor response: %+v", resp.Cursor)
	}
}

func TestContextWebhookHelpers(t *testing.T) {
	ctx, _ := newTestContext(t, http.MethodPost, "/", `{"ok":true}`)
	ctx.Request.Header.Set("X-GitHub-Delivery", "delivery-1")
	ctx.Request.Header.Set("X-Hub-Signature-256", "sha256=abc")
	ctx.Request.Header.Set("X-Timestamp", "1710000000")

	body, err := ctx.RawBody()
	if err != nil {
		t.Fatalf("read raw body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected raw body: %s", body)
	}

	bodyAgain, err := ctx.RawBody()
	if err != nil {
		t.Fatalf("read raw body twice: %v", err)
	}
	if string(bodyAgain) != string(body) {
		t.Fatalf("unexpected cached raw body: %s", bodyAgain)
	}

	restored, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != `{"ok":true}` {
		t.Fatalf("unexpected restored body: %s", restored)
	}

	if got := ctx.WebhookEventID(); got != "delivery-1" {
		t.Fatalf("unexpected webhook event id: %s", got)
	}
	if got := ctx.WebhookSignature(); got != "sha256=abc" {
		t.Fatalf("unexpected webhook signature: %s", got)
	}
	if got := ctx.WebhookTimestamp(); got != "1710000000" {
		t.Fatalf("unexpected webhook timestamp: %s", got)
	}
}

func TestContextTraceHelpers(t *testing.T) {
	var traceID trace.TraceID
	var spanID trace.SpanID
	copy(traceID[:], []byte("0123456789abcdef"))
	copy(spanID[:], []byte("12345678"))

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	reqCtx := trace.ContextWithSpanContext(stdcontext.Background(), spanContext)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(w)
	ginCtx.Request = req

	ctx := &engine.Context{Context: ginCtx}
	ctx.SetEngine(engine.New())

	if ctx.TraceID() != traceID.String() {
		t.Fatalf("unexpected trace id: %s", ctx.TraceID())
	}
	if ctx.SpanID() != spanID.String() {
		t.Fatalf("unexpected span id: %s", ctx.SpanID())
	}
}
