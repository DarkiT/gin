package gin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	ggin "github.com/gin-gonic/gin"
)

const routingBenchmarkRouteFanout = 128

var routingBenchmarkModeOnce sync.Once

type benchmarkResponseWriter struct {
	header http.Header
	code   int
}

func newBenchmarkResponseWriter() *benchmarkResponseWriter {
	return &benchmarkResponseWriter{
		header: make(http.Header),
	}
}

func (w *benchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *benchmarkResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}

func (w *benchmarkResponseWriter) Write(data []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return len(data), nil
}

func (w *benchmarkResponseWriter) reset() {
	for key := range w.header {
		delete(w.header, key)
	}
	w.code = 0
}

func benchmarkReleaseMode() {
	routingBenchmarkModeOnce.Do(func() {
		SetMode(ReleaseMode)
	})
}

func benchmarkNoContent(c *Context) {
	c.Status(http.StatusNoContent)
}

func buildBenchmarkEngine(includeStandard, includeRegex bool) *Engine {
	benchmarkReleaseMode()

	engine := New()
	engine.NoRoute(func(c *ggin.Context) {
		c.Status(http.StatusNotFound)
	})

	if includeStandard {
		registerStandardBenchmarkRoutes(engine)
	}
	if includeRegex {
		registerRegexBenchmarkRoutes(engine)
	}

	return engine
}

func registerStandardBenchmarkRoutes(engine *Engine) {
	for i := 0; i < routingBenchmarkRouteFanout; i++ {
		engine.GET(fmt.Sprintf("/plain/static/%03d", i), benchmarkNoContent)
		engine.GET(fmt.Sprintf("/plain/teams/%03d/members/:memberID/projects/:projectID", i), benchmarkNoContent)
		engine.GET(fmt.Sprintf("/plain/assets/%03d/files/:fileID/revisions/:revisionID", i), benchmarkNoContent)
	}

	engine.GET("/api/v1/accounts/:accountID/articles/:articleID/comments/:commentID", benchmarkNoContent)
}

func registerRegexBenchmarkRoutes(engine *Engine) {
	for i := 0; i < routingBenchmarkRouteFanout; i++ {
		engine.GET(fmt.Sprintf("/regex/fill/%03d/{id:[0-9]+}", i), benchmarkNoContent)
		engine.GET(
			fmt.Sprintf("/regex/catalog/%03d/{kind:(?:news|blog|report|analysis)}/{slug:(?:[a-z0-9]+(?:-[a-z0-9]+){1,4})}", i),
			benchmarkNoContent,
		)
	}

	engine.GET("/regex/users/{userID:[0-9]+}/orders/{orderID:[0-9]+}", benchmarkNoContent)
	engine.GET(
		"/content/{section:(?:news|blog|report|analysis)}/{date:(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])}/{slug:(?:[a-z0-9]+(?:-[a-z0-9]+){2,8})}",
		benchmarkNoContent,
	)
	engine.GET(
		"/articles/{date:[0-9]{8}}-{slug:[a-z0-9]+}-{kind:(?:news|blog|report|analysis)}",
		benchmarkNoContent,
	)
}

type routingBenchmarkCase struct {
	name       string
	engine     *Engine
	method     string
	target     string
	wantStatus int
}

func runRoutingBenchmark(b *testing.B, tc routingBenchmarkCase) {
	b.Helper()

	req := httptest.NewRequest(tc.method, tc.target, nil)
	writer := newBenchmarkResponseWriter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.reset()
		tc.engine.ServeHTTP(writer, req)
		if writer.code != tc.wantStatus {
			b.Fatalf("status = %d, want %d", writer.code, tc.wantStatus)
		}
	}
}

func runRoutingParallelBenchmark(b *testing.B, tc routingBenchmarkCase) {
	b.Helper()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		writer := newBenchmarkResponseWriter()
		for pb.Next() {
			writer.reset()
			tc.engine.ServeHTTP(writer, req)
			if writer.code != tc.wantStatus {
				b.Fatalf("status = %d, want %d", writer.code, tc.wantStatus)
			}
		}
	})
}

// BenchmarkRouting 对比普通路由、regex 路由与混合路由的串行请求开销。
func BenchmarkRouting(b *testing.B) {
	standardEngine := buildBenchmarkEngine(true, false)
	regexEngine := buildBenchmarkEngine(false, true)
	mixedEngine := buildBenchmarkEngine(true, true)

	cases := []routingBenchmarkCase{
		{
			name:       "standard_only_hit",
			engine:     standardEngine,
			method:     http.MethodGet,
			target:     "/api/v1/accounts/42/articles/9001/comments/7",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "regex_only_simple_hit",
			engine:     regexEngine,
			method:     http.MethodGet,
			target:     "/regex/users/42/orders/9001",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "regex_only_complex_hit",
			engine:     regexEngine,
			method:     http.MethodGet,
			target:     "/content/analysis/20241231/openai-routing-benchmark-suite",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "regex_only_same_segment_hit",
			engine:     regexEngine,
			method:     http.MethodGet,
			target:     "/articles/20240408-release-news",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_standard_hit",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/api/v1/accounts/42/articles/9001/comments/7",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_regex_simple_hit",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/regex/users/42/orders/9001",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_regex_complex_hit",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/content/analysis/20241231/openai-routing-benchmark-suite",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_miss",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/missing/routes/that/do/not/exist",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			runRoutingBenchmark(b, tc)
		})
	}
}

// BenchmarkRoutingParallel 对比高并发下普通路由、regex 路由与混合路由的吞吐。
func BenchmarkRoutingParallel(b *testing.B) {
	standardEngine := buildBenchmarkEngine(true, false)
	regexEngine := buildBenchmarkEngine(false, true)
	mixedEngine := buildBenchmarkEngine(true, true)

	cases := []routingBenchmarkCase{
		{
			name:       "standard_only_hit",
			engine:     standardEngine,
			method:     http.MethodGet,
			target:     "/api/v1/accounts/42/articles/9001/comments/7",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "regex_only_simple_hit",
			engine:     regexEngine,
			method:     http.MethodGet,
			target:     "/regex/users/42/orders/9001",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "regex_only_complex_hit",
			engine:     regexEngine,
			method:     http.MethodGet,
			target:     "/content/analysis/20241231/openai-routing-benchmark-suite",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_standard_hit",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/api/v1/accounts/42/articles/9001/comments/7",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "mixed_regex_complex_hit",
			engine:     mixedEngine,
			method:     http.MethodGet,
			target:     "/content/analysis/20241231/openai-routing-benchmark-suite",
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			runRoutingParallelBenchmark(b, tc)
		})
	}
}
