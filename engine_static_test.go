package gin_test

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	engine "github.com/darkit/gin"
)

func TestSiteFSPrefersRegularRouteOverFallback(t *testing.T) {
	dir := writeStaticFixture(t, map[string]string{
		"index.html": "<html>site-index</html>",
		"main.js":    "console.log('site');",
	})

	e := engine.New()
	r := e.Router()
	r.GET("/app/health", func(c *engine.Context) {
		c.String(http.StatusOK, "health-ok")
	})
	r.SiteFS("/app", http.Dir(dir))

	w := performStaticRequest(e, http.MethodGet, "/app/health", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || w.Body.String() != "health-ok" {
		t.Fatalf("regular route should win, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/app/dashboard", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("site-index")) {
		t.Fatalf("site fallback failed, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/app/main.js", nil)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("console.log")) {
		t.Fatalf("static file serving failed, status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestSiteFSPrefersRegexRouteOverFallback(t *testing.T) {
	dir := writeStaticFixture(t, map[string]string{
		"index.html": "<html>regex-site</html>",
	})

	e := engine.New()
	r := e.Router()
	r.GET("/app/{id:[0-9]+}", func(c *engine.Context) {
		c.String(http.StatusOK, "regex:"+c.Param("id"))
	})
	r.SiteFS("/app", http.Dir(dir))

	w := performStaticRequest(e, http.MethodGet, "/app/123", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || w.Body.String() != "regex:123" {
		t.Fatalf("regex route should win, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/app/dashboard", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("regex-site")) {
		t.Fatalf("site fallback failed, status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestFallbackSiteFSOnlyHandlesHTMLRequests(t *testing.T) {
	dir := writeStaticFixture(t, map[string]string{
		"index.html": "<html>global-site</html>",
	})

	e := engine.New()
	e.GET("/api/ping", func(c *engine.Context) {
		c.String(http.StatusOK, "pong")
	})
	e.FallbackSiteFS(http.Dir(dir))

	w := performStaticRequest(e, http.MethodGet, "/api/ping", nil)
	if w.Code != http.StatusOK || w.Body.String() != "pong" {
		t.Fatalf("regular route failed, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/dashboard", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("global-site")) {
		t.Fatalf("global fallback failed, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/api/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-html request should not hit site fallback, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodPost, "/dashboard", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("post request should not hit site fallback, status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestAssetsMountDoesNotFallThroughToRootFallback(t *testing.T) {
	assetsDir := writeStaticFixture(t, map[string]string{
		"app.js": "console.log('asset');",
	})
	siteDir := writeStaticFixture(t, map[string]string{
		"index.html": "<html>root-site</html>",
	})

	e := engine.New()
	e.AssetsFS("/assets", http.Dir(assetsDir))
	e.FallbackSiteFS(http.Dir(siteDir))

	w := performStaticRequest(e, http.MethodGet, "/assets/app.js", nil)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("asset")) {
		t.Fatalf("asset file failed, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/assets/missing.js", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("asset subtree should not fall through to root site, status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestFallbackSiteEmbeddedZip(t *testing.T) {
	archive := fstest.MapFS{
		"ui/app.zip": &fstest.MapFile{
			Data: createZipArchive(t, map[string]string{
				"index.html": "<html>zip-index</html>",
				"main.js":    "console.log('zip');",
			}),
		},
	}

	e := engine.New()
	if err := e.FallbackSiteEmbeddedZip(archive, "ui/app.zip"); err != nil {
		t.Fatalf("fallback embedded zip: %v", err)
	}

	w := performStaticRequest(e, http.MethodGet, "/dashboard", map[string]string{
		"Accept": "text/html",
	})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("zip-index")) {
		t.Fatalf("embedded zip history fallback failed, status=%d body=%q", w.Code, w.Body.String())
	}

	w = performStaticRequest(e, http.MethodGet, "/main.js", nil)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("console.log")) {
		t.Fatalf("embedded zip asset failed, status=%d body=%q", w.Code, w.Body.String())
	}
}

func writeStaticFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func performStaticRequest(handler http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func createZipArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}
