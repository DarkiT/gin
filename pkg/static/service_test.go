package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSiteServiceServesNotFoundFile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"404.html": "custom-404",
	}
	for name, content := range files {
		target := dir + "/" + name
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	service := NewSiteService(http.Dir(dir), WithNotFoundFile("404.html"), WithoutHistoryFallback())
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	if !service.TryServeHTTP(w, req) {
		t.Fatal("expected service to handle request")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want=%d", w.Code, http.StatusNotFound)
	}
	if body := w.Body.String(); body != "custom-404" {
		t.Fatalf("body=%q, want=%q", body, "custom-404")
	}
}

func TestSiteServiceHistoryFallbackRequiresHTMLAccept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/index.html", []byte("index"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}

	service := NewSiteService(http.Dir(dir))
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()

	if service.TryServeHTTP(w, req) {
		t.Fatal("expected request without html accept to miss")
	}
}
