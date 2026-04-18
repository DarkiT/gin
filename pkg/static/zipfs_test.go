package static

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestZipFileSystemSubPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	zipPath := createZipFixture(t, map[string]string{
		"admin/index.html":        "admin-index",
		"admin/assets/app.js":     "console.log('ok')",
		"admin-portal/index.html": "portal-index",
		"public/index.html":       "public-index",
	})

	cfg := NewZipFSConfig(zipPath, "/assets", WithSubPaths("admin/"))
	zfs, err := NewZipFileSystem(cfg)
	if err != nil {
		t.Fatalf("new zip fs: %v", err)
	}
	t.Cleanup(func() { zfs.Stop() })

	router := gin.New()
	RegisterZipFS(router, "/assets", zfs)

	tests := []struct {
		name       string
		path       string
		wantCode   int
		wantSubstr string
	}{
		{
			name:       "allowed exact subpath",
			path:       "/assets/admin/index.html",
			wantCode:   http.StatusOK,
			wantSubstr: "admin-index",
		},
		{
			name:       "allowed descendant subpath",
			path:       "/assets/admin/assets/app.js",
			wantCode:   http.StatusOK,
			wantSubstr: "console.log",
		},
		{
			name:     "deny prefix collision",
			path:     "/assets/admin-portal/index.html",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "deny unrelated subpath",
			path:     "/assets/public/index.html",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d, body=%q", w.Code, tt.wantCode, w.Body.String())
			}
			if tt.wantSubstr != "" && w.Body.String() == "" {
				t.Fatalf("expected body to contain %q", tt.wantSubstr)
			}
			if tt.wantSubstr != "" && !strings.Contains(w.Body.String(), tt.wantSubstr) {
				t.Fatalf("body = %q, want substring %q", w.Body.String(), tt.wantSubstr)
			}
		})
	}
}

func TestZipFileSystemStripPrefixHonorsConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		configure func(zipPath string) ZipFSConfig
		request   string
		wantBody  string
	}{
		{
			name: "strip prefix enabled",
			configure: func(zipPath string) ZipFSConfig {
				return NewZipFSConfig(zipPath, "/assets")
			},
			request:  "/assets/app/index.html",
			wantBody: "stripped-prefix",
		},
		{
			name: "strip prefix disabled",
			configure: func(zipPath string) ZipFSConfig {
				return NewZipFSConfig(zipPath, "/assets", WithStripPrefix(false))
			},
			request:  "/assets/app/index.html",
			wantBody: "preserved-prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"app/index.html":        "stripped-prefix",
				"assets/app/index.html": "preserved-prefix",
			}

			zipPath := createZipFixture(t, files)
			zfs, err := NewZipFileSystem(tt.configure(zipPath))
			if err != nil {
				t.Fatalf("new zip fs: %v", err)
			}
			t.Cleanup(func() { zfs.Stop() })

			router := gin.New()
			RegisterZipFS(router, "/assets", zfs)

			req := httptest.NewRequest(http.MethodGet, tt.request, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d, body=%q", w.Code, http.StatusOK, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestPasswordProtectedZipFSSubPaths(t *testing.T) {
	pzfs := &passwordProtectedZipFS{
		subPaths: []string{"admin/"},
	}

	if !pzfs.isValidSubPath("/admin/index.html") {
		t.Fatal("expected admin path to be allowed")
	}
	if pzfs.isValidSubPath("/admin-portal/index.html") {
		t.Fatal("expected prefix collision path to be denied")
	}
	if pzfs.isValidSubPath("/public/index.html") {
		t.Fatal("expected unrelated path to be denied")
	}
}

func createZipFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "fixture.zip")

	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = file.Close() }()

	writer := zip.NewWriter(file)
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

	return zipPath
}
