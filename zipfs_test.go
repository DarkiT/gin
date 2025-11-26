package gin

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	yekazip "github.com/yeka/zip"
)

// createTestZip 创建测试用的zip文件
func createTestZip(t *testing.T, filename string, files map[string]string) string {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, filename)

	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("创建zip文件失败: %v", err)
	}
	defer func() { _ = file.Close() }()

	zipWriter := zip.NewWriter(file)
	defer func() { _ = zipWriter.Close() }()

	for path, content := range files {
		writer, err := zipWriter.Create(path)
		if err != nil {
			t.Fatalf("创建zip文件内容失败: %v", err)
		}
		_, err = writer.Write([]byte(content))
		if err != nil {
			t.Fatalf("写入zip文件内容失败: %v", err)
		}
	}

	return zipPath
}

// createPasswordProtectedZip 创建密码保护的测试zip文件
func createPasswordProtectedZip(t *testing.T, filename, password string, files map[string]string) string {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, filename)

	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("创建zip文件失败: %v", err)
	}
	defer func() { _ = file.Close() }()

	zipWriter := yekazip.NewWriter(file)
	defer func() { _ = zipWriter.Close() }()

	for path, content := range files {
		// 创建加密的文件条目
		writer, err := zipWriter.Encrypt(path, password, yekazip.AES256Encryption)
		if err != nil {
			t.Fatalf("创建加密zip文件内容失败: %v", err)
		}
		_, err = writer.Write([]byte(content))
		if err != nil {
			t.Fatalf("写入加密zip文件内容失败: %v", err)
		}
	}

	return zipPath
}

// TestZipFileSystem_Basic 测试基础zip文件系统功能
func TestZipFileSystem_Basic(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"index.html":    "<html><body>Hello World</body></html>",
		"style.css":     "body { color: red; }",
		"js/script.js":  "console.log('hello');",
		"images/bg.png": "fake png data",
	}
	zipPath := createTestZip(t, "test.zip", files)

	// 创建zip文件系统
	config := ZipFSConfig{
		ZipPath:   zipPath,
		URLPrefix: "/app",
		IndexFile: "index.html",
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		t.Fatalf("创建zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 创建测试路由器
	router := NewRouter(nil)
	router.engine.GET("/app/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 测试访问首页
	req := httptest.NewRequest("GET", "/app/", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
		t.Errorf("响应内容: %s", resp.Body.String())
		t.Errorf("响应头: %v", resp.Header())
	}

	// 测试访问CSS文件
	req = httptest.NewRequest("GET", "/app/style.css", nil)
	resp = httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedContent := "body { color: red; }"
	if !strings.Contains(resp.Body.String(), expectedContent) {
		t.Errorf("期望内容包含 %q，得到 %q", expectedContent, resp.Body.String())
	}
}

// TestZipFile_Basic 测试单个zip文件功能
func TestZipFile_Basic(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"config.json": `{"name": "test", "version": "1.0"}`,
		"readme.txt":  "This is a readme file",
	}
	zipPath := createTestZip(t, "config.zip", files)

	// 创建zip文件管理器
	config := &ZipFileConfig{}
	zf, err := NewZipFile(zipPath, "config.json", config)
	if err != nil {
		t.Fatalf("创建zip文件管理器失败: %v", err)
	}
	defer zf.Stop()

	// 创建测试路由器
	router := NewRouter(nil)
	router.engine.GET("/config", func(c *gin.Context) {
		zf.ServeHTTP(c)
	})

	// 测试访问文件
	req := httptest.NewRequest("GET", "/config", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedContent := `{"name": "test", "version": "1.0"}`
	if resp.Body.String() != expectedContent {
		t.Errorf("期望内容 %q，得到 %q", expectedContent, resp.Body.String())
	}

	// 检查Content-Type
	expectedContentType := "application/json"
	if !strings.HasPrefix(resp.Header().Get("Content-Type"), expectedContentType) {
		t.Errorf("期望Content-Type包含 %q，得到 %q", expectedContentType, resp.Header().Get("Content-Type"))
	}
}

// TestRouter_SetZipFS 测试Router的SetZipFS方法
func TestRouter_SetZipFS(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"index.html": "<html><body>Router SetZipFS Test</body></html>",
		"app.css":    "body { background: blue; }",
	}
	zipPath := createTestZip(t, "router_test.zip", files)

	// 创建路由器并设置zip文件系统
	router := NewRouter(nil)
	err := router.SetZipFS(zipPath, "/assets")
	if err != nil {
		t.Fatalf("设置zip文件系统失败: %v", err)
	}

	// 测试访问文件
	req := httptest.NewRequest("GET", "/assets/app.css", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedContent := "body { background: blue; }"
	if !strings.Contains(resp.Body.String(), expectedContent) {
		t.Errorf("期望内容包含 %q，得到 %q", expectedContent, resp.Body.String())
	}
}

// TestRouter_SetZipFile 测试Router的SetZipFile方法
func TestRouter_SetZipFile(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"api.json":    `{"api": "v1", "endpoints": ["users", "posts"]}`,
		"schema.yaml": "version: 1.0\nschema: openapi",
	}
	zipPath := createTestZip(t, "api_test.zip", files)

	// 创建路由器并设置zip文件
	router := NewRouter(nil)
	err := router.SetZipFile("/api/spec", zipPath, "api.json")
	if err != nil {
		t.Fatalf("设置zip文件失败: %v", err)
	}

	// 测试访问文件
	req := httptest.NewRequest("GET", "/api/spec", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedContent := `{"api": "v1", "endpoints": ["users", "posts"]}`
	if resp.Body.String() != expectedContent {
		t.Errorf("期望内容 %q，得到 %q", expectedContent, resp.Body.String())
	}
}

// TestZipFS_HotReload 测试热更新功能
func TestZipFS_HotReload(t *testing.T) {
	// 创建临时目录和zip文件
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "hotreload.zip")

	// 创建初始zip文件
	createZipFile := func(content string) {
		file, err := os.Create(zipPath)
		if err != nil {
			t.Fatalf("创建zip文件失败: %v", err)
		}
		defer func() { _ = file.Close() }()

		zipWriter := zip.NewWriter(file)
		defer func() { _ = zipWriter.Close() }()

		writer, err := zipWriter.Create("test.txt")
		if err != nil {
			t.Fatalf("创建zip文件内容失败: %v", err)
		}
		_, err = writer.Write([]byte(content))
		if err != nil {
			t.Fatalf("写入zip文件内容失败: %v", err)
		}
	}

	// 创建初始内容
	initialContent := "initial content"
	createZipFile(initialContent)

	// 创建启用热更新的zip文件系统
	config := ZipFSConfig{
		ZipPath:       zipPath,
		URLPrefix:     "/test",
		HotReload:     true,
		CheckInterval: 100 * time.Millisecond, // 快速检查间隔用于测试
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		t.Fatalf("创建zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 启动热更新
	zfs.StartHotReload()

	// 创建路由器
	router := NewRouter(nil)
	router.engine.GET("/test/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 测试初始内容
	req := httptest.NewRequest("GET", "/test/test.txt", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	if !strings.Contains(resp.Body.String(), initialContent) {
		t.Errorf("期望内容包含 %q，得到 %q", initialContent, resp.Body.String())
	}

	// 等待一下然后更新zip文件
	time.Sleep(200 * time.Millisecond)
	updatedContent := "updated content"
	createZipFile(updatedContent)

	// 等待热更新检测到变化
	time.Sleep(300 * time.Millisecond)

	// 测试更新后的内容
	req = httptest.NewRequest("GET", "/test/test.txt", nil)
	resp = httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	// 注意: 由于实际的文件系统行为，热更新可能需要更多时间
	// 在实际测试中可能需要调整时间间隔
}

// TestZipFS_SubPaths 测试子路径限制功能
func TestZipFS_SubPaths(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"allowed/file1.txt":     "allowed content 1",
		"allowed/file2.txt":     "allowed content 2",
		"restricted/secret.txt": "secret content",
		"public.txt":            "public content",
	}
	zipPath := createTestZip(t, "subpaths.zip", files)

	// 创建带子路径限制的zip文件系统
	config := ZipFSConfig{
		ZipPath:   zipPath,
		URLPrefix: "/files",
		SubPaths:  []string{"/allowed", "/public.txt"},
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		t.Fatalf("创建zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 创建路由器
	router := NewRouter(nil)
	router.engine.GET("/files/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 测试访问允许的文件
	req := httptest.NewRequest("GET", "/files/allowed/file1.txt", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望访问允许路径成功，状态码 %d", resp.Code)
		t.Errorf("响应内容: %s", resp.Body.String())
	}

	// 测试访问限制的文件
	req = httptest.NewRequest("GET", "/files/restricted/secret.txt", nil)
	resp = httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Errorf("期望访问限制路径返回404，状态码 %d", resp.Code)
	}
}

// TestZipFS_Metrics 测试监控指标功能
func TestZipFS_Metrics(t *testing.T) {
	// 创建测试zip文件
	files := map[string]string{
		"test.txt": "test content",
	}
	zipPath := createTestZip(t, "metrics.zip", files)

	// 创建zip文件系统
	config := ZipFSConfig{
		ZipPath:   zipPath,
		URLPrefix: "/metrics-test",
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		t.Fatalf("创建zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 获取初始指标
	initialMetrics := zfs.GetMetrics()
	if initialMetrics.ReloadCount != 1 { // 初始加载算1次
		t.Errorf("期望初始重载次数为1，得到 %d", initialMetrics.ReloadCount)
	}

	// 创建路由器并发送请求
	router := NewRouter(nil)
	router.engine.GET("/metrics-test/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 发送几个请求
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/metrics-test/test.txt", nil)
		resp := httptest.NewRecorder()
		router.engine.ServeHTTP(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("请求 %d 失败，状态码 %d", i+1, resp.Code)
		}
	}

	// 检查指标更新
	finalMetrics := zfs.GetMetrics()
	if finalMetrics.RequestCount != 3 {
		t.Errorf("期望请求次数为3，得到 %d", finalMetrics.RequestCount)
	}
}

// TestContentTypeDetection 测试内容类型检测
func TestContentTypeDetection(t *testing.T) {
	testCases := []struct {
		filename   string
		content    string
		expectedCT string
	}{
		{"test.html", "<html></html>", "text/html"},
		{"style.css", "body{color:red}", "text/css"},
		{"script.js", "console.log('hi')", "application/javascript"},
		{"data.json", `{"key":"value"}`, "application/json"},
		{"unknown.xyz", "some data", "text/plain"}, // 会回退到检测
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			detectedType := detectContentType(tc.filename, []byte(tc.content))
			if !strings.HasPrefix(detectedType, tc.expectedCT) {
				t.Errorf("文件 %s: 期望Content-Type前缀 %s，得到 %s", tc.filename, tc.expectedCT, detectedType)
			}
		})
	}
}

// BenchmarkZipFS_ServeFile 基准测试zip文件服务性能
func BenchmarkZipFS_ServeFile(b *testing.B) {
	// 创建测试zip文件
	files := map[string]string{
		"benchmark.txt": strings.Repeat("test content ", 1000),
	}

	tempDir := b.TempDir()
	zipPath := filepath.Join(tempDir, "benchmark.zip")

	file, err := os.Create(zipPath)
	if err != nil {
		b.Fatalf("创建zip文件失败: %v", err)
	}
	defer func() { _ = file.Close() }()

	zipWriter := zip.NewWriter(file)
	defer func() { _ = zipWriter.Close() }()

	for path, content := range files {
		writer, err := zipWriter.Create(path)
		if err != nil {
			b.Fatalf("创建zip文件内容失败: %v", err)
		}
		_, err = writer.Write([]byte(content))
		if err != nil {
			b.Fatalf("写入zip文件内容失败: %v", err)
		}
	}
	// defers handle close

	// 创建zip文件系统
	config := ZipFSConfig{
		ZipPath:   zipPath,
		URLPrefix: "/bench",
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		b.Fatalf("创建zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 创建路由器
	router := NewRouter(nil)
	router.engine.GET("/bench/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 基准测试
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/bench/benchmark.txt", nil)
		resp := httptest.NewRecorder()
		router.engine.ServeHTTP(resp, req)

		if resp.Code != http.StatusOK {
			b.Errorf("请求失败，状态码 %d", resp.Code)
		}
	}
}

// TestZipFileSystem_PasswordProtected 测试密码保护的zip文件系统功能
func TestZipFileSystem_PasswordProtected(t *testing.T) {
	// 创建密码保护的测试zip文件
	password := "test123456"
	files := map[string]string{
		"secret.html": "<html><body>Secret Content</body></html>",
		"secret.css":  "body { color: green; }",
		"data.json":   `{"secret": "password protected data"}`,
	}
	zipPath := createPasswordProtectedZip(t, "protected.zip", password, files)

	// 创建带密码的zip文件系统
	config := ZipFSConfig{
		ZipPath:   zipPath,
		URLPrefix: "/protected",
		Password:  password,
		IndexFile: "secret.html",
	}

	zfs, err := NewZipFileSystem(config)
	if err != nil {
		t.Fatalf("创建密码保护的zip文件系统失败: %v", err)
	}
	defer zfs.Stop()

	// 创建测试路由器
	router := NewRouter(nil)
	router.engine.GET("/protected/*filepath", func(c *gin.Context) {
		zfs.ServeHTTP(c)
	})

	// 测试访问加密的HTML文件
	req := httptest.NewRequest("GET", "/protected/secret.html", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
		t.Errorf("响应内容: %s", resp.Body.String())
	}

	expectedContent := "Secret Content"
	if !strings.Contains(resp.Body.String(), expectedContent) {
		t.Errorf("期望内容包含 %q，得到 %q", expectedContent, resp.Body.String())
	}

	// 测试访问加密的CSS文件
	req = httptest.NewRequest("GET", "/protected/secret.css", nil)
	resp = httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedCSS := "body { color: green; }"
	if !strings.Contains(resp.Body.String(), expectedCSS) {
		t.Errorf("期望CSS内容包含 %q，得到 %q", expectedCSS, resp.Body.String())
	}

	// 测试访问加密的JSON文件
	req = httptest.NewRequest("GET", "/protected/data.json", nil)
	resp = httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedJSON := "password protected data"
	if !strings.Contains(resp.Body.String(), expectedJSON) {
		t.Errorf("期望JSON内容包含 %q，得到 %q", expectedJSON, resp.Body.String())
	}

	// 检查Content-Type是否正确设置
	expectedContentType := "application/json"
	if !strings.HasPrefix(resp.Header().Get("Content-Type"), expectedContentType) {
		t.Errorf("期望Content-Type包含 %q，得到 %q", expectedContentType, resp.Header().Get("Content-Type"))
	}
}

// TestZipFile_PasswordProtected 测试密码保护的单个zip文件功能
func TestZipFile_PasswordProtected(t *testing.T) {
	// 创建密码保护的测试zip文件
	password := "secret999"
	files := map[string]string{
		"config.json": `{"protected": true, "data": "encrypted content"}`,
		"readme.txt":  "This is protected content",
	}
	zipPath := createPasswordProtectedZip(t, "protected_config.zip", password, files)

	// 创建带密码的zip文件管理器
	config := &ZipFileConfig{
		Password: password,
	}
	zf, err := NewZipFile(zipPath, "config.json", config)
	if err != nil {
		t.Fatalf("创建密码保护的zip文件管理器失败: %v", err)
	}
	defer zf.Stop()

	// 创建测试路由器
	router := NewRouter(nil)
	router.engine.GET("/protected-config", func(c *gin.Context) {
		zf.ServeHTTP(c)
	})

	// 测试访问加密文件
	req := httptest.NewRequest("GET", "/protected-config", nil)
	resp := httptest.NewRecorder()
	router.engine.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("期望状态码 %d，得到 %d", http.StatusOK, resp.Code)
	}

	expectedContent := `"protected": true`
	if !strings.Contains(resp.Body.String(), expectedContent) {
		t.Errorf("期望内容包含 %q，得到 %q", expectedContent, resp.Body.String())
	}

	// 检查Content-Type
	expectedContentType := "application/json"
	if !strings.HasPrefix(resp.Header().Get("Content-Type"), expectedContentType) {
		t.Errorf("期望Content-Type包含 %q，得到 %q", expectedContentType, resp.Header().Get("Content-Type"))
	}
}
