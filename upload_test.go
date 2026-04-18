package gin

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	gingonic "github.com/gin-gonic/gin"
)

type uploadTestFile struct {
	field    string
	filename string
	content  []byte
}

func newUploadTestContext(t *testing.T, req *http.Request) (*Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	ginCtx, _ := gingonic.CreateTestContext(w)
	ginCtx.Request = req
	ctx := &Context{Context: ginCtx}
	ctx.SetEngine(New())
	return ctx, w
}

func newMultipartRequest(t *testing.T, method, path string, files []uploadTestFile) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for _, file := range files {
		part, err := writer.CreateFormFile(file.field, file.filename)
		if err != nil {
			t.Fatalf("创建表单文件失败: %v", err)
		}
		if _, err := part.Write(file.content); err != nil {
			t.Fatalf("写入表单文件失败: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭表单失败: %v", err)
	}

	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestDefaultUploadConfig(t *testing.T) {
	cfg := DefaultUploadConfig()
	if cfg.UploadDir != "" {
		t.Fatalf("默认上传目录不正确")
	}
	if cfg.MaxFileSize != 10<<20 {
		t.Fatalf("默认文件大小限制不正确")
	}
	if cfg.MaxMultipartMemory != 32<<20 {
		t.Fatalf("默认内存限制不正确")
	}
	if cfg.AllowedExts != nil {
		t.Fatalf("默认扩展名应为空")
	}
	if cfg.FileNameFunc != nil {
		t.Fatalf("默认文件名生成器应为空")
	}
}

func TestUploadOptions(t *testing.T) {
	opts := &uploadOptions{}
	ToDir("/tmp")(opts)
	MaxSize(1024)(opts)
	AllowExts("jpg", "png")(opts)
	AsName("avatar.png")(opts)

	if opts.dir != "/tmp" {
		t.Fatalf("ToDir 未生效")
	}
	if opts.maxSize != 1024 {
		t.Fatalf("MaxSize 未生效")
	}
	if len(opts.exts) != 2 || opts.exts[0] != "jpg" || opts.exts[1] != "png" {
		t.Fatalf("AllowExts 未生效")
	}
	if opts.filename != "avatar.png" {
		t.Fatalf("AsName 未生效")
	}
}

func TestValidateFileSize(t *testing.T) {
	err := validateFileSize(11, 10)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("应返回文件过大错误")
	}
	if err := validateFileSize(10, 10); err != nil {
		t.Fatalf("边界值不应报错")
	}
	if err := validateFileSize(11, 0); err != nil {
		t.Fatalf("不限制大小时不应报错")
	}
}

func TestValidateFileExt(t *testing.T) {
	if err := validateFileExt("a.jpg", []string{"png", "jpg"}); err != nil {
		t.Fatalf("允许的扩展名不应报错")
	}
	if err := validateFileExt("a.JPG", []string{"jpg"}); err != nil {
		t.Fatalf("扩展名应忽略大小写")
	}
	err := validateFileExt("a.txt", []string{"jpg"})
	if !errors.Is(err, ErrFileExtNotAllowed) {
		t.Fatalf("不允许的扩展名应报错")
	}
	if err := validateFileExt("a.txt", nil); err != nil {
		t.Fatalf("未限制扩展名时不应报错")
	}
}

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello")
	req := newMultipartRequest(t, http.MethodPost, "/upload", []uploadTestFile{{
		field:    "file",
		filename: "hello.txt",
		content:  content,
	}})
	ctx, _ := newUploadTestContext(t, req)

	res, err := ctx.SaveFile("file", ToDir(dir), AsName("saved.txt"))
	if err != nil {
		t.Fatalf("保存文件失败: %v", err)
	}
	if res.OriginalName != "hello.txt" || res.SavedName != "saved.txt" {
		t.Fatalf("上传结果文件名不正确")
	}
	if res.Ext != "txt" {
		t.Fatalf("扩展名解析错误")
	}
	if res.Path != filepath.Join(dir, "saved.txt") {
		t.Fatalf("保存路径不正确")
	}
	if res.Size != int64(len(content)) {
		t.Fatalf("文件大小不正确")
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("读取保存文件失败: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("保存内容不一致")
	}
}

func TestSaveFiles(t *testing.T) {
	dir := t.TempDir()
	req := newMultipartRequest(t, http.MethodPost, "/upload", []uploadTestFile{
		{field: "files", filename: "a.txt", content: []byte("a")},
		{field: "files", filename: "b.txt", content: []byte("bb")},
	})
	ctx, _ := newUploadTestContext(t, req)

	results, err := ctx.SaveFiles("files", ToDir(dir))
	if err != nil {
		t.Fatalf("批量保存失败: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("返回结果数量不正确")
	}
	seen := make(map[string]struct{})
	for _, res := range results {
		if res.SavedName == "" {
			t.Fatalf("保存文件名不能为空")
		}
		if _, ok := seen[res.SavedName]; ok {
			t.Fatalf("保存文件名应唯一")
		}
		seen[res.SavedName] = struct{}{}
		if _, err := os.Stat(res.Path); err != nil {
			t.Fatalf("保存文件不存在: %v", err)
		}
	}
}

func TestValidateFile(t *testing.T) {
	dir := t.TempDir()
	req := newMultipartRequest(t, http.MethodPost, "/upload", []uploadTestFile{{
		field:    "file",
		filename: "note.txt",
		content:  []byte("data"),
	}})
	ctx, _ := newUploadTestContext(t, req)

	header, err := ctx.ValidateFile("file", ToDir(dir), AsName("should-not-save.txt"), AllowExts("txt"))
	if err != nil {
		t.Fatalf("验证文件失败: %v", err)
	}
	if header == nil || header.Filename != "note.txt" {
		t.Fatalf("返回的文件头不正确")
	}
	if _, err := os.Stat(filepath.Join(dir, "should-not-save.txt")); err == nil {
		t.Fatalf("ValidateFile 不应保存文件")
	}
}

func TestStreamFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "download.txt")
	content := []byte("stream")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download", nil)
	ctx, w := newUploadTestContext(t, req)
	ctx.StreamFile(path, "download.txt")

	if w.Code != http.StatusOK {
		t.Fatalf("下载状态码错误")
	}
	if disp := w.Header().Get("Content-Disposition"); disp != "attachment; filename=\"download.txt\"" {
		t.Fatalf("下载头不正确")
	}
	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Fatalf("下载内容不一致")
	}
}
