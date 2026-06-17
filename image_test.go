package gin

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	imagepkg "github.com/darkit/gin/pkg/image"
	gingonic "github.com/gin-gonic/gin"
)

func createTestImage(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.Set(x, y, color.RGBA{R: 200, G: 100, B: 50, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("生成测试图片失败: %v", err)
	}
	return buf.Bytes()
}

func newImageUploadRequest(t *testing.T, field, filename string, content []byte) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("创建表单失败: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("写入表单失败: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭表单失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func newImageContext(t *testing.T, req *http.Request) *Context {
	t.Helper()
	w := httptest.NewRecorder()
	ginCtx, _ := gingonic.CreateTestContext(w)
	ginCtx.Request = req
	ctx := &Context{Context: ginCtx}
	ctx.SetEngine(New())
	return ctx
}

// TestSaveImage_Resize 尺寸调整
func TestSaveImage_Resize(t *testing.T) {
	data := createTestImage(t, 400, 300)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	result, err := ctx.SaveImage("file", imagepkg.Resize(200, 150))
	if err != nil {
		t.Fatalf("Resize 失败: %v", err)
	}
	if result.Width != 200 || result.Height != 150 {
		t.Fatalf("Resize 尺寸不正确")
	}
}

// TestSaveImage_Compress 压缩
func TestSaveImage_Compress(t *testing.T) {
	data := createTestImage(t, 400, 300)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	result, err := ctx.SaveImage("file", imagepkg.Compress(50))
	if err != nil {
		t.Fatalf("Compress 失败: %v", err)
	}
	if result.Size <= 0 {
		t.Fatalf("压缩后大小不正确")
	}
}

// TestSaveImage_Watermark 水印
func TestSaveImage_Watermark(t *testing.T) {
	data := createTestImage(t, 400, 300)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	result, err := ctx.SaveImage("file", imagepkg.WatermarkText("demo", imagepkg.WatermarkTextOptions{Position: "bottom-right"}))
	if err != nil {
		t.Fatalf("Watermark 失败: %v", err)
	}
	if result.Width == 0 || result.Height == 0 {
		t.Fatalf("水印输出尺寸不正确")
	}
}

// TestSaveImage_FormatConvert 格式转换
func TestSaveImage_FormatConvert(t *testing.T) {
	data := createTestImage(t, 400, 300)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	result, err := ctx.SaveImage("file", imagepkg.ToFormat("png"))
	if err != nil {
		t.Fatalf("FormatConvert 失败: %v", err)
	}
	if result.Format != "png" {
		t.Fatalf("格式转换未生效")
	}
	file, err := os.Open(result.Path)
	if err != nil {
		t.Fatalf("读取输出文件失败: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("关闭输出文件失败: %v", closeErr)
		}
	}()
	if _, err := png.Decode(file); err != nil {
		t.Fatalf("输出文件不是 PNG: %v", err)
	}
}

// TestProcessImages_MultipleSizes 多尺寸生成
func TestProcessImages_MultipleSizes(t *testing.T) {
	data := createTestImage(t, 800, 600)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	results, err := ctx.ProcessImages("file", []imagepkg.ImageConfig{
		{Suffix: "_thumb", Options: []imagepkg.ImageOption{imagepkg.Thumbnail(100, 100)}},
		{Suffix: "_medium", Options: []imagepkg.ImageOption{imagepkg.ResizeWidth(400)}},
	})
	if err != nil {
		t.Fatalf("多尺寸生成失败: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("多尺寸数量不正确")
	}
	for _, res := range results {
		if _, err := os.Stat(res.Path); err != nil {
			t.Fatalf("输出文件不存在: %v", err)
		}
		if res.Path == "" || res.SavedName == "" {
			t.Fatalf("输出路径不正确")
		}
	}
}

// TestSaveImage_Chain 链式处理
func TestSaveImage_Chain(t *testing.T) {
	data := createTestImage(t, 600, 400)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	result, err := ctx.SaveImage(
		"file",
		imagepkg.ResizeWidth(300),
		imagepkg.Compress(70),
		imagepkg.WatermarkText("chain", imagepkg.WatermarkTextOptions{Position: "center"}),
		imagepkg.ToFormat("png"),
	)
	if err != nil {
		t.Fatalf("链式处理失败: %v", err)
	}
	if result.Format != "png" {
		t.Fatalf("链式处理格式不正确")
	}
	if result.Width != 300 {
		t.Fatalf("链式处理尺寸不正确")
	}
}

func TestSaveImage_PathTraversal(t *testing.T) {
	data := createTestImage(t, 400, 300)
	req := newImageUploadRequest(t, "file", "photo.jpg", data)
	ctx := newImageContext(t, req)

	_, err := ctx.SaveImage("file", imagepkg.ToFormat("../../../etc/passwd"))
	if err == nil {
		t.Fatalf("路径遍历应被拒绝")
	}
}
