package image

import (
	stdimage "image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	xwebp "golang.org/x/image/webp"
)

func TestProcessConvertsToWebP(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.png")
	dstPath := filepath.Join(tmpDir, "result.webp")

	src := stdimage.NewRGBA(stdimage.Rect(0, 0, 3, 2))
	src.Set(0, 0, color.RGBA{R: 255, A: 255})
	src.Set(1, 0, color.RGBA{G: 255, A: 255})
	src.Set(2, 0, color.RGBA{B: 255, A: 255})
	src.Set(1, 1, color.RGBA{R: 120, G: 80, B: 40, A: 200})

	file, err := os.Create(srcPath)
	if err != nil {
		t.Fatalf("create source image: %v", err)
	}
	if err := png.Encode(file, src); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Logf("close source png after encode failure: %v", closeErr)
		}
		t.Fatalf("encode source png: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close source png: %v", err)
	}

	result, err := Process(srcPath, dstPath, "source.png", ToFormat("webp"), Compress(80))
	if err != nil {
		t.Fatalf("process image to webp: %v", err)
	}

	if result.Format != "webp" {
		t.Fatalf("expected format webp, got %q", result.Format)
	}
	if result.Width != 3 || result.Height != 2 {
		t.Fatalf("unexpected dimensions: %dx%d", result.Width, result.Height)
	}
	if result.Size <= 0 {
		t.Fatalf("expected non-empty webp output, got size %d", result.Size)
	}

	output, err := os.Open(dstPath)
	if err != nil {
		t.Fatalf("open encoded webp: %v", err)
	}
	defer func() {
		if closeErr := output.Close(); closeErr != nil {
			t.Errorf("close encoded webp: %v", closeErr)
		}
	}()

	cfg, err := xwebp.DecodeConfig(output)
	if err != nil {
		t.Fatalf("decode encoded webp: %v", err)
	}
	if cfg.Width != 3 || cfg.Height != 2 {
		t.Fatalf("unexpected decoded dimensions: %dx%d", cfg.Width, cfg.Height)
	}
}

func TestProcessConvertsToWebPWithInvalidQuality(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.png")
	dstPath := filepath.Join(tmpDir, "result.webp")

	src := stdimage.NewRGBA(stdimage.Rect(0, 0, 2, 2))
	src.Set(0, 0, color.RGBA{R: 220, G: 100, B: 50, A: 255})

	file, err := os.Create(srcPath)
	if err != nil {
		t.Fatalf("create source image: %v", err)
	}
	if err := png.Encode(file, src); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Logf("close source png after encode failure: %v", closeErr)
		}
		t.Fatalf("encode source png: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close source png: %v", err)
	}

	result, err := Process(srcPath, dstPath, "source.png", ToFormat("webp"), Compress(101))
	if err != nil {
		t.Fatalf("process image to webp with invalid quality: %v", err)
	}
	if result.Size <= 0 {
		t.Fatalf("expected non-empty webp output, got size %d", result.Size)
	}
}
