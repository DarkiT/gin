package image

import (
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strings"

	"github.com/darkit/gin/internal/pathutil"
	"github.com/disintegration/imaging"
)

// ImageResult 处理结果
type ImageResult struct {
	// OriginalName 原始文件名
	OriginalName string `json:"original_name"`
	// SavedName 保存后的文件名
	SavedName string `json:"saved_name"`
	// Path 文件保存路径
	Path string `json:"path"`
	// Width 图片宽度
	Width int `json:"width"`
	// Height 图片高度
	Height int `json:"height"`
	// Size 文件大小（字节）
	Size int64 `json:"size"`
	// Format 文件格式
	Format string `json:"format"`
}

// ImageConfig 批量处理配置
type ImageConfig struct {
	// Suffix 文件名后缀，例如 _thumb、_medium
	Suffix string
	// Options 处理选项
	Options []ImageOption
}

// Process 处理图片并写入目标路径
func Process(srcPath, dstPath, originalName string, opts ...ImageOption) (*ImageResult, error) {
	baseDir := os.TempDir()
	if baseDir == "" {
		baseDir = "/tmp"
	}
	validatedSrc, err := safeImagePath(baseDir, srcPath)
	if err != nil {
		return nil, fmt.Errorf("源图片路径非法: %w", err)
	}
	validatedDst, err := safeImagePath(baseDir, dstPath)
	if err != nil {
		return nil, fmt.Errorf("目标图片路径非法: %w", err)
	}
	img, err := imaging.Open(validatedSrc, imaging.AutoOrientation(true))
	if err != nil {
		return nil, err
	}
	options := normalizeImageOptions(opts)
	processed, err := applyTransformations(img, options)
	if err != nil {
		return nil, err
	}
	if err := saveImage(processed, validatedDst, options); err != nil {
		return nil, err
	}
	info, err := os.Stat(validatedDst)
	if err != nil {
		return nil, err
	}
	return &ImageResult{
		OriginalName: originalName,
		SavedName:    filepath.Base(validatedDst),
		Path:         validatedDst,
		Width:        processed.Bounds().Dx(),
		Height:       processed.Bounds().Dy(),
		Size:         info.Size(),
		Format:       normalizeFormat(options.format, validatedDst),
	}, nil
}

func applyTransformations(src image.Image, options *imageOptions) (image.Image, error) {
	result := src
	switch options.resizeMode {
	case "resize":
		if options.resizeWidth > 0 || options.resizeHeight > 0 {
			result = imaging.Resize(result, options.resizeWidth, options.resizeHeight, imaging.Lanczos)
		}
	case "width":
		if options.resizeWidth > 0 {
			result = imaging.Resize(result, options.resizeWidth, 0, imaging.Lanczos)
		}
	case "height":
		if options.resizeHeight > 0 {
			result = imaging.Resize(result, 0, options.resizeHeight, imaging.Lanczos)
		}
	case "crop":
		if options.resizeWidth > 0 && options.resizeHeight > 0 {
			anchor := parseAnchor(options.resizeAnchor)
			result = imaging.CropAnchor(result, options.resizeWidth, options.resizeHeight, anchor)
		}
	case "thumbnail":
		if options.resizeWidth > 0 && options.resizeHeight > 0 {
			result = imaging.Thumbnail(result, options.resizeWidth, options.resizeHeight, imaging.Lanczos)
		}
	}
	if options.watermark != nil {
		marked, err := applyWatermark(result, options.watermark)
		if err != nil {
			return nil, err
		}
		result = marked
	}
	return result, nil
}

func saveImage(img image.Image, dstPath string, options *imageOptions) (err error) {
	format := normalizeFormat(options.format, dstPath)
	if err := ensureDir(filepath.Dir(dstPath)); err != nil {
		return err
	}
	file, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	switch format {
	case "jpg", "jpeg":
		return imaging.Encode(file, img, imaging.JPEG, imaging.JPEGQuality(options.quality))
	case "png":
		return imaging.Encode(file, img, imaging.PNG)
	case "webp":
		return encodeWebP(file, img, options.quality)
	default:
		return fmt.Errorf("不支持的图片格式: %s", format)
	}
}

func normalizeFormat(format string, filename string) string {
	if strings.TrimSpace(format) == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(filename)), ".")
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "jpeg" {
		return "jpg"
	}
	return format
}

func ensureDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("保存路径不能为空")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return nil
}

func safeImagePath(baseDir, input string) (string, error) {
	rel := strings.TrimSpace(input)
	if rel == "" {
		return "", pathutil.ErrInvalidPath
	}
	if filepath.IsAbs(rel) {
		pathRel, err := filepath.Rel(baseDir, rel)
		if err != nil {
			return "", err
		}
		rel = pathRel
	}
	return pathutil.SafePath(baseDir, rel)
}

func parseAnchor(anchor string) imaging.Anchor {
	switch strings.ToLower(strings.TrimSpace(anchor)) {
	case "top-left":
		return imaging.TopLeft
	case "top":
		return imaging.Top
	case "top-right":
		return imaging.TopRight
	case "left":
		return imaging.Left
	case "right":
		return imaging.Right
	case "bottom-left":
		return imaging.BottomLeft
	case "bottom":
		return imaging.Bottom
	case "bottom-right":
		return imaging.BottomRight
	case "center":
		return imaging.Center
	default:
		return imaging.Center
	}
}
