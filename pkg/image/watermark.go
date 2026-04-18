package image

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"os"
	"strings"

	"github.com/disintegration/imaging"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

type watermarkKind int

const (
	watermarkKindImage watermarkKind = iota
	watermarkKindText
)

type watermarkOptions struct {
	kind     watermarkKind
	path     string
	text     string
	position string
	textOpts *WatermarkTextOptions
}

func applyWatermark(src image.Image, opts *watermarkOptions) (image.Image, error) {
	if opts == nil {
		return src, nil
	}
	position := normalizePosition(opts.position)
	opacity := 0.5
	if opts.textOpts != nil && opts.textOpts.Opacity > 0 {
		opacity = opts.textOpts.Opacity
	}
	switch opts.kind {
	case watermarkKindImage:
		return applyImageWatermark(src, opts.path, position, opacity)
	case watermarkKindText:
		return applyTextWatermark(src, opts.text, position, opts.textOpts, opacity)
	default:
		return src, nil
	}
}

func applyImageWatermark(src image.Image, path, position string, opacity float64) (image.Image, error) {
	if strings.TrimSpace(path) == "" {
		return src, errors.New("水印图片路径不能为空")
	}
	baseDir := os.TempDir()
	if baseDir == "" {
		baseDir = "/tmp"
	}
	validatedPath, err := safeImagePath(baseDir, path)
	if err != nil {
		return nil, fmt.Errorf("水印图片路径非法: %w", err)
	}
	wm, err := imaging.Open(validatedPath)
	if err != nil {
		return nil, err
	}
	pos := calculatePosition(src.Bounds(), wm.Bounds(), position)
	return imaging.Overlay(src, wm, pos, opacity), nil
}

func applyTextWatermark(src image.Image, text string, position string, opts *WatermarkTextOptions, opacity float64) (image.Image, error) {
	if strings.TrimSpace(text) == "" {
		return src, errors.New("水印文字不能为空")
	}
	colorValue := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	if opts != nil && opts.Color != nil {
		if c, ok := opts.Color.(color.RGBA); ok {
			colorValue = c
		} else {
			r, g, b, a := opts.Color.RGBA()
			colorValue = color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
		}
	}
	wmImg := renderTextWatermark(text, colorValue, opts)
	pos := calculatePosition(src.Bounds(), wmImg.Bounds(), position)
	return imaging.Overlay(src, wmImg, pos, opacity), nil
}

func renderTextWatermark(text string, c color.RGBA, opts *WatermarkTextOptions) image.Image {
	face := basicfont.Face7x13
	if opts != nil && opts.Size > 0 {
		face = basicfont.Face7x13
	}
	d := &font.Drawer{Face: face}
	textWidth := d.MeasureString(text).Ceil()
	textHeight := face.Metrics().Height.Ceil()
	if textWidth <= 0 {
		textWidth = 1
	}
	if textHeight <= 0 {
		textHeight = 1
	}
	img := image.NewRGBA(image.Rect(0, 0, textWidth, textHeight))
	d = &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(c),
		Face: face,
		Dot:  fixed.P(0, face.Metrics().Ascent.Ceil()),
	}
	d.DrawString(text)
	return img
}

func normalizePosition(position string) string {
	pos := strings.TrimSpace(strings.ToLower(position))
	if pos == "" {
		return "bottom-right"
	}
	return pos
}

func calculatePosition(bg image.Rectangle, fg image.Rectangle, position string) image.Point {
	margin := 10
	bgW := bg.Dx()
	bgH := bg.Dy()
	fgW := fg.Dx()
	fgH := fg.Dy()
	var x, y int
	switch position {
	case "top-left":
		x = margin
		y = margin
	case "top":
		x = (bgW - fgW) / 2
		y = margin
	case "top-right":
		x = bgW - fgW - margin
		y = margin
	case "left":
		x = margin
		y = (bgH - fgH) / 2
	case "center":
		x = (bgW - fgW) / 2
		y = (bgH - fgH) / 2
	case "right":
		x = bgW - fgW - margin
		y = (bgH - fgH) / 2
	case "bottom-left":
		x = margin
		y = bgH - fgH - margin
	case "bottom":
		x = (bgW - fgW) / 2
		y = bgH - fgH - margin
	case "bottom-right":
		x = bgW - fgW - margin
		y = bgH - fgH - margin
	default:
		x = bgW - fgW - margin
		y = bgH - fgH - margin
	}
	if x < margin {
		x = margin
	}
	if y < margin {
		y = margin
	}
	return image.Pt(x, y)
}
