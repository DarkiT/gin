package image

import "image/color"

// ImageOption 图片处理选项
type ImageOption func(*imageOptions)

type imageOptions struct {
	resizeWidth  int
	resizeHeight int
	resizeMode   string
	resizeAnchor string
	quality      int
	format       string
	watermark    *watermarkOptions
}

func defaultImageOptions() *imageOptions {
	return &imageOptions{
		quality: 95,
	}
}

// Resize 调整尺寸
func Resize(width, height int) ImageOption {
	return func(o *imageOptions) {
		o.resizeWidth = width
		o.resizeHeight = height
		o.resizeMode = "resize"
	}
}

// ResizeWidth 按宽度等比缩放
func ResizeWidth(width int) ImageOption {
	return func(o *imageOptions) {
		o.resizeWidth = width
		o.resizeHeight = 0
		o.resizeMode = "width"
	}
}

// ResizeHeight 按高度等比缩放
func ResizeHeight(height int) ImageOption {
	return func(o *imageOptions) {
		o.resizeWidth = 0
		o.resizeHeight = height
		o.resizeMode = "height"
	}
}

// Crop 裁剪
func Crop(width, height int, anchor string) ImageOption {
	return func(o *imageOptions) {
		o.resizeWidth = width
		o.resizeHeight = height
		o.resizeMode = "crop"
		o.resizeAnchor = anchor
	}
}

// Compress 压缩质量 1-100
func Compress(quality int) ImageOption {
	return func(o *imageOptions) {
		o.quality = quality
	}
}

// Watermark 图片水印
func Watermark(imagePath string, position string) ImageOption {
	return func(o *imageOptions) {
		o.watermark = &watermarkOptions{
			kind:     watermarkKindImage,
			path:     imagePath,
			position: position,
		}
	}
}

// WatermarkText 文字水印
func WatermarkText(text string, opts WatermarkTextOptions) ImageOption {
	return func(o *imageOptions) {
		o.watermark = &watermarkOptions{
			kind:     watermarkKindText,
			text:     text,
			position: opts.Position,
			textOpts: &opts,
		}
	}
}

// ToFormat 格式转换 jpeg/png/webp
func ToFormat(format string) ImageOption {
	return func(o *imageOptions) {
		o.format = format
	}
}

// Thumbnail 缩略图
func Thumbnail(width, height int) ImageOption {
	return func(o *imageOptions) {
		o.resizeWidth = width
		o.resizeHeight = height
		o.resizeMode = "thumbnail"
	}
}

// WatermarkTextOptions 文字水印选项
type WatermarkTextOptions struct {
	// Position 水印位置
	Position string
	// Size 字体大小
	Size int
	// Color 文字颜色
	Color color.Color
	// Opacity 透明度
	Opacity float64
}

func normalizeImageOptions(opts []ImageOption) *imageOptions {
	options := defaultImageOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(options)
	}
	if options.quality <= 0 || options.quality > 100 {
		options.quality = 95
	}
	return options
}

// ExtractFormat 获取目标格式
func ExtractFormat(opts []ImageOption) string {
	options := normalizeImageOptions(opts)
	return options.format
}
