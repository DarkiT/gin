# pkg/image

`pkg/image` 提供图片处理能力，包括缩放、裁剪、水印和格式转换。

## 模块用途

- 图片缩放和裁剪
- 添加水印
- 格式转换（支持 WebP）
- 批量处理

## 支持的格式

| 格式 | 说明 |
|------|------|
| JPEG/JPG | JPEG 格式 |
| PNG | PNG 格式 |
| WebP | WebP 格式 |

## 关键类型与函数

### ImageResult

```go
type ImageResult struct {
    OriginalName string // 原始文件名
    SavedName    string // 保存后的文件名
    Path        string // 文件保存路径
    Width       int    // 图片宽度
    Height      int    // 图片高度
    Size        int64  // 文件大小（字节）
    Format      string // 文件格式
}
```

### Process

```go
result, err := image.Process(srcPath, dstPath, originalName string, opts ...ImageOption) (*ImageResult, error)
```

### 图像选项

| 选项 | 说明 |
|------|------|
| `WithWidth(width int)` | 设置目标宽度 |
| `WithHeight(height int)` | 设置目标高度 |
| `WithResizeMode(mode string)` | 设置缩放模式 |
| `WithAnchor(anchor string)` | 设置裁剪锚点 |
| `WithQuality(quality int)` | 设置输出质量 |
| `WithFormat(format string)` | 设置输出格式 |
| `WithWatermark(watermark *WatermarkConfig)` | 添加水印 |

### 缩放模式

| 模式 | 说明 |
|------|------|
| `resize` | 按指定尺寸缩放（默认） |
| `width` | 按宽度缩放，高度自适应 |
| `height` | 按高度缩放，宽度自适应 |
| `crop` | 居中裁剪到指定尺寸 |
| `thumbnail` | 生成缩略图 |

### 水印配置

```go
type WatermarkConfig struct {
    Image   string  // 水印图片路径
    Dx      int     // X 轴偏移
    Dy      int     // Y 轴偏移
    Opacity float64 // 透明度 (0-1)
}
```

## 配置说明

### 水印锚点

| 锚点 | 说明 |
|------|------|
| `top-left` | 左上 |
| `top` | 上中 |
| `top-right` | 右上 |
| `left` | 左中 |
| `center` | 居中（默认） |
| `right` | 右中 |
| `bottom-left` | 左下 |
| `bottom` | 下中 |
| `bottom-right` | 右下 |

## 使用示例

### 基础缩放

```go
package main

import (
	"fmt"

	"github.com/darkit/gin/pkg/image"
)

func main() {
	result, err := image.Process(
		"./input.jpg",
		"./output.jpg",
		"input.jpg",
		image.WithWidth(800),
		image.WithHeight(600),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Saved: %s (%dx%d, %d bytes)\n",
		result.SavedName, result.Width, result.Height, result.Size)
}
```

### 按宽度缩放

```go
result, err := image.Process(
    "input.jpg",
    "output.jpg",
    "input.jpg",
    image.WithWidth(1024),
    image.WithResizeMode("width"),
)
```

### 居中裁剪

```go
result, err := image.Process(
    "input.jpg",
    "output.jpg",
    "input.jpg",
    image.WithWidth(400),
    image.WithHeight(400),
    image.WithResizeMode("crop"),
    image.WithAnchor("center"),
)
```

### 生成缩略图

```go
result, err := image.Process(
    "input.jpg",
    "thumbnail.jpg",
    "input.jpg",
    image.WithWidth(200),
    image.WithHeight(200),
    image.WithResizeMode("thumbnail"),
)
```

### 添加水印

```go
result, err := image.Process(
    "input.jpg",
    "output.jpg",
    "input.jpg",
    image.WithWidth(800),
    image.WithWatermark(&image.WatermarkConfig{
        Image:   "watermark.png",
        Dx:      10,
        Dy:      10,
        Opacity: 0.3,
    }),
)
```

### 转换为 WebP

```go
result, err := image.Process(
    "input.jpg",
    "output.webp",
    "input.jpg",
    image.WithFormat("webp"),
    image.WithQuality(85),
)
```

### 批量处理

```go
configs := []image.ImageConfig{
    {Suffix: "_thumb", Options: []image.ImageOption{
        image.WithWidth(200),
        image.WithHeight(200),
        image.WithResizeMode("thumbnail"),
    }},
    {Suffix: "_medium", Options: []image.ImageOption{
        image.WithWidth(800),
        image.WithResizeMode("width"),
    }},
    {Suffix: "_large", Options: []image.ImageOption{
        image.WithWidth(1920),
        image.WithResizeMode("width"),
    }},
}

// 批量处理图片
for _, cfg := range configs {
    dstPath := strings.TrimSuffix(srcPath, filepath.Ext(srcPath)) + cfg.Suffix + ".jpg"
    _, err := image.Process(srcPath, dstPath, filepath.Base(srcPath), cfg.Options...)
    if err != nil {
        // 处理错误
    }
}
```

## 安全特性

- 路径安全验证：防止路径遍历攻击
- 临时目录隔离：源文件路径在临时目录内
- 格式自动检测：根据文件扩展名自动检测

## 与 Engine 的集成

此包可与 `Engine.WithUploadDir()` 结合使用：

```go
app := gin.New(
    gin.WithUploadDir("./uploads"),
    gin.WithAllowedExts("jpg", "jpeg", "png", "webp"),
)

// 在处理器中处理上传的图片
func handleUpload(c *gin.Context) {
    file, err := c.FormFile("image")
    if err != nil {
        c.BadRequest(err.Error())
        return
    }

    srcPath := "./uploads/" + file.Filename
    dstPath := "./uploads/thumb_" + file.Filename

    result, err := image.Process(srcPath, dstPath, file.Filename,
        image.WithWidth(200),
        image.WithResizeMode("thumbnail"),
    )
    if err != nil {
        c.InternalError(err.Error())
        return
    }

    c.Success(gin.H{
        "path":   result.Path,
        "width":  result.Width,
        "height": result.Height,
    })
}
```

## 注意事项

1. **内存使用**：处理大图片时注意内存消耗
2. **格式支持**：WebP 转换需要 libwebp 支持
3. **质量设置**：JPEG 质量建议 75-90，过高会增加文件大小
4. **水印图片**：水印图片需要预先准备好
