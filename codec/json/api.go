// Copyright 2025 Gin Core Team. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package json

import "io"

// API 表示当前启用的 JSON 编解码实现。
var API Core

// Core 定义 JSON 编解码器需要实现的核心能力。
type Core interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	MarshalIndent(v any, prefix, indent string) ([]byte, error)
	NewEncoder(writer io.Writer) Encoder
	NewDecoder(reader io.Reader) Decoder
}

// Encoder 定义将 JSON 值写入输出流的编码器接口。
type Encoder interface {
	// SetEscapeHTML 指定是否转义 JSON 字符串中的 HTML 特殊字符。
	// 默认会将 `&`、`<`、`>` 转义为 `\u0026`、`\u003c`、`\u003e`，
	// 以避免将 JSON 嵌入 HTML 时可能出现的安全问题。
	// 在非 HTML 场景下，如果转义会影响可读性，可通过 `SetEscapeHTML(false)` 关闭。
	SetEscapeHTML(on bool)

	// Encode 将 v 编码为 JSON 写入流，并在末尾追加换行符。
	Encode(v any) error
}

// Decoder 定义从输入流读取并解码 JSON 值的解码器接口。
type Decoder interface {
	// UseNumber 使 Decoder 在将数字解码到 `any` 时使用 `Number`，而不是 `float64`。
	UseNumber()

	// DisallowUnknownFields 使 Decoder 在目标为结构体且输入包含未知导出字段时返回错误。
	DisallowUnknownFields()

	// Decode 从输入流读取下一个 JSON 值，并解码到 v 指向的位置。
	Decode(v any) error
}
