package render

import (
	"net/http"

	original "github.com/gin-gonic/gin/render"
)

// ---- 接口 ----
type (
	// Render 为渲染接口的类型别名。
	Render = original.Render
	// HTMLRender 为 HTML 渲染器接口的类型别名。
	HTMLRender = original.HTMLRender
)

// ---- 类型 ----
type (
	// JSON 为 JSON 渲染类型的类型别名。
	JSON = original.JSON
	// IndentedJSON 为带缩进的 JSON 渲染类型别名。
	IndentedJSON = original.IndentedJSON
	// SecureJSON 为安全 JSON 渲染类型别名。
	SecureJSON = original.SecureJSON
	// JsonpJSON 为 JSONP 渲染类型别名。
	JsonpJSON = original.JsonpJSON
	// AsciiJSON 为 ASCII JSON 渲染类型别名。
	AsciiJSON = original.AsciiJSON
	// BSON 为 BSON 渲染类型别名。
	BSON = original.BSON
	// PureJSON 为原始 JSON 渲染类型别名。
	PureJSON = original.PureJSON
	// XML 为 XML 渲染类型别名。
	XML = original.XML
	// String 为字符串渲染类型别名。
	String = original.String
	// Redirect 为重定向渲染类型别名。
	Redirect = original.Redirect
	// Data 为二进制数据渲染类型别名。
	Data = original.Data
	// HTML 为 HTML 渲染类型别名。
	HTML = original.HTML
	// HTMLDebug 为 HTML 调试渲染类型别名。
	HTMLDebug = original.HTMLDebug
	// HTMLProduction 为 HTML 生产渲染类型别名。
	HTMLProduction = original.HTMLProduction
	// YAML 为 YAML 渲染类型别名。
	YAML = original.YAML
	// Reader 为 Reader 渲染类型别名。
	Reader = original.Reader
	// ProtoBuf 为 ProtoBuf 渲染类型别名。
	ProtoBuf = original.ProtoBuf
	// TOML 为 TOML 渲染类型别名。
	TOML = original.TOML
	// MsgPack 为 MsgPack 渲染类型别名。
	MsgPack = original.MsgPack
	// Delims 为 HTML 模板分隔符类型别名。
	Delims = original.Delims
)

// WriteJSON 写入 JSON 响应内容。
func WriteJSON(w http.ResponseWriter, obj any) error {
	return original.WriteJSON(w, obj)
}

// WriteMsgPack 写入 MsgPack 响应内容。
func WriteMsgPack(w http.ResponseWriter, obj any) error {
	return original.WriteMsgPack(w, obj)
}

// WriteString 写入字符串响应内容。
func WriteString(w http.ResponseWriter, format string, data []any) error {
	return original.WriteString(w, format, data)
}
