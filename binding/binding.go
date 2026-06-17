package binding

import original "github.com/gin-gonic/gin/binding"

// ---- 常量 ----
const (
	// MIMEJSON 表示 JSON 的 MIME 类型。
	MIMEJSON = original.MIMEJSON
	// MIMEHTML 表示 HTML 的 MIME 类型。
	MIMEHTML = original.MIMEHTML
	// MIMEXML 表示 XML 的 MIME 类型。
	MIMEXML = original.MIMEXML
	// MIMEXML2 表示备用 XML 的 MIME 类型。
	MIMEXML2 = original.MIMEXML2
	// MIMEPlain 表示纯文本的 MIME 类型。
	MIMEPlain = original.MIMEPlain
	// MIMEPOSTForm 表示表单提交的 MIME 类型。
	MIMEPOSTForm = original.MIMEPOSTForm
	// MIMEMultipartPOSTForm 表示多段表单提交的 MIME 类型。
	MIMEMultipartPOSTForm = original.MIMEMultipartPOSTForm
	// MIMEPROTOBUF 表示 Protobuf 的 MIME 类型。
	MIMEPROTOBUF = original.MIMEPROTOBUF
	// MIMEMSGPACK 表示 MsgPack 的 MIME 类型。
	MIMEMSGPACK = original.MIMEMSGPACK
	// MIMEMSGPACK2 表示备用 MsgPack 的 MIME 类型。
	MIMEMSGPACK2 = original.MIMEMSGPACK2
	// MIMEYAML 表示 YAML 的 MIME 类型。
	MIMEYAML = original.MIMEYAML
	// MIMEYAML2 表示备用 YAML 的 MIME 类型。
	MIMEYAML2 = original.MIMEYAML2
	// MIMETOML 表示 TOML 的 MIME 类型。
	MIMETOML = original.MIMETOML
	// MIMEBSON 表示 BSON 的 MIME 类型。
	MIMEBSON = original.MIMEBSON
)

// ---- 接口与类型 ----
type (
	// Binding 定义请求数据绑定的接口。
	Binding = original.Binding
	// BindingBody 定义可重复读取请求体的绑定接口。
	BindingBody = original.BindingBody
	// BindingUri 定义 URI 参数绑定接口。
	BindingUri = original.BindingUri
	// StructValidator 定义结构体验证接口。
	StructValidator = original.StructValidator
	// BindUnmarshaler 定义自定义反序列化接口。
	BindUnmarshaler = original.BindUnmarshaler
	// SliceValidationError 表示切片验证错误集合。
	SliceValidationError = original.SliceValidationError
)

// ---- 变量 ----
var (
	// Validator 为默认结构体验证器。
	Validator = original.Validator
	// EnableDecoderUseNumber 控制 JSON 解析是否使用 Number。
	EnableDecoderUseNumber = original.EnableDecoderUseNumber
	// EnableDecoderDisallowUnknownFields 控制 JSON 解析是否禁止未知字段。
	EnableDecoderDisallowUnknownFields = original.EnableDecoderDisallowUnknownFields
)

var (
	// JSON 为 JSON 绑定器。
	JSON = original.JSON
	// XML 为 XML 绑定器。
	XML = original.XML
	// Form 为表单绑定器。
	Form = original.Form
	// Query 为查询参数绑定器。
	Query = original.Query
	// FormPost 为表单提交绑定器。
	FormPost = original.FormPost
	// FormMultipart 为多段表单绑定器。
	FormMultipart = original.FormMultipart
	// ProtoBuf 为 Protobuf 绑定器。
	ProtoBuf = original.ProtoBuf
	// MsgPack 为 MsgPack 绑定器。
	MsgPack = original.MsgPack
	// YAML 为 YAML 绑定器。
	YAML = original.YAML
	// Uri 为 URI 绑定器。
	Uri = original.Uri
	// Header 为请求头绑定器。
	Header = original.Header
	// Plain 为纯文本绑定器。
	Plain = original.Plain
	// TOML 为 TOML 绑定器。
	TOML = original.TOML
	// BSON 为 BSON 绑定器。
	BSON = original.BSON
)

var (
	// ErrConvertMapStringSlice 表示将 map 转换为字符串切片失败。
	ErrConvertMapStringSlice = original.ErrConvertMapStringSlice
	// ErrConvertToMapString 表示转换为 map[string]string 失败。
	ErrConvertToMapString = original.ErrConvertToMapString
	// ErrMultiFileHeader 表示多文件头部错误。
	ErrMultiFileHeader = original.ErrMultiFileHeader
	// ErrMultiFileHeaderLenInvalid 表示多文件头部数量无效。
	ErrMultiFileHeaderLenInvalid = original.ErrMultiFileHeaderLenInvalid
)

// Default 根据 Content-Type 返回默认绑定器。
func Default(method, contentType string) Binding {
	return original.Default(method, contentType)
}

// MapFormWithTag 将表单映射到结构体字段。
func MapFormWithTag(ptr any, form map[string][]string, tag string) error {
	return original.MapFormWithTag(ptr, form, tag)
}
