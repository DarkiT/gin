package swagger

// OpenAPI OpenAPI 3.0 规范根对象
type OpenAPI struct {
	OpenAPI    string                `json:"openapi"`              // OpenAPI 版本号，如 "3.0.0"
	Info       Info                  `json:"info"`                 // API 基本信息
	Servers    []Server              `json:"servers,omitempty"`    // 服务器列表
	Paths      map[string]PathItem   `json:"paths"`                // API 路径定义
	Components *Components           `json:"components,omitempty"` // 可复用的组件
	Tags       []Tag                 `json:"tags,omitempty"`       // 标签列表
	Security   []map[string][]string `json:"security,omitempty"`   // 全局安全要求
}

// Info API 基本信息
type Info struct {
	Title       string  `json:"title"`                 // API 标题
	Description string  `json:"description,omitempty"` // API 描述
	Version     string  `json:"version"`               // API 版本
	Contact     Contact `json:"contact"`               // 联系信息
}

// Contact 联系信息
type Contact struct {
	Name  string `json:"name,omitempty"`  // 联系人名称
	Email string `json:"email,omitempty"` // 联系邮箱
	URL   string `json:"url,omitempty"`   // 联系网址
}

// Server 服务器信息
type Server struct {
	URL         string `json:"url"`                   // 服务器 URL
	Description string `json:"description,omitempty"` // 服务器描述
}

// PathItem 路径项，包含该路径下所有 HTTP 方法的操作
type PathItem struct {
	Get     *Operation `json:"get,omitempty"`     // GET 操作
	Post    *Operation `json:"post,omitempty"`    // POST 操作
	Put     *Operation `json:"put,omitempty"`     // PUT 操作
	Delete  *Operation `json:"delete,omitempty"`  // DELETE 操作
	Patch   *Operation `json:"patch,omitempty"`   // PATCH 操作
	Head    *Operation `json:"head,omitempty"`    // HEAD 操作
	Options *Operation `json:"options,omitempty"` // OPTIONS 操作
	Trace   *Operation `json:"trace,omitempty"`   // TRACE 操作
}

// Operation API 操作定义
type Operation struct {
	Summary     string                `json:"summary,omitempty"`     // 操作简要说明
	Description string                `json:"description,omitempty"` // 操作详细描述
	Tags        []string              `json:"tags,omitempty"`        // 标签列表
	OperationID string                `json:"operationId,omitempty"` // 操作 ID（唯一）
	Parameters  []Parameter           `json:"parameters,omitempty"`  // 参数列表
	RequestBody *RequestBody          `json:"requestBody,omitempty"` // 请求体
	Responses   map[string]Response   `json:"responses"`             // 响应定义
	Deprecated  bool                  `json:"deprecated,omitempty"`  // 是否废弃
	Security    []SecurityRequirement `json:"security,omitempty"`    // 安全要求
}

// Parameter 参数定义
type Parameter struct {
	Name        string  `json:"name"`                  // 参数名称
	In          string  `json:"in"`                    // 参数位置: query, header, path, cookie
	Description string  `json:"description,omitempty"` // 参数描述
	Required    bool    `json:"required,omitempty"`    // 是否必需
	Deprecated  bool    `json:"deprecated,omitempty"`  // 是否废弃
	Schema      *Schema `json:"schema,omitempty"`      // 参数模式
}

// RequestBody 请求体定义
type RequestBody struct {
	Description string               `json:"description,omitempty"` // 请求体描述
	Required    bool                 `json:"required,omitempty"`    // 是否必需
	Content     map[string]MediaType `json:"content"`               // 内容类型映射
}

// MediaType 媒体类型定义
type MediaType struct {
	Schema   *Schema            `json:"schema,omitempty"`   // 数据模式
	Example  any                `json:"example,omitempty"`  // 示例值
	Examples map[string]Example `json:"examples,omitempty"` // 多个示例
}

// Example 示例定义
type Example struct {
	Summary     string `json:"summary,omitempty"`     // 示例摘要
	Description string `json:"description,omitempty"` // 示例描述
	Value       any    `json:"value,omitempty"`       // 示例值
}

// Response 响应定义
type Response struct {
	Description string               `json:"description"`       // 响应描述
	Content     map[string]MediaType `json:"content,omitempty"` // 内容类型映射
	Headers     map[string]Header    `json:"headers,omitempty"` // 响应头
}

// Header 响应头定义
type Header struct {
	Description string  `json:"description,omitempty"` // 头描述
	Schema      *Schema `json:"schema,omitempty"`      // 头模式
}

// Schema JSON Schema 定义
type Schema struct {
	Type        string             `json:"type,omitempty"`        // 数据类型: string, number, integer, boolean, array, object
	Format      string             `json:"format,omitempty"`      // 格式: int32, int64, float, double, date, date-time, etc.
	Description string             `json:"description,omitempty"` // 描述
	Required    []string           `json:"required,omitempty"`    // 必需字段列表
	Properties  map[string]*Schema `json:"properties,omitempty"`  // 对象属性
	Items       *Schema            `json:"items,omitempty"`       // 数组项模式
	Example     any                `json:"example,omitempty"`     // 示例值
	Enum        []any              `json:"enum,omitempty"`        // 枚举值
	Default     any                `json:"default,omitempty"`     // 默认值
	Minimum     *float64           `json:"minimum,omitempty"`     // 最小值
	Maximum     *float64           `json:"maximum,omitempty"`     // 最大值
	MinLength   *int               `json:"minLength,omitempty"`   // 最小长度
	MaxLength   *int               `json:"maxLength,omitempty"`   // 最大长度
	Pattern     string             `json:"pattern,omitempty"`     // 正则模式
	Ref         string             `json:"$ref,omitempty"`        // 引用其他 Schema
}

// Components 可复用组件
type Components struct {
	Schemas         map[string]*Schema        `json:"schemas,omitempty"`         // Schema 定义
	Responses       map[string]Response       `json:"responses,omitempty"`       // 响应定义
	Parameters      map[string]Parameter      `json:"parameters,omitempty"`      // 参数定义
	RequestBodies   map[string]RequestBody    `json:"requestBodies,omitempty"`   // 请求体定义
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"` // 安全方案定义
}

// SecurityScheme 安全方案定义
type SecurityScheme struct {
	Type             string `json:"type"`                       // 类型: apiKey, http, oauth2, openIdConnect
	Description      string `json:"description,omitempty"`      // 描述
	Name             string `json:"name,omitempty"`             // API Key 名称
	In               string `json:"in,omitempty"`               // API Key 位置: query, header, cookie
	Scheme           string `json:"scheme,omitempty"`           // HTTP 认证方案: basic, bearer
	BearerFormat     string `json:"bearerFormat,omitempty"`     // Bearer 令牌格式
	OpenIdConnectUrl string `json:"openIdConnectUrl,omitempty"` // OpenID Connect URL
}

// SecurityRequirement 安全要求
type SecurityRequirement map[string][]string

// Tag 标签定义
type Tag struct {
	Name        string `json:"name"`                  // 标签名称
	Description string `json:"description,omitempty"` // 标签描述
}
